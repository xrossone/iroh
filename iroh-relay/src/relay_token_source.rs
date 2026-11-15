//! A live relay authorization token, per relay and per endpoint.
//!
//! # Why this is here and not upstream in `iroh`
//!
//! `VENDORING.md`'s *"deliberately not patched here"* section says the fix goes
//! upstream. **That was right for the fix as described and is wrong for the fix
//! actually needed.** As described, it replaced `iroh::RelayConfig.auth_token`
//! on a live endpoint — which is `iroh`'s type and would have vendored the whole
//! fabric's foundation. What is needed instead is three facts smaller:
//!
//! 1. The token is read inside *this* crate's `connect()`, not in `iroh` —
//!    `ClientBuilder.auth_token` is a plain `Option<String>` read at
//!    `client.rs:320` on native and `:407` under Wasm.
//! 2. A cloned builder is not the obstacle: iroh's relay actor clones the
//!    pre-built builder on every redial, and a `watch::Receiver` is `Clone` and
//!    shares one channel, so a receiver reached from here reads the current
//!    value at each redial. Nothing in `iroh` changes.
//! 3. Upstream ships this pattern one struct over: the server feeds every live
//!    connection a rate limit through a `watch::Sender`
//!    (`server/http_server.rs:962-968`), received and checked on each poll
//!    (`server/streams.rs`). ADR 0027 §5 names that as the model, and it is in
//!    this crate.
//!
//! An upstream PR is still owed, and `VENDORING.md` now says so against this
//! crate rather than against `iroh`.
//!
//! # The key is `(RelayUrl, endpoint public key)`, not the URL alone
//!
//! Keyed on the URL, this registry assumes one endpoint per process. That holds
//! for `xrossd` — `xross-fabric` binds once — but **not for T1**, two nodes in
//! one process, which is the tier this repository's ladder puts second. Two such
//! nodes pointed at one relay would share one token, and a grant is
//! endpoint-bound, so one of them presents a grant for the other's endpoint and
//! is refused permanently with `access_denied` and no reason.
//!
//! Process-global rather than a builder field, because the builder is
//! constructed inside iroh from a `RelayMap` snapshot where we have no hand.
//!
//! Lifecycle is owner-managed: `xross-fabric` retains the token returned by
//! [`register`] and calls [`take_if_current`] on close or bind failure. A late
//! close from an older endpoint generation cannot remove a replacement. The
//! unconditional [`take`] remains for callers that do not carry an owner; such
//! callers are responsible for not retiring another generation's entry.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use iroh_base::RelayUrl;

/// The live token for one `(relay, endpoint)` pair, updated by whoever holds
/// the paired `watch::Sender`.
///
/// `Clone` and backed by one shared channel: a receiver taken out of the
/// registry at connect time and one still registered for the next redial both
/// observe the same value.
pub type TokenReceiver = tokio::sync::watch::Receiver<Option<String>>;

/// Called by `connect()` when a relay answers the upgrade with 401 or 403.
///
/// `Fn` rather than `FnOnce`: a refusal can happen on every redial.
pub type RejectionNotifier = Arc<dyn Fn() + Send + Sync>;

/// Opaque identity for one registration instance.
///
/// The private `Arc` gives each call to [`register`] an identity that cannot be
/// forged or reused while a caller still owns the token. A clone names the
/// same registration; another call to `register` always gets a different one.
#[derive(Clone)]
pub struct RegistrationToken(Arc<()>);

impl PartialEq for RegistrationToken {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for RegistrationToken {}

impl PartialOrd for RegistrationToken {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RegistrationToken {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (Arc::as_ptr(&self.0) as usize).cmp(&(Arc::as_ptr(&other.0) as usize))
    }
}

impl std::fmt::Debug for RegistrationToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RegistrationToken(<opaque>)")
    }
}

/// Result of looking up a token through one specific registration.
///
/// `OwnerMismatch` means the key is absent or is currently owned by a newer
/// registration. `Current(None)` is deliberately distinct: this registration
/// is still current, but its watch channel currently carries no token.
#[derive(Clone, PartialEq, Eq)]
pub enum TokenLookup {
    /// The key is absent or the supplied owner is no longer current.
    OwnerMismatch,
    /// The supplied owner is current, with the token value currently in its watch channel.
    Current(Option<String>),
}

impl std::fmt::Debug for TokenLookup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OwnerMismatch => f.write_str("OwnerMismatch"),
            Self::Current(None) => f.write_str("Current(None)"),
            Self::Current(Some(_)) => f.write_str("Current(Some(<redacted>))"),
        }
    }
}

/// One registered relay/endpoint pair.
struct Entry {
    owner: RegistrationToken,
    rx: TokenReceiver,
    on_rejected: Option<RejectionNotifier>,
}

/// `(relay, endpoint public key)`. The endpoint key, not the process, is what
/// makes T1 — two endpoints in one process — safe: see the module doc.
type Key = (RelayUrl, [u8; 32]);

fn registry() -> &'static Mutex<HashMap<Key, Entry>> {
    static REGISTRY: OnceLock<Mutex<HashMap<Key, Entry>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Registers a live token source for `(url, endpoint_key)`, replacing any
/// previous registration for the same pair. The returned token identifies this
/// exact registration for a later [`take_if_current`] call; existing callers
/// that do not need conditional retirement may ignore it and keep using [`take`].
pub fn register(
    url: RelayUrl,
    endpoint_key: [u8; 32],
    rx: TokenReceiver,
    on_rejected: Option<RejectionNotifier>,
) -> RegistrationToken {
    // Recovered rather than propagated: the map itself cannot be left
    // inconsistent by a panic under the lock (every operation here is a
    // single insert/remove/read), so a poisoned mutex is only ever "some
    // other operation on this registry panicked", and turning that into a
    // permanent process-wide panic inside `connect()` — the caller of
    // `current` and `note_rejected` below — is a worse failure than
    // continuing with whatever the map already holds.
    let mut guard = registry().lock().unwrap_or_else(|e| e.into_inner());
    let owner = RegistrationToken(Arc::new(()));
    guard.insert(
        (url, endpoint_key),
        Entry {
            owner: owner.clone(),
            rx,
            on_rejected,
        },
    );
    owner
}

/// Removes and returns the registration for `(url, endpoint_key)`, if any.
///
/// Unconditionally removes the registration for compatibility with callers
/// that do not retain an owner token. Generation-aware callers should use
/// [`take_if_current`] so a late cleanup cannot remove a replacement.
pub fn take(url: &RelayUrl, endpoint_key: &[u8; 32]) -> Option<TokenReceiver> {
    let mut guard = registry().lock().unwrap_or_else(|e| e.into_inner());
    guard.remove(&(url.clone(), *endpoint_key)).map(|entry| entry.rx)
}

/// Removes and returns `(url, endpoint_key)` only if `owner` still names its
/// current registration. Replacement and comparison/removal share the same
/// registry mutex, so an old close cannot erase a newer registration between
/// checking ownership and removing the entry.
pub fn take_if_current(
    url: &RelayUrl,
    endpoint_key: &[u8; 32],
    owner: &RegistrationToken,
) -> Option<TokenReceiver> {
    let mut guard = registry().lock().unwrap_or_else(|e| e.into_inner());
    let key = (url.clone(), *endpoint_key);
    let is_current = guard
        .get(&key)
        .is_some_and(|entry| Arc::ptr_eq(&entry.owner.0, &owner.0));
    if !is_current {
        return None;
    }
    guard.remove(&key).map(|entry| entry.rx)
}

/// The current token for `(url, endpoint_key)`, if one is registered and set.
///
/// `None` means either nothing is registered for this pair, or something is
/// registered but its current value is `None` — both are "attach nothing" to a
/// caller, which is why `connect()` can fold this straight into an `Option`
/// chain with the static, builder-captured token.
pub fn current(url: &RelayUrl, endpoint_key: &[u8; 32]) -> Option<String> {
    let guard = registry().lock().unwrap_or_else(|e| e.into_inner());
    guard
        .get(&(url.clone(), *endpoint_key))
        .and_then(|entry| entry.rx.borrow().clone())
}

/// Reads the token only if `owner` is still the current registration for the
/// pair. Unlike [`current`], this does not conflate a replaced registration
/// with a current registration whose token is absent.
pub fn current_for(
    url: &RelayUrl,
    endpoint_key: &[u8; 32],
    owner: &RegistrationToken,
) -> TokenLookup {
    let guard = registry().lock().unwrap_or_else(|e| e.into_inner());
    match guard.get(&(url.clone(), *endpoint_key)) {
        Some(entry) if Arc::ptr_eq(&entry.owner.0, &owner.0) => {
            TokenLookup::Current(entry.rx.borrow().clone())
        }
        _ => TokenLookup::OwnerMismatch,
    }
}

/// Runs the registered notifier for `(url, endpoint_key)`, if there is one.
///
/// Cheap and total: an unregistered pair is a no-op, so `connect()` calls this
/// unconditionally on an authorization refusal — a refusal can arrive for a
/// relay this process never registered for, and that must not panic.
///
/// The notifier is cloned out and called **after** the lock is released. It
/// runs the runtime's own code (`RelayAuthorizationSink::authorization_rejected`
/// by way of `xross-fabric`), and a handler that touched this registry while
/// still under the lock would deadlock.
///
/// **The sink must not block.** This is called from `connect()` on the relay
/// actor's own connect path — synchronously, on whatever task is driving that
/// redial — so a `RelayAuthorizationSink::authorization_rejected` that blocks
/// (a synchronous network call, a lock held elsewhere, anything that waits)
/// stalls that redial for as long as it blocks. An implementer that needs to
/// do real work in response — refetch a grant, write to disk — must hand it
/// off (a channel send, a spawned task) rather than do it inline.
pub fn note_rejected(url: &RelayUrl, endpoint_key: &[u8; 32]) {
    let notifier = {
        let guard = registry().lock().unwrap_or_else(|e| e.into_inner());
        guard
            .get(&(url.clone(), *endpoint_key))
            .and_then(|entry| entry.on_rejected.clone())
    };
    if let Some(notifier) = notifier {
        notifier();
    }
}

/// Runs the refusal notifier only if `owner` is still the current
/// registration for the pair. Returns `true` when a matching notifier was
/// invoked. The notifier is cloned under the registry lock and called after
/// releasing it, so user code cannot block registry operations.
pub fn note_rejected_for(
    url: &RelayUrl,
    endpoint_key: &[u8; 32],
    owner: &RegistrationToken,
) -> bool {
    let notifier = {
        let guard = registry().lock().unwrap_or_else(|e| e.into_inner());
        guard
            .get(&(url.clone(), *endpoint_key))
            .filter(|entry| Arc::ptr_eq(&entry.owner.0, &owner.0))
            .and_then(|entry| entry.on_rejected.clone())
    };
    if let Some(notifier) = notifier {
        notifier();
        true
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(s: &str) -> RelayUrl {
        RelayUrl::from(url::Url::parse(s).expect("valid url"))
    }

    #[test]
    fn an_unregistered_pair_has_no_current_token_and_no_panic_on_rejection() {
        let relay = url("http://unregistered.test/");
        assert_eq!(current(&relay, &[0u8; 32]), None);
        // Must not panic: a refusal can arrive for a relay this process never
        // registered for.
        note_rejected(&relay, &[0u8; 32]);
    }

    #[test]
    fn registering_makes_the_token_visible_and_taking_removes_it() {
        let relay = url("http://registered.test/");
        let key = [7u8; 32];
        let (_tx, rx) = tokio::sync::watch::channel(Some("initial".to_owned()));
        register(relay.clone(), key, rx, None);
        assert_eq!(current(&relay, &key), Some("initial".to_owned()));

        assert!(take(&relay, &key).is_some());
        assert_eq!(current(&relay, &key), None);
        assert!(take(&relay, &key).is_none());
    }

    #[test]
    fn an_old_registration_cannot_take_its_same_key_replacement() {
        let relay = url("http://conditional-replacement.test/");
        let key = [17u8; 32];
        let (_old_tx, old_rx) = tokio::sync::watch::channel(Some("old".to_owned()));
        let old_owner = register(relay.clone(), key, old_rx, None);
        let (_new_tx, new_rx) = tokio::sync::watch::channel(Some("new".to_owned()));
        let new_owner = register(relay.clone(), key, new_rx, None);

        assert!(take_if_current(&relay, &key, &old_owner).is_none());
        assert_eq!(current(&relay, &key), Some("new".to_owned()));
        assert!(take_if_current(&relay, &key, &new_owner).is_some());
        assert_eq!(current(&relay, &key), None);
    }

    #[test]
    fn owner_scoped_reads_and_refusals_ignore_a_replaced_generation() {
        let relay = url("http://owner-scoped-replacement.test/");
        let key = [21u8; 32];
        let old_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let old_counted = Arc::clone(&old_calls);
        let (_old_tx, old_rx) = tokio::sync::watch::channel(Some("old".to_owned()));
        let old_owner = register(
            relay.clone(),
            key,
            old_rx,
            Some(Arc::new(move || {
                old_counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            })),
        );
        let new_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let new_counted = Arc::clone(&new_calls);
        let (new_tx, new_rx) = tokio::sync::watch::channel(Some("new".to_owned()));
        let new_owner = register(
            relay.clone(),
            key,
            new_rx,
            Some(Arc::new(move || {
                new_counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            })),
        );

        assert_eq!(current_for(&relay, &key, &old_owner), TokenLookup::OwnerMismatch);
        assert!(!note_rejected_for(&relay, &key, &old_owner));
        assert_eq!(old_calls.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(new_calls.load(std::sync::atomic::Ordering::SeqCst), 0);

        assert_eq!(
            current_for(&relay, &key, &new_owner),
            TokenLookup::Current(Some("new".to_owned()))
        );
        new_tx
            .send(Some("new-refresh".to_owned()))
            .expect("replacement receiver is current");
        assert_eq!(
            current_for(&relay, &key, &new_owner),
            TokenLookup::Current(Some("new-refresh".to_owned()))
        );
        new_tx.send(None).expect("replacement receiver is current");
        assert_eq!(current_for(&relay, &key, &new_owner), TokenLookup::Current(None));

        assert!(note_rejected_for(&relay, &key, &new_owner));
        assert_eq!(old_calls.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(new_calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn owner_scoped_reads_and_refusals_stay_with_their_url_and_endpoint_key() {
        let relay_a = url("http://owner-scope-a.test/");
        let relay_b = url("http://owner-scope-b.test/");
        let key_a = [22u8; 32];
        let key_b = [23u8; 32];
        let calls_a = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count_a = Arc::clone(&calls_a);
        let (_tx_a, rx_a) = tokio::sync::watch::channel(Some("a".to_owned()));
        let owner_a = register(
            relay_a.clone(),
            key_a,
            rx_a,
            Some(Arc::new(move || {
                count_a.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            })),
        );
        let calls_b = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count_b = Arc::clone(&calls_b);
        let (_tx_b, rx_b) = tokio::sync::watch::channel(Some("b".to_owned()));
        let owner_b = register(
            relay_a.clone(),
            key_b,
            rx_b,
            Some(Arc::new(move || {
                count_b.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            })),
        );

        assert_eq!(
            current_for(&relay_a, &key_a, &owner_a),
            TokenLookup::Current(Some("a".to_owned()))
        );
        assert_eq!(
            current_for(&relay_a, &key_b, &owner_b),
            TokenLookup::Current(Some("b".to_owned()))
        );
        assert_eq!(current_for(&relay_a, &key_b, &owner_a), TokenLookup::OwnerMismatch);
        assert_eq!(current_for(&relay_b, &key_a, &owner_a), TokenLookup::OwnerMismatch);
        assert!(!note_rejected_for(&relay_a, &key_b, &owner_a));
        assert!(!note_rejected_for(&relay_b, &key_a, &owner_a));
        assert_eq!(calls_a.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(calls_b.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert!(note_rejected_for(&relay_a, &key_b, &owner_b));
        assert_eq!(calls_a.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(calls_b.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn retirement_before_replacement_does_not_retire_the_later_registration() {
        let relay = url("http://conditional-close-first.test/");
        let key = [18u8; 32];
        let (_old_tx, old_rx) = tokio::sync::watch::channel(Some("old".to_owned()));
        let old_owner = register(relay.clone(), key, old_rx, None);

        assert!(take_if_current(&relay, &key, &old_owner).is_some());
        let (_new_tx, new_rx) = tokio::sync::watch::channel(Some("new".to_owned()));
        let new_owner = register(relay.clone(), key, new_rx, None);

        assert!(take_if_current(&relay, &key, &old_owner).is_none());
        assert_eq!(current(&relay, &key), Some("new".to_owned()));
        assert!(take_if_current(&relay, &key, &new_owner).is_some());
    }

    #[test]
    fn conditional_retirement_is_scoped_to_the_url_and_endpoint_key() {
        let relay_a = url("http://conditional-scope-a.test/");
        let relay_b = url("http://conditional-scope-b.test/");
        let key_a = [19u8; 32];
        let key_b = [20u8; 32];
        let (_tx_a, rx_a) = tokio::sync::watch::channel(Some("a".to_owned()));
        let owner_a = register(relay_a.clone(), key_a, rx_a, None);
        let (_tx_b, rx_b) = tokio::sync::watch::channel(Some("b".to_owned()));
        let _owner_b = register(relay_a.clone(), key_b, rx_b, None);
        let (_tx_c, rx_c) = tokio::sync::watch::channel(Some("c".to_owned()));
        let _owner_c = register(relay_b.clone(), key_a, rx_c, None);

        assert!(take_if_current(&relay_a, &key_a, &owner_a).is_some());
        assert_eq!(current(&relay_a, &key_b), Some("b".to_owned()));
        assert_eq!(current(&relay_b, &key_a), Some("c".to_owned()));
        assert!(take_if_current(&relay_b, &key_a, &owner_a).is_none());
        assert_eq!(current(&relay_b, &key_a), Some("c".to_owned()));
    }

    #[test]
    fn pushing_through_the_sender_updates_what_current_reports() {
        let relay = url("http://pushed.test/");
        let key = [9u8; 32];
        let (tx, rx) = tokio::sync::watch::channel(Some("first".to_owned()));
        register(relay.clone(), key, rx, None);
        assert_eq!(current(&relay, &key), Some("first".to_owned()));

        tx.send(Some("second".to_owned())).expect("receiver still live");
        assert_eq!(current(&relay, &key), Some("second".to_owned()));
    }

    #[test]
    fn two_endpoint_keys_on_one_relay_do_not_share_a_token() {
        let relay = url("http://shared-relay.test/");
        let key_a = [1u8; 32];
        let key_b = [2u8; 32];
        let (_tx_a, rx_a) = tokio::sync::watch::channel(Some("token-a".to_owned()));
        let (_tx_b, rx_b) = tokio::sync::watch::channel(Some("token-b".to_owned()));
        register(relay.clone(), key_a, rx_a, None);
        register(relay.clone(), key_b, rx_b, None);

        assert_eq!(current(&relay, &key_a), Some("token-a".to_owned()));
        assert_eq!(current(&relay, &key_b), Some("token-b".to_owned()));
    }

    #[test]
    fn note_rejected_runs_the_notifier_exactly_once_per_call() {
        let relay = url("http://rejecting.test/");
        let key = [3u8; 32];
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = calls.clone();
        let (_tx, rx) = tokio::sync::watch::channel(None);
        register(
            relay.clone(),
            key,
            rx,
            Some(Arc::new(move || {
                counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            })),
        );

        note_rejected(&relay, &key);
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        note_rejected(&relay, &key);
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    }
}
