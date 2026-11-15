//! Per-endpoint confinement of network path classes (Xross fork).
//!
//! A [`PathPolicy`] names the classes of network path an endpoint may create and use:
//! direct IP, relay, custom transports. One policy is shared by the socket, every
//! transport sender and every remote-state actor of an endpoint, and is checked
//!
//! - when transports are constructed and paths or candidates are created,
//! - at the single send funnel, for every datagram,
//! - at the single receive funnel, for every datagram, before noq sees it.
//!
//! The policy is **monotonic** for the lifetime of an endpoint: it can only be narrowed
//! (and finally fenced to nothing) under a strictly greater epoch. Widening needs a new
//! endpoint. Because the allowed set only shrinks, every check is evaluated against the
//! current state, which is at least as strict as refusing work tagged with an older epoch.

use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use super::transports::{Addr, FourTuple};

/// A set of network path classes.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PathClasses(u8);

impl PathClasses {
    /// No class: nothing may be sent or received.
    pub const NONE: Self = Self(0);
    /// Direct IP paths, including LAN hints, QUIC address discovery and port mapping.
    pub const DIRECT: Self = Self(1);
    /// Relay paths.
    pub const RELAY: Self = Self(1 << 1);
    /// Custom transport paths.
    pub const CUSTOM: Self = Self(1 << 2);
    /// Every class.
    pub const ALL: Self = Self(Self::DIRECT.0 | Self::RELAY.0 | Self::CUSTOM.0);

    /// Builds a set from raw bits, refusing unknown bits.
    pub fn from_bits(bits: u8) -> Option<Self> {
        (bits & !Self::ALL.0 == 0).then_some(Self(bits))
    }

    /// The raw bits.
    pub fn bits(self) -> u8 {
        self.0
    }

    /// Whether every class in `other` is in `self`.
    pub fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Whether the set is empty.
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The union of two sets.
    pub fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// The class of a transport address.
    pub(crate) fn of_addr(addr: &Addr) -> Self {
        match addr {
            Addr::Ip(_) => Self::DIRECT,
            Addr::Relay(..) => Self::RELAY,
            Addr::Custom(_) => Self::CUSTOM,
        }
    }

    /// The class of a network path.
    pub(crate) fn of_path(path: &FourTuple) -> Self {
        match path {
            FourTuple::Ip { .. } => Self::DIRECT,
            FourTuple::Relay { .. } => Self::RELAY,
            FourTuple::Custom { .. } => Self::CUSTOM,
        }
    }

    fn index(self) -> usize {
        match self {
            Self::DIRECT => 0,
            Self::RELAY => 1,
            _ => 2,
        }
    }
}

impl fmt::Debug for PathClasses {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut set = f.debug_set();
        if self.contains(Self::DIRECT) {
            set.entry(&"direct");
        }
        if self.contains(Self::RELAY) {
            set.entry(&"relay");
        }
        if self.contains(Self::CUSTOM) {
            set.entry(&"custom");
        }
        set.finish()
    }
}

/// Why a policy change or epoch check was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PathPolicyError {
    /// A strict policy must allow at least one class; use [`PathPolicy::fence`] to stop all traffic.
    EmptySet,
    /// The new epoch is not greater than the current one.
    EpochNotIncreasing {
        /// The current epoch.
        current: u64,
    },
    /// The new set is not a subset of the current one; widening needs a new endpoint.
    Widening,
    /// The epoch does not fit the policy's 56-bit epoch space.
    EpochOutOfRange,
    /// The caller's epoch is older than the policy's current epoch.
    Stale {
        /// The current epoch.
        current: u64,
    },
}

impl fmt::Display for PathPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptySet => write!(f, "a strict path policy must allow at least one class"),
            Self::EpochNotIncreasing { current } => {
                write!(
                    f,
                    "path policy epoch must exceed the current epoch {current}"
                )
            }
            Self::Widening => write!(f, "a path policy can only be narrowed"),
            Self::EpochOutOfRange => write!(f, "path policy epoch out of range"),
            Self::Stale { current } => write!(f, "stale path policy epoch (current {current})"),
        }
    }
}

impl std::error::Error for PathPolicyError {}

/// The policy state at one instant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathPolicySnapshot {
    /// The epoch.
    pub epoch: u64,
    /// The allowed classes.
    pub classes: PathClasses,
}

/// Counters of what the boundaries let through and refused, per class.
///
/// `dispatched` counts sends handed to a concrete transport *after* the policy check, and
/// `delivered` counts received datagrams passed on to QUIC after the check: these are
/// actual attempts, not intentions.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PathPolicyStats {
    /// Datagrams handed to a concrete transport, indexed `[direct, relay, custom]`.
    pub sends_dispatched: [u64; 3],
    /// Datagrams refused at the send boundary.
    pub sends_denied: [u64; 3],
    /// Received datagrams passed on to QUIC.
    pub recvs_delivered: [u64; 3],
    /// Received datagrams dropped before QUIC.
    pub recvs_denied: [u64; 3],
    /// Paths opened on a connection.
    pub path_opens: [u64; 3],
    /// Path opens refused, and established paths closed, because of the policy.
    pub path_opens_denied: [u64; 3],
    /// Candidate addresses dropped before they entered a remote's candidate set.
    pub candidates_denied: [u64; 3],
    /// Hole-punching rounds refused because direct paths are not allowed.
    pub holepunch_denied: u64,
}

#[derive(Default)]
struct Counters {
    sends_dispatched: [AtomicU64; 3],
    sends_denied: [AtomicU64; 3],
    recvs_delivered: [AtomicU64; 3],
    recvs_denied: [AtomicU64; 3],
    path_opens: [AtomicU64; 3],
    path_opens_denied: [AtomicU64; 3],
    candidates_denied: [AtomicU64; 3],
    holepunch_denied: AtomicU64,
}

fn load3(c: &[AtomicU64; 3]) -> [u64; 3] {
    [
        c[0].load(Ordering::Relaxed),
        c[1].load(Ordering::Relaxed),
        c[2].load(Ordering::Relaxed),
    ]
}

struct Inner {
    /// `epoch << 8 | classes`.
    state: AtomicU64,
    counters: Counters,
}

/// A per-endpoint, monotonic allowlist of network path classes.
///
/// Cloning shares the same policy.
#[derive(Clone)]
pub struct PathPolicy {
    inner: Arc<Inner>,
}

impl fmt::Debug for PathPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self.snapshot();
        f.debug_struct("PathPolicy")
            .field("epoch", &s.epoch)
            .field("classes", &s.classes)
            .finish()
    }
}

impl Default for PathPolicy {
    fn default() -> Self {
        Self::permissive()
    }
}

const MAX_EPOCH: u64 = (1 << 56) - 1;

fn pack(epoch: u64, classes: PathClasses) -> u64 {
    (epoch << 8) | u64::from(classes.0)
}

fn unpack(state: u64) -> PathPolicySnapshot {
    PathPolicySnapshot {
        epoch: state >> 8,
        classes: PathClasses((state & 0xff) as u8),
    }
}

impl PathPolicy {
    fn new(epoch: u64, classes: PathClasses) -> Self {
        Self {
            inner: Arc::new(Inner {
                state: AtomicU64::new(pack(epoch, classes)),
                counters: Counters::default(),
            }),
        }
    }

    /// Every class at epoch 0: the upstream behaviour.
    pub fn permissive() -> Self {
        Self::new(0, PathClasses::ALL)
    }

    /// Only `classes`, at `epoch`. The set must not be empty.
    pub fn strict(classes: PathClasses, epoch: u64) -> Result<Self, PathPolicyError> {
        if classes.is_empty() {
            return Err(PathPolicyError::EmptySet);
        }
        if epoch > MAX_EPOCH {
            return Err(PathPolicyError::EpochOutOfRange);
        }
        Ok(Self::new(epoch, classes))
    }

    /// The current epoch and classes.
    pub fn snapshot(&self) -> PathPolicySnapshot {
        unpack(self.inner.state.load(Ordering::Acquire))
    }

    /// Whether `class` is allowed now.
    pub fn allows(&self, class: PathClasses) -> bool {
        !class.is_empty() && self.snapshot().classes.contains(class)
    }

    /// Whether nothing is allowed any more.
    pub fn is_fenced(&self) -> bool {
        self.snapshot().classes.is_empty()
    }

    /// Refuses `expected` unless it is the current epoch.
    pub fn check_epoch(&self, expected: u64) -> Result<(), PathPolicyError> {
        let current = self.snapshot().epoch;
        if current == expected {
            Ok(())
        } else {
            Err(PathPolicyError::Stale { current })
        }
    }

    /// Narrows the policy to `classes` under `new_epoch`.
    ///
    /// Refused unless `new_epoch` is greater than the current epoch and `classes` is a
    /// subset of the current set. Takes effect for the next check at every boundary.
    pub fn restrict(&self, new_epoch: u64, classes: PathClasses) -> Result<(), PathPolicyError> {
        if new_epoch > MAX_EPOCH {
            return Err(PathPolicyError::EpochOutOfRange);
        }
        let mut cur = self.inner.state.load(Ordering::Acquire);
        loop {
            let snap = unpack(cur);
            if new_epoch <= snap.epoch {
                return Err(PathPolicyError::EpochNotIncreasing {
                    current: snap.epoch,
                });
            }
            if !snap.classes.contains(classes) {
                return Err(PathPolicyError::Widening);
            }
            match self.inner.state.compare_exchange(
                cur,
                pack(new_epoch, classes),
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(()),
                Err(actual) => cur = actual,
            }
        }
    }

    /// Stops all traffic under `new_epoch`: equivalent to `restrict(new_epoch, NONE)`.
    pub fn fence(&self, new_epoch: u64) -> Result<(), PathPolicyError> {
        self.restrict(new_epoch, PathClasses::NONE)
    }

    /// The counters so far.
    pub fn stats(&self) -> PathPolicyStats {
        let c = &self.inner.counters;
        PathPolicyStats {
            sends_dispatched: load3(&c.sends_dispatched),
            sends_denied: load3(&c.sends_denied),
            recvs_delivered: load3(&c.recvs_delivered),
            recvs_denied: load3(&c.recvs_denied),
            path_opens: load3(&c.path_opens),
            path_opens_denied: load3(&c.path_opens_denied),
            candidates_denied: load3(&c.candidates_denied),
            holepunch_denied: c.holepunch_denied.load(Ordering::Relaxed),
        }
    }

    // Boundary helpers. Each returns whether the action may proceed and counts the outcome.

    /// Send boundary: may a datagram go out on `path`? Counts a denial.
    pub(crate) fn admit_send(&self, path: &FourTuple) -> bool {
        let class = PathClasses::of_path(path);
        let ok = self.allows(class);
        if !ok {
            self.inner.counters.sends_denied[class.index()].fetch_add(1, Ordering::Relaxed);
        }
        ok
    }

    /// Counts a datagram handed to a concrete transport (after [`Self::admit_send`]).
    pub(crate) fn record_dispatch(&self, path: &FourTuple) {
        let class = PathClasses::of_path(path);
        self.inner.counters.sends_dispatched[class.index()].fetch_add(1, Ordering::Relaxed);
    }

    /// Receive boundary: may a datagram from `remote` reach QUIC? Counts both outcomes.
    pub(crate) fn admit_recv(&self, remote: &Addr) -> bool {
        let class = PathClasses::of_addr(remote);
        let ok = self.allows(class);
        let slot = if ok {
            &self.inner.counters.recvs_delivered
        } else {
            &self.inner.counters.recvs_denied
        };
        slot[class.index()].fetch_add(1, Ordering::Relaxed);
        ok
    }

    /// Creation boundary: may a path to `path` be opened? Counts both outcomes.
    pub(crate) fn admit_path_open(&self, path: &FourTuple) -> bool {
        let class = PathClasses::of_path(path);
        let ok = self.allows(class);
        let slot = if ok {
            &self.inner.counters.path_opens
        } else {
            &self.inner.counters.path_opens_denied
        };
        slot[class.index()].fetch_add(1, Ordering::Relaxed);
        ok
    }

    /// Counts an established path closed because its class is not allowed.
    pub(crate) fn record_path_closed(&self, path: &FourTuple) {
        let class = PathClasses::of_path(path);
        self.inner.counters.path_opens_denied[class.index()].fetch_add(1, Ordering::Relaxed);
    }

    /// Creation boundary: may `addr` become a candidate? Counts a denial.
    pub(crate) fn admit_candidate(&self, addr: &Addr) -> bool {
        let class = PathClasses::of_addr(addr);
        let ok = self.allows(class);
        if !ok {
            self.inner.counters.candidates_denied[class.index()].fetch_add(1, Ordering::Relaxed);
        }
        ok
    }

    /// Creation boundary: may a hole-punching round run? Counts a denial.
    pub(crate) fn admit_holepunch(&self) -> bool {
        let ok = self.allows(PathClasses::DIRECT);
        if !ok {
            self.inner
                .counters
                .holepunch_denied
                .fetch_add(1, Ordering::Relaxed);
        }
        ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classes_reject_unknown_bits() {
        assert_eq!(PathClasses::from_bits(0b111), Some(PathClasses::ALL));
        assert_eq!(PathClasses::from_bits(0b1000), None);
        assert!(PathClasses::ALL.contains(PathClasses::RELAY));
        assert!(!PathClasses::RELAY.contains(PathClasses::DIRECT));
    }

    #[test]
    fn strict_refuses_empty_set_and_large_epoch() {
        assert_eq!(
            PathPolicy::strict(PathClasses::NONE, 1).unwrap_err(),
            PathPolicyError::EmptySet
        );
        assert_eq!(
            PathPolicy::strict(PathClasses::RELAY, MAX_EPOCH + 1).unwrap_err(),
            PathPolicyError::EpochOutOfRange
        );
        let p = PathPolicy::strict(PathClasses::RELAY, MAX_EPOCH).unwrap();
        assert_eq!(
            p.snapshot(),
            PathPolicySnapshot {
                epoch: MAX_EPOCH,
                classes: PathClasses::RELAY
            }
        );
    }

    #[test]
    fn restrict_is_monotonic() {
        let p = PathPolicy::permissive();
        assert!(p.allows(PathClasses::DIRECT));
        p.restrict(3, PathClasses::RELAY.union(PathClasses::CUSTOM))
            .unwrap();
        assert!(!p.allows(PathClasses::DIRECT));
        assert!(p.allows(PathClasses::RELAY));
        // Epoch reuse and going back are refused.
        assert_eq!(
            p.restrict(3, PathClasses::RELAY).unwrap_err(),
            PathPolicyError::EpochNotIncreasing { current: 3 }
        );
        assert_eq!(
            p.restrict(2, PathClasses::RELAY).unwrap_err(),
            PathPolicyError::EpochNotIncreasing { current: 3 }
        );
        // Widening is refused even with a fresh epoch.
        assert_eq!(
            p.restrict(4, PathClasses::ALL).unwrap_err(),
            PathPolicyError::Widening
        );
        assert_eq!(p.snapshot().epoch, 3);
        assert_eq!(p.check_epoch(3), Ok(()));
        assert_eq!(p.check_epoch(2), Err(PathPolicyError::Stale { current: 3 }));
        p.fence(5).unwrap();
        assert!(p.is_fenced());
        assert!(!p.allows(PathClasses::RELAY));
        assert!(!p.allows(PathClasses::NONE));
        assert_eq!(
            p.restrict(6, PathClasses::RELAY).unwrap_err(),
            PathPolicyError::Widening
        );
    }

    #[test]
    fn clones_share_state() {
        let a = PathPolicy::permissive();
        let b = a.clone();
        a.fence(1).unwrap();
        assert!(b.is_fenced());
    }
}
