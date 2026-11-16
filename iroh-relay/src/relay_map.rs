//! based on tailscale/tailcfg/derpmap.go

use std::{
    collections::BTreeMap,
    fmt,
    sync::{Arc, RwLock},
};

use iroh_base::{RelayUrl, RelayUrlParseError};
use serde::{Deserialize, Serialize};

use crate::defaults::DEFAULT_RELAY_QUIC_PORT;
use crate::relay_token_source::RegistrationToken;

/// Authorization policy attached to one relay entry.
///
/// `BoundRequired(None)` is a sticky fail-closed state: a connection may not
/// fall back to a static token when its endpoint binding is missing.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RelayAuthBinding {
    /// Preserve the legacy key-only registry and static-token behavior.
    Legacy,
    /// Require a matching registration owner; `None` means the owner is absent.
    BoundRequired(Option<RegistrationToken>),
}

impl Default for RelayAuthBinding {
    fn default() -> Self {
        Self::Legacy
    }
}

impl RelayAuthBinding {
    fn is_legacy(&self) -> bool {
        matches!(self, Self::Legacy)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SerializedRelayAuthBinding {
    Legacy,
    BoundRequired,
}

impl Serialize for RelayAuthBinding {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Legacy => SerializedRelayAuthBinding::Legacy.serialize(serializer),
            Self::BoundRequired(_) => {
                SerializedRelayAuthBinding::BoundRequired.serialize(serializer)
            }
        }
    }
}

impl<'de> Deserialize<'de> for RelayAuthBinding {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(match SerializedRelayAuthBinding::deserialize(deserializer)? {
            SerializedRelayAuthBinding::Legacy => Self::Legacy,
            // Registration tokens are process-local identities and are never
            // serialized. A serialized bound marker must therefore fail closed.
            SerializedRelayAuthBinding::BoundRequired => Self::BoundRequired(None),
        })
    }
}

#[derive(Debug, Default)]
struct RelayMapState {
    relays: BTreeMap<RelayUrl, Arc<RelayConfig>>,
    require_registration: bool,
}

impl RelayMapState {
    fn from_configs(mut relays: BTreeMap<RelayUrl, Arc<RelayConfig>>) -> Self {
        let require_registration = relays
            .values()
            .any(|config| !config.registration.is_legacy());
        if require_registration {
            for config in relays.values_mut() {
                if config.registration.is_legacy() {
                    *config = Arc::new(config.as_ref().clone().with_required_registration(None));
                }
            }
        }
        Self {
            relays,
            require_registration,
        }
    }
}

/// List of relay server configurations to be used in an iroh endpoint.
///
/// A [`RelayMap`] can be constructed from an iterator of [`RelayConfig`] or [`RelayUrl]`,
/// or by creating an empty relay map with [`RelayMap::empty`] and then adding entries with
/// [`RelayMap::insert`].
///
/// Example:
/// ```
/// # use std::str::FromStr;
/// # use iroh_base::RelayUrl;
/// # use iroh_relay::RelayMap;
/// let relay1 = RelayUrl::from_str("https://relay1.example.org").unwrap();
/// let relay2 = RelayUrl::from_str("https://relay2.example.org").unwrap();
/// let map = RelayMap::from_iter(vec![relay1, relay2]);
/// ```
#[derive(Debug, Clone)]
pub struct RelayMap {
    /// Relay configuration and its authorization owner share one lock and
    /// one entry, so an actor snapshots both atomically.
    relays: Arc<RwLock<RelayMapState>>,
}

impl PartialEq for RelayMap {
    fn eq(&self, other: &Self) -> bool {
        let this = self.relays.read().expect("poisoned");
        let that = other.relays.read().expect("poisoned");
        this.require_registration == that.require_registration && this.relays == that.relays
    }
}

impl Eq for RelayMap {}

impl RelayMap {
    /// Creates an empty relay map.
    pub fn empty() -> Self {
        Self {
            relays: Arc::new(RwLock::new(RelayMapState::default())),
        }
    }

    /// Creates a [`RelayMap`] from an iterator.
    ///
    /// The conversion from a URL to a [`RelayConfig`] is done the same as when parsing it directly,
    /// which means it is assumed to run QUIC on default settings as defined in [`RelayQuicConfig::default`].
    ///
    /// # Example
    /// ```rust
    /// # use iroh_relay::RelayMap;
    /// let map =
    ///     RelayMap::try_from_iter(["https://relay_0.cool.com", "https://relay_1.cool.com"]).unwrap();
    /// ```
    pub fn try_from_iter<'a, T: IntoIterator<Item = &'a str>>(
        urls: T,
    ) -> Result<Self, RelayUrlParseError> {
        let relays: BTreeMap<RelayUrl, Arc<RelayConfig>> = urls
            .into_iter()
            .map(|t| {
                t.parse()
                    .map(|url: RelayUrl| (url.clone(), Arc::new(RelayConfig::from(url))))
            })
            .collect::<Result<_, _>>()?;
        Ok(Self {
            relays: Arc::new(RwLock::new(RelayMapState {
                relays,
                require_registration: false,
            })),
        })
    }

    /// Returns the URLs of all servers in this relay map.
    ///
    /// This function is generic over the container to collect into. If you simply want a list
    /// of URLs, call this with `map.urls::<Vec<_>>()` to get a `Vec<RelayUrl>`.
    pub fn urls<T>(&self) -> T
    where
        T: FromIterator<RelayUrl>,
    {
        self.relays
            .read()
            .expect("poisoned")
            .relays
            .keys()
            .cloned()
            .collect::<T>()
    }

    /// Returns a list with the [`RelayConfig`] for each relay in this relay map.
    ///
    /// This function is generic over the container to collect into. If you simply want a list
    /// of URLs, call this with `map.relays::<Vec<_>>()` to get a `Vec<RelayConfig>`.
    pub fn relays<T>(&self) -> T
    where
        T: FromIterator<Arc<RelayConfig>>,
    {
        self.relays
            .read()
            .expect("poisoned")
            .relays
            .values()
            .cloned()
            .collect::<T>()
    }

    /// Returns `true` if a relay with `url` is contained in this this relay map.
    pub fn contains(&self, url: &RelayUrl) -> bool {
        self.relays
            .read()
            .expect("poisoned")
            .relays
            .contains_key(url)
    }

    /// Returns the config for a relay.
    pub fn get(&self, url: &RelayUrl) -> Option<Arc<RelayConfig>> {
        self.relays
            .read()
            .expect("poisoned")
            .relays
            .get(url)
            .cloned()
    }

    /// Returns the number of relays in this relay map.
    pub fn len(&self) -> usize {
        self.relays.read().expect("poisoned").relays.len()
    }

    /// Returns `true` if this relay map is empty.
    pub fn is_empty(&self) -> bool {
        self.relays.read().expect("poisoned").relays.is_empty()
    }

    /// Inserts a new relay into the relay map.
    ///
    /// Xross fork: a URL over [`iroh_base::MAX_RELAY_URL_LEN`] bytes is refused with a warning
    /// and the map is left unchanged (returns `None`), so no relay connection is made for it.
    pub fn insert(&self, url: RelayUrl, endpoint: Arc<RelayConfig>) -> Option<Arc<RelayConfig>> {
        if let Err(err) = url.check_len() {
            tracing::warn!("relay not added: {err}");
            return None;
        }
        let mut state = self.relays.write().expect("poisoned");
        let previous = state.relays.get(&url).cloned();
        let mut endpoint = endpoint.as_ref().clone();
        if let Some(previous) = previous.as_deref() {
            if let RelayAuthBinding::BoundRequired(old_owner) = &previous.registration {
                if endpoint.registration.is_legacy() {
                    endpoint.registration = RelayAuthBinding::BoundRequired(old_owner.clone());
                }
            }
        }
        if state.require_registration && endpoint.registration.is_legacy() {
            endpoint.registration = RelayAuthBinding::BoundRequired(None);
        }
        if !endpoint.registration.is_legacy() && !state.require_registration {
            state.require_registration = true;
            for config in state.relays.values_mut() {
                if config.registration.is_legacy() {
                    *config = Arc::new(config.as_ref().clone().with_required_registration(None));
                }
            }
        }
        state.relays.insert(url, Arc::new(endpoint))
    }

    /// Removes an existing relay by its URL.
    pub fn remove(&self, url: &RelayUrl) -> Option<Arc<RelayConfig>> {
        self.relays
            .write()
            .expect("poisoned")
            .relays
            .remove(url)
    }

    /// Extends this `RelayMap` with another one.
    pub fn extend(&self, other: &RelayMap) {
        let (other_relays, other_requires_registration) = {
            let other = other.relays.read().expect("poisoned");
            (
                other.relays.clone(),
                other.require_registration,
            )
        };
        if other_requires_registration {
            self.require_registration();
        }
        for (url, config) in other_relays {
            self.insert(url, config);
        }
    }

    /// Makes authorization ownership mandatory for this endpoint's relay map.
    /// The requirement is sticky across clones, removals, insertions, and
    /// extensions. Existing entries without owners become `BoundRequired(None)`.
    pub fn require_registration(&self) {
        let mut state = self.relays.write().expect("poisoned");
        state.require_registration = true;
        for config in state.relays.values_mut() {
            if config.registration.is_legacy() {
                *config = Arc::new(config.as_ref().clone().with_required_registration(None));
            }
        }
    }

    /// Returns an atomic snapshot of a relay's config and owner binding.
    /// A missing entry in a required map is still fail-closed.
    pub fn get_with_registration(
        &self,
        url: &RelayUrl,
    ) -> (Option<Arc<RelayConfig>>, RelayAuthBinding) {
        let state = self.relays.read().expect("poisoned");
        match state.relays.get(url) {
            Some(config) => (Some(config.clone()), config.registration.clone()),
            None if state.require_registration => {
                (None, RelayAuthBinding::BoundRequired(None))
            }
            None => (None, RelayAuthBinding::Legacy),
        }
    }

    /// Sets an authorization token for all relays configured in this relay map.
    ///
    /// This applies [`RelayConfig::with_auth_token`] to all current entries in this relay map.
    /// Any entries added to this relay map *after* calling this will not have the token set.
    ///
    /// See [`RelayConfig::with_auth_token`] for details.
    pub fn with_auth_token(self, auth_token: impl Into<String>) -> Self {
        let auth_token = auth_token.into();
        let mut state = self.relays.write().expect("poisoned");
        for config in state.relays.values_mut() {
            *config = Arc::new(config.as_ref().clone().with_auth_token(auth_token.clone()));
        }
        drop(state);
        self
    }
}

impl FromIterator<RelayConfig> for RelayMap {
    fn from_iter<T: IntoIterator<Item = RelayConfig>>(iter: T) -> Self {
        Self::from_iter(iter.into_iter().map(Arc::new))
    }
}

impl FromIterator<Arc<RelayConfig>> for RelayMap {
    fn from_iter<T: IntoIterator<Item = Arc<RelayConfig>>>(iter: T) -> Self {
        Self {
            relays: Arc::new(RwLock::new(RelayMapState::from_configs(
                iter.into_iter()
                    .map(|config| (config.url.clone(), config))
                    .collect(),
            ))),
        }
    }
}

impl From<RelayUrl> for RelayMap {
    /// Creates a [`RelayMap`] from a [`RelayUrl`].
    ///
    /// The [`RelayConfig`]s in the [`RelayMap`] will have the default QUIC address
    /// discovery ports.
    fn from(value: RelayUrl) -> Self {
        Self {
            relays: Arc::new(RwLock::new(RelayMapState::from_configs(
                [(value.clone(), Arc::new(value.into()))].into(),
            ))),
        }
    }
}

impl From<RelayConfig> for RelayMap {
    fn from(value: RelayConfig) -> Self {
        Self {
            relays: Arc::new(RwLock::new(RelayMapState::from_configs(
                [(value.url.clone(), Arc::new(value))].into(),
            ))),
        }
    }
}

impl FromIterator<RelayUrl> for RelayMap {
    /// Creates a [`RelayMap`] from an iterator of [`RelayUrl`].
    ///
    /// The [`RelayConfig`]s in the [`RelayMap`] will have the default QUIC address
    /// discovery ports.
    fn from_iter<T: IntoIterator<Item = RelayUrl>>(iter: T) -> Self {
        Self {
            relays: Arc::new(RwLock::new(RelayMapState::from_configs(
                iter.into_iter()
                    .map(|url| (url.clone(), Arc::new(url.into())))
                    .collect(),
            ))),
        }
    }
}

impl fmt::Display for RelayMap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self, f)
    }
}

/// Information on a specific relay server.
///
/// Includes the Url where it can be dialed.
// Please note that this is documented in the `iroh.computer` repository under
// `src/app/docs/reference/config/page.mdx`.  Any changes to this need to be updated there.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
#[non_exhaustive]
pub struct RelayConfig {
    /// The [`RelayUrl`] where this relay server can be dialed.
    pub url: RelayUrl,
    /// Configuration to speak to the QUIC endpoint on the relay server.
    ///
    /// When `None`, we will not attempt to do QUIC address discovery
    /// with this relay server.
    #[serde(default = "quic_config")]
    pub quic: Option<RelayQuicConfig>,
    /// Optional authorization token sent to the relay.
    ///
    /// Set via [`RelayConfig::with_auth_token`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_token: Option<String>,
    /// Endpoint-scoped authorization ownership. The marker serializes, but
    /// the process-local owner token does not; deserialized bound configs fail
    /// closed until an owner is explicitly attached.
    #[serde(default, skip_serializing_if = "RelayAuthBinding::is_legacy")]
    registration: RelayAuthBinding,
}

impl RelayConfig {
    /// Creates a new relay configuration with the given URL and optional QUIC config.
    pub fn new(url: RelayUrl, quic: Option<RelayQuicConfig>) -> Self {
        Self {
            url,
            quic,
            auth_token: None,
            registration: RelayAuthBinding::Legacy,
        }
    }

    /// Sets an authorization token for this relay.
    ///
    /// On native targets, the token is sent as an `Authorization: Bearer TOKEN`
    /// header on the WebSocket upgrade request.
    ///
    /// When compiled to WebAssembly the token is sent as a `?token=TOKEN`
    /// query parameter on the upgrade URL, since browsers don't allow setting
    /// headers on WebSocket requests.
    pub fn with_auth_token(mut self, token: impl Into<String>) -> Self {
        self.auth_token = Some(token.into());
        self
    }

    /// Attaches an opaque owner token and makes registration binding required.
    pub fn with_registration_owner(mut self, owner: RegistrationToken) -> Self {
        self.registration = RelayAuthBinding::BoundRequired(Some(owner));
        self
    }

    fn with_required_registration(mut self, owner: Option<RegistrationToken>) -> Self {
        self.registration = RelayAuthBinding::BoundRequired(owner);
        self
    }
}

impl From<RelayUrl> for RelayConfig {
    fn from(value: RelayUrl) -> Self {
        Self {
            url: value,
            quic: quic_config(),
            auth_token: None,
            registration: RelayAuthBinding::Legacy,
        }
    }
}

fn quic_config() -> Option<RelayQuicConfig> {
    Some(RelayQuicConfig::default())
}

/// Configuration for speaking to the QUIC endpoint on the relay
/// server to do QUIC address discovery.
///
/// Defaults to using [`DEFAULT_RELAY_QUIC_PORT`].
#[derive(Debug, Deserialize, Serialize, Clone, Eq, PartialEq, PartialOrd, Ord)]
#[non_exhaustive]
pub struct RelayQuicConfig {
    /// The port on which the connection should be bound to.
    pub port: u16,
}

impl RelayQuicConfig {
    /// Creates a new QUIC address discovery configuration with the given port.
    pub fn new(port: u16) -> Self {
        Self { port }
    }
}

impl Default for RelayQuicConfig {
    fn default() -> Self {
        Self {
            port: DEFAULT_RELAY_QUIC_PORT,
        }
    }
}

impl fmt::Display for RelayConfig {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.url)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    /// Xross fork: a runtime insert (directly, or through `extend`) of a relay URL over
    /// [`iroh_base::MAX_RELAY_URL_LEN`] bytes is refused and leaves the map unchanged, so no
    /// relay connection or probe is ever made for it. Parsing from strings refuses it too.
    #[test]
    fn relay_map_refuses_overlong_relay_url() {
        use iroh_base::MAX_RELAY_URL_LEN;
        let url_of_len = |len: usize| {
            let prefix = "https://r.example/";
            format!("{prefix}{}", "a".repeat(len - prefix.len()))
        };
        let ok = RelayUrl::from(url::Url::parse(&url_of_len(MAX_RELAY_URL_LEN)).unwrap());
        let long = RelayUrl::from(url::Url::parse(&url_of_len(MAX_RELAY_URL_LEN + 1)).unwrap());

        let map = RelayMap::empty();
        assert!(map.insert(ok.clone(), Arc::new(ok.clone().into())).is_none());
        assert!(map.contains(&ok));

        assert!(map.insert(long.clone(), Arc::new(long.clone().into())).is_none());
        assert!(!map.contains(&long));
        assert_eq!(map.len(), 1);

        let other = RelayMap::from(long.clone());
        map.extend(&other);
        assert!(!map.contains(&long));
        assert_eq!(map.len(), 1);

        assert!(RelayMap::try_from_iter([url_of_len(MAX_RELAY_URL_LEN + 1).as_str()]).is_err());
    }

    #[test]
    fn relay_map_extend() {
        let urls1 = vec![
            RelayUrl::from_str("https://hello-a-01.com").unwrap(),
            RelayUrl::from_str("https://hello-b-01.com").unwrap(),
            RelayUrl::from_str("https://hello-c-01-.com").unwrap(),
        ];

        let urls2 = vec![
            RelayUrl::from_str("https://hello-a-02.com").unwrap(),
            RelayUrl::from_str("https://hello-b-02.com").unwrap(),
            RelayUrl::from_str("https://hello-c-02-.com").unwrap(),
        ];

        let map1 = RelayMap::from_iter(urls1.clone().into_iter().map(RelayConfig::from));
        let map2 = RelayMap::from_iter(urls2.clone().into_iter().map(RelayConfig::from));

        assert_ne!(map1, map2);

        // combine

        let map3 = RelayMap::from_iter(
            map1.relays::<Vec<_>>()
                .into_iter()
                .chain(map2.relays::<Vec<_>>()),
        );

        assert_eq!(map3.len(), 6);

        map1.extend(&map2);
        assert_eq!(map3, map1);
    }

    #[test]
    fn registration_owner_stays_attached_through_clone_and_from_iter() {
        let url = RelayUrl::from_str("https://owner-snapshot.test").unwrap();
        let key = [41u8; 32];
        let (_tx, rx) = tokio::sync::watch::channel(Some("token".to_owned()));
        let owner = crate::relay_token_source::register(url.clone(), key, rx, None);
        let config = RelayConfig::from(url.clone()).with_registration_owner(owner.clone());
        let map = RelayMap::from_iter([config]);

        let cloned = map.clone();
        let (_, binding) = cloned.get_with_registration(&url);
        assert_eq!(binding, RelayAuthBinding::BoundRequired(Some(owner.clone())));

        let reconstructed = RelayMap::from_iter(map.relays::<Vec<_>>());
        let (_, binding) = reconstructed.get_with_registration(&url);
        assert_eq!(binding, RelayAuthBinding::BoundRequired(Some(owner)));
    }

    #[test]
    fn required_registration_cannot_be_downgraded_by_map_mutations() {
        let url = RelayUrl::from_str("https://sticky-owner.test").unwrap();
        let legacy = RelayConfig::from(url.clone());
        let map = RelayMap::from_iter([legacy.clone()]);
        map.require_registration();

        let binding_of = |map: &RelayMap| {
            map.get_with_registration(&url).1
        };
        assert_eq!(binding_of(&map), RelayAuthBinding::BoundRequired(None));

        let cloned = map.clone();
        cloned.insert(url.clone(), Arc::new(legacy.clone()));
        assert_eq!(binding_of(&map), RelayAuthBinding::BoundRequired(None));

        cloned.remove(&url).expect("relay is present");
        assert_eq!(
            cloned.get_with_registration(&url).1,
            RelayAuthBinding::BoundRequired(None)
        );
        cloned.insert(url.clone(), Arc::new(legacy.clone()));
        assert_eq!(binding_of(&map), RelayAuthBinding::BoundRequired(None));

        let legacy_map = RelayMap::from_iter([legacy]);
        cloned.extend(&legacy_map);
        assert_eq!(binding_of(&map), RelayAuthBinding::BoundRequired(None));

        let reconstructed = RelayMap::from_iter(cloned.relays::<Vec<_>>());
        assert_eq!(binding_of(&reconstructed), RelayAuthBinding::BoundRequired(None));

        let another_url = RelayUrl::from_str("https://sticky-owner-other.test").unwrap();
        let legacy_map = RelayMap::from_iter([
            RelayConfig::from(url.clone()),
            RelayConfig::from(another_url.clone()),
        ]);
        let (_tx, rx) = tokio::sync::watch::channel(Some("owned".to_owned()));
        let owner = crate::relay_token_source::register(url.clone(), [43u8; 32], rx, None);
        legacy_map.insert(
            url.clone(),
            Arc::new(RelayConfig::from(url).with_registration_owner(owner)),
        );
        assert_eq!(
            legacy_map.get_with_registration(&another_url).1,
            RelayAuthBinding::BoundRequired(None)
        );
    }

    #[test]
    fn serialized_binding_preserves_required_mode_without_serializing_owner() {
        let url = RelayUrl::from_str("https://serialized-owner.test").unwrap();
        let (_tx, rx) = tokio::sync::watch::channel(Some("not-serialized".to_owned()));
        let owner = crate::relay_token_source::register(url.clone(), [42u8; 32], rx, None);
        let config = RelayConfig::from(url.clone()).with_registration_owner(owner);

        let encoded = serde_json::to_string(&config).expect("config serializes");
        assert!(encoded.contains("bound_required"));
        assert!(!encoded.contains("not-serialized"));

        let decoded: RelayConfig = serde_json::from_str(&encoded).expect("config deserializes");
        assert_eq!(decoded.registration, RelayAuthBinding::BoundRequired(None));
        assert_eq!(
            RelayMap::from(decoded).get_with_registration(&url).1,
            RelayAuthBinding::BoundRequired(None)
        );
    }
}
