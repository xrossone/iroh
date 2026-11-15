//! Exposes [`Client`], which allows to establish connections to a relay server.
//!
//! Based on tailscale/derp/derphttp/derphttp_client.go

use std::{
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{self, Poll},
};

use conn::Conn;
use iroh_base::{RelayUrl, SecretKey};
#[cfg(not(wasm_browser))]
use iroh_dns::dns::{DnsError, DnsResolver};
use n0_error::{AnyError, e, stack_error};
use n0_future::{
    Sink, Stream,
    split::{SplitSink, SplitStream, split},
    time,
};
use tracing::{debug, trace};
use url::Url;

pub use self::conn::{RecvError, SendError};
use crate::{
    KeyCache,
    http::{ProtocolVersion, RELAY_PATH},
    protos::{
        handshake,
        relay::{ClientToRelayMsg, RelayToClientMsg},
    },
    relay_map::RelayAuthBinding,
    relay_token_source::{self, TokenLookup},
};

pub(crate) mod conn;
#[cfg(not(wasm_browser))]
pub(crate) mod streams;
#[cfg(not(wasm_browser))]
mod tls;
#[cfg(not(wasm_browser))]
mod util;

/// Connection errors.
///
/// `ConnectError` contains `DialError`, errors that can occur while dialing the
/// relay, as well as errors that occur while creating or maintaining a connection.
#[stack_error(derive, add_meta, from_sources)]
#[allow(missing_docs)]
#[non_exhaustive]
pub enum ConnectError {
    #[error("Invalid URL for websocket: {url}")]
    InvalidWebsocketUrl { url: Url },
    #[error("Invalid relay URL: {url}")]
    InvalidRelayUrl { url: Url },
    /// Error returned from the underlying WebSocket stream while establishing the connection.
    ///
    /// The concrete error type is `tokio_websockets::Error` on native targets and
    /// `ws_stream_wasm::WsErr` on `wasm_browser` targets. Use [`AnyError::downcast_ref`] to
    /// recover it. Note that the concrete downcast type is not covered by any semver
    /// guarantees and may change between releases.
    #[error(transparent)]
    Websocket { source: AnyError },
    #[error(
        "Server replied with invalid iroh-relay version header: {}",
        server_version.as_deref().unwrap_or("<empty>")
    )]
    BadVersionHeader { server_version: Option<String> },
    #[error("Authorization token set to a string that is not a valid HTTP header value")]
    InvalidAuthToken,
    #[error(transparent)]
    Handshake {
        #[error(std_err)]
        source: handshake::Error,
    },
    #[error(transparent)]
    Dial { source: DialError },
    #[error("Unexpected status during upgrade: {code}")]
    UnexpectedUpgradeStatus { code: hyper::StatusCode },
    #[error("Failed to upgrade response")]
    Upgrade {
        #[error(std_err)]
        source: hyper::Error,
    },
    #[error("Invalid TLS servername")]
    InvalidTlsServername {},
    #[error("No local address available")]
    NoLocalAddr {},
    #[error("Relay registration owner is missing")]
    RegistrationOwnerMissing {},
    #[error("Relay registration was replaced by another owner")]
    RegistrationSuperseded {},
    #[error("Browser WebSocket connection failed")]
    BrowserWebsocket {},
    #[error("Relay denied endpoint authorization")]
    AuthorizationRejected {},
    #[error("tls connection failed")]
    Tls {
        #[error(std_err)]
        source: std::io::Error,
    },
    #[error(
        "No rustls crypto provider configured while both ring and aws-lc-rs feature flags are disabled"
    )]
    MissingCryptoProvider,
    #[cfg(wasm_browser)]
    #[error("The relay protocol is not available in browsers")]
    RelayProtoNotAvailable {},
}

fn redacted_url(url: &Url) -> Url {
    let mut redacted = url.clone();
    let _ = redacted.set_username("");
    let _ = redacted.set_password(None);
    redacted.set_path("/");
    redacted.set_query(None);
    redacted.set_fragment(None);
    redacted
}

#[cfg(any(wasm_browser, test))]
fn browser_websocket_error<T>(_source: T) -> ConnectError {
    e!(ConnectError::BrowserWebsocket {})
}

/// Errors that can occur while dialing the relay server.
#[stack_error(derive, add_meta, from_sources)]
#[allow(missing_docs)]
#[non_exhaustive]
pub enum DialError {
    #[error("Invalid target port")]
    InvalidTargetPort {},
    #[error(transparent)]
    #[cfg(not(wasm_browser))]
    Dns { source: DnsError },
    #[error(transparent)]
    Timeout {
        #[error(std_err)]
        source: time::Elapsed,
    },
    #[error(transparent)]
    Io {
        #[error(std_err)]
        source: std::io::Error,
    },
    #[error("Invalid URL: {url}")]
    InvalidUrl { url: Url },
    #[error("Failed proxy connection: {status}")]
    ProxyConnectInvalidStatus { status: hyper::StatusCode },
    #[error("Invalid Proxy URL {proxy_url}")]
    ProxyInvalidUrl { proxy_url: Url },
    #[error("failed to establish proxy connection")]
    ProxyConnect {
        #[error(std_err)]
        source: hyper::Error,
    },
    #[error("Invalid proxy TLS servername: {proxy_hostname}")]
    ProxyInvalidTlsServername { proxy_hostname: String },
    #[error("Invalid proxy target port")]
    ProxyInvalidTargetPort {},
}

/// Build a Client.
#[derive(derive_more::Debug, Clone)]
pub struct ClientBuilder {
    /// Default is None
    #[debug("address family selector callback")]
    address_family_selector: Option<Arc<dyn Fn() -> bool + Send + Sync>>,
    /// Server url.
    url: RelayUrl,
    /// TLS verification config.
    tls_config: Option<rustls::ClientConfig>,
    /// HTTP Proxy
    proxy_url: Option<Url>,
    /// The secret key of this client.
    secret_key: SecretKey,
    /// Optional authorization token.
    ///
    /// Sent as an `Authorization: Bearer` header on native targets and as
    /// a `?token=` query parameter under Wasm. See [`ClientBuilder::auth_token`].
    #[debug("authorization token (<redacted>)")]
    auth_token: Option<String>,
    /// Endpoint-level authorization policy captured from the relay map when
    /// the active relay actor is created.
    registration_binding: RelayAuthBinding,
    #[cfg(not(wasm_browser))]
    dns_resolver: DnsResolver,
    /// Cache for public keys of remote endpoints.
    key_cache: KeyCache,
}

impl ClientBuilder {
    /// Create a new [`ClientBuilder`]
    pub fn new(
        url: impl Into<RelayUrl>,
        secret_key: SecretKey,
        #[cfg(not(wasm_browser))] dns_resolver: DnsResolver,
    ) -> Self {
        ClientBuilder {
            address_family_selector: None,
            url: url.into(),
            tls_config: None,
            proxy_url: None,
            secret_key,
            #[cfg(not(wasm_browser))]
            dns_resolver,
            key_cache: KeyCache::new(128),
            auth_token: None,
            registration_binding: RelayAuthBinding::Legacy,
        }
    }

    /// Sets a custom TLS config.
    ///
    /// This is a required option.
    ///
    /// You can construct a [`rustls::ClientConfig`] by combining a [`rustls::crypto::CryptoProvider`]
    /// with a [`tls::CaTlsConfig`] using [`tls::CaTlsConfig::client_config`], for example:
    ///
    /// ```no_run
    /// use std::sync::Arc;
    ///
    /// use iroh_relay::tls::CaTlsConfig;
    ///
    /// let crypto_provider: rustls::crypto::CryptoProvider = todo!();
    /// let client_config = CaTlsConfig::default().client_config(Arc::new(crypto_provider));
    /// ```
    ///
    /// If you enable the tls-ring or tls-aws-lc-rs feature, you can use the enabled crypto provider
    /// by using [`tls::default_provider`].
    ///
    /// [`tls::CaTlsConfig`]: crate::tls::CaTlsConfig
    /// [`tls::CaTlsConfig::client_config`]: crate::tls::CaTlsConfig::client_config
    /// [`tls::default_provider`]: crate::tls::default_provider
    pub fn tls_client_config(mut self, tls_config: rustls::ClientConfig) -> Self {
        self.tls_config = Some(tls_config);
        self
    }

    /// Sets a callback hinting whether to prefer IPv6 when dialing the relay.
    ///
    /// The callback runs on each dial. When it returns `true`, IPv6 addresses
    /// are tried first and IPv4 dials are held back slightly, biasing the
    /// happy-eyeballs race towards IPv6; when it returns `false`, IPv4 is
    /// preferred. Only return `true` when IPv6 is expected to work, since
    /// otherwise the bias just delays the connection.
    pub fn address_family_selector<S>(mut self, selector: S) -> Self
    where
        S: Fn() -> bool + Send + Sync + 'static,
    {
        self.address_family_selector = Some(Arc::new(selector));
        self
    }

    /// Set an explicit proxy url to proxy all HTTP(S) traffic through.
    pub fn proxy_url(mut self, url: Url) -> Self {
        self.proxy_url.replace(url);
        self
    }

    /// Sets an authorization token.
    ///
    /// On native targets, the token is sent as an `Authorization: Bearer TOKEN`
    /// header on the WebSocket upgrade request that establishes the relay
    /// connection. The token must be a valid HTTP header field value, if not
    /// [`Self::connect`] will return [`ConnectError::InvalidAuthToken`].
    ///
    /// When compiled to WebAssembly the token is sent as a `?token=TOKEN`
    /// query parameter on the upgrade URL, since browsers don't allow setting
    /// headers on WebSocket requests.
    pub fn auth_token(mut self, token: impl Into<String>) -> Self {
        self.auth_token = Some(token.into());
        self
    }

    /// Requires this client to use the endpoint registration attached to its
    /// relay-map entry. Missing or superseded registrations fail closed and
    /// never fall back to [`Self::auth_token`].
    pub fn registration_binding(mut self, binding: RelayAuthBinding) -> Self {
        self.registration_binding = binding;
        self
    }

    fn auth_token_for_connect(&self) -> Result<Option<String>, ConnectError> {
        let public_key = self.secret_key.public();
        let endpoint_key = public_key.as_bytes();
        match &self.registration_binding {
            RelayAuthBinding::Legacy => Ok(
                relay_token_source::current(&self.url, endpoint_key)
                    .or_else(|| self.auth_token.clone()),
            ),
            RelayAuthBinding::BoundRequired(None) => {
                Err(e!(ConnectError::RegistrationOwnerMissing {}))
            }
            RelayAuthBinding::BoundRequired(Some(owner)) => {
                match relay_token_source::current_for(&self.url, endpoint_key, owner) {
                    TokenLookup::Current(token) => Ok(token),
                    TokenLookup::OwnerMismatch => {
                        Err(e!(ConnectError::RegistrationSuperseded {}))
                    }
                }
            }
        }
    }

    fn note_authorization_rejected(&self) {
        let public_key = self.secret_key.public();
        let endpoint_key = public_key.as_bytes();
        match &self.registration_binding {
            RelayAuthBinding::Legacy => relay_token_source::note_rejected(&self.url, endpoint_key),
            RelayAuthBinding::BoundRequired(Some(owner)) => {
                relay_token_source::note_rejected_for(&self.url, endpoint_key, owner);
            }
            RelayAuthBinding::BoundRequired(None) => {}
        }
    }

    #[cfg(wasm_browser)]
    fn wasm_dial_urls(mut dial_url: Url, token: Option<&str>) -> (Url, Url) {
        let url_for_log = redacted_url(&dial_url);
        if let Some(token) = token {
            dial_url
                .query_pairs_mut()
                .append_pair(crate::http::AUTH_TOKEN_URL_QUERY_PARAM, token);
        }
        (dial_url, url_for_log)
    }

    /// Set the capacity of the cache for public keys.
    pub fn key_cache_capacity(mut self, capacity: usize) -> Self {
        self.key_cache = KeyCache::new(capacity);
        self
    }

    /// Establishes a new connection to the relay server.
    #[cfg(not(wasm_browser))]
    pub async fn connect(&self) -> Result<Client, ConnectError> {
        use http::header::{AUTHORIZATION, HeaderValue, SEC_WEBSOCKET_PROTOCOL};
        use tls::MaybeTlsStreamBuilder;

        use crate::{
            http::CLIENT_AUTH_HEADER,
            protos::{handshake::KeyMaterialClientAuth, relay::MAX_FRAME_SIZE},
        };

        let mut dial_url = (*self.url).clone();
        dial_url.set_path(RELAY_PATH);
        // The relay URL is exchanged with the http(s) scheme in tickets and similar.
        // We need to use the ws:// or wss:// schemes when connecting with websockets, though.
        dial_url
            .set_scheme(match self.url.scheme() {
                "http" => "ws",
                "ws" => "ws",
                _ => "wss",
            })
            .map_err(|_| {
                e!(ConnectError::InvalidWebsocketUrl {
                    url: redacted_url(&dial_url)
                })
            })?;

        debug!(url = %redacted_url(&dial_url), "Dialing relay by websocket");

        // Resolve the owner before opening a socket. A removed or superseded
        // endpoint registration must not reach the network or fall back to a
        // stale builder-captured token.
        let auth_token = self.auth_token_for_connect()?;

        let tls_config = self
            .tls_config
            .clone()
            .ok_or_else(|| e!(ConnectError::MissingCryptoProvider))?;

        #[allow(unused_mut)]
        let mut builder =
            MaybeTlsStreamBuilder::new(dial_url.clone(), self.dns_resolver.clone(), tls_config)
                .prefer_ipv6(self.prefer_ipv6())
                .proxy_url(self.proxy_url.clone());

        let stream = builder.connect().await?;
        let local_addr = stream
            .as_ref()
            .local_addr()
            .map_err(|_| e!(ConnectError::NoLocalAddr))?;

        let mut builder = tokio_websockets::ClientBuilder::new()
            .uri(dial_url.as_str())
            .map_err(|_| {
                e!(ConnectError::InvalidRelayUrl {
                    url: redacted_url(&dial_url)
                })
            })?
            .add_header(
                SEC_WEBSOCKET_PROTOCOL,
                ProtocolVersion::all_as_header_value(),
            )
            .expect("valid header name and value")
            .limits(tokio_websockets::Limits::default().max_payload_len(Some(MAX_FRAME_SIZE)))
            // We turn off automatic flushing after a threshold (the default would be after 8KB).
            // This means we need to flush manually, which we do by calling `Sink::send_all` or
            // `Sink::send` (which calls `Sink::flush`) in the `ActiveRelayActor`.
            .config(tokio_websockets::Config::default().flush_threshold(usize::MAX));

        // The registered token wins over the one captured in the builder. iroh's
        // relay actor clones this builder on every redial, so this is the line
        // that makes a refreshed grant apply to a live endpoint — the whole of
        // ADR 0027 §5's precondition.
        if let Some(token) = auth_token {
            let value = HeaderValue::from_str(&format!("Bearer {token}"))
                .map_err(|_| e!(ConnectError::InvalidAuthToken))?;
            builder = builder
                .add_header(AUTHORIZATION, value)
                .expect("valid header name");
        }

        if let Some(client_auth) = KeyMaterialClientAuth::new(&self.secret_key, &stream) {
            debug!("Using TLS key export for relay client authentication");
            builder = builder
                .add_header(CLIENT_AUTH_HEADER, client_auth.into_header_value())
                .expect(
                    "impossible: CLIENT_AUTH_HEADER isn't a disallowed header value for websockets",
                );
        }
        let (conn, response) = match builder.connect_on(stream).await {
            Ok(result) => result,
            Err(tokio_websockets::Error::Upgrade(
                tokio_websockets::upgrade::Error::DidNotSwitchProtocols(status),
            )) => {
                let status = hyper::StatusCode::from_u16(status)
                    .unwrap_or(hyper::StatusCode::INTERNAL_SERVER_ERROR);
                if status == hyper::StatusCode::UNAUTHORIZED
                    || status == hyper::StatusCode::FORBIDDEN
                {
                    self.note_authorization_rejected();
                }
                return Err(e!(ConnectError::UnexpectedUpgradeStatus { code: status }));
            }
            Err(err) => {
                return Err(e!(ConnectError::Websocket {
                    source: AnyError::from_std(err),
                }));
            }
        };

        // **This is the one place in this crate where "grant refused" is
        // distinguishable from "unreachable".** A relay that refuses a grant
        // answers the websocket upgrade with 401 or 403 instead of 101; every
        // other failure — a dial error, a TLS failure, a 502 from a proxy, a 404
        // from a misconfigured URL — is not an authorization answer and must not
        // send the runtime off to refetch a grant that is fine.
        //
        // Without this call `RelayAuthorizationSink::authorization_rejected` has
        // no caller, `xrossd` can never reach `grant_state: "refused"`, and ADR
        // 0027 §8's *"a silent permanent failure rather than a slow one"* is
        // exactly what ships: the actor redials for ever with a token the relay
        // has already rejected.
        let status = response.status();
        if status != hyper::StatusCode::SWITCHING_PROTOCOLS {
            if status == hyper::StatusCode::UNAUTHORIZED || status == hyper::StatusCode::FORBIDDEN {
                self.note_authorization_rejected();
            }
            return Err(e!(ConnectError::UnexpectedUpgradeStatus { code: status }));
        }

        let protocol_version_str = response
            .headers()
            .get(SEC_WEBSOCKET_PROTOCOL)
            .and_then(|s| s.to_str().ok());
        let protocol_version = protocol_version_str
            .and_then(ProtocolVersion::match_from_str)
            .ok_or_else(|| {
                e!(ConnectError::BadVersionHeader {
                    server_version: protocol_version_str.map(ToOwned::to_owned)
                })
            })?;

        // **The other place a refusal is distinguishable from unreachable.**
        // The check above covers a relay that denies the websocket upgrade
        // itself (401/403). This relay's own access control denies later:
        // every request upgrades to 101, and `AccessControl::on_connect`'s
        // `Deny` is delivered inside the handshake protocol that
        // `Conn::new` runs, as a `ServerDeniesAuth` frame — surfaced here as
        // `handshake::Error::ServerDeniedAuth`. A revoked grant takes this
        // path, not the status-code one above, so the reverse edge has to be
        // raised here too or a revocation is never reported.
        let conn = Conn::new(
            conn,
            self.key_cache.clone(),
            &self.secret_key,
            protocol_version,
        )
        .await
        .inspect_err(|err| {
            if matches!(err, handshake::Error::ServerDeniedAuth { .. }) {
                self.note_authorization_rejected();
            }
        })?;

        trace!("connect done");

        Ok(Client {
            conn,
            local_addr: Some(local_addr),
        })
    }

    /// Reports whether IPv4 dials should be slightly
    /// delayed to give IPv6 a better chance of winning dial races.
    /// Implementations should only return true if IPv6 is expected
    /// to succeed. (otherwise delaying IPv4 will delay the connection
    /// overall)
    #[cfg(not(wasm_browser))]
    fn prefer_ipv6(&self) -> bool {
        match self.address_family_selector {
            Some(ref selector) => selector(),
            None => false,
        }
    }

    /// Establishes a new connection to the relay server.
    #[cfg(wasm_browser)]
    pub async fn connect(&self) -> Result<Client, ConnectError> {
        let mut dial_url = (*self.url).clone();
        dial_url.set_path(RELAY_PATH);
        // The relay URL is exchanged with the http(s) scheme in tickets and similar.
        // We need to use the ws:// or wss:// schemes when connecting with websockets, though.
        dial_url
            .set_scheme(match self.url.scheme() {
                "http" => "ws",
                "ws" => "ws",
                _ => "wss",
            })
            .map_err(|_| {
                e!(ConnectError::InvalidWebsocketUrl {
                    url: redacted_url(&dial_url)
                })
            })?;

        // Resolve before dialing. `WsMeta::connect` does not expose HTTP status
        // codes, so browser-side pre-upgrade 401/403 cannot be classified, but
        // the protocol handshake below can report `ServerDeniedAuth`.
        let auth_token = self.auth_token_for_connect()?;
        let (dial_url, url_for_log) = Self::wasm_dial_urls(dial_url, auth_token.as_deref());

        // Never log the `?token=` URL: browser WebSocket APIs require the
        // credential in the query string, which would otherwise expose it.
        debug!(url = %url_for_log, "Dialing relay by websocket");

        let (ws_meta, ws_stream) = ws_stream_wasm::WsMeta::connect(
            dial_url.as_str(),
            Some(ProtocolVersion::all().collect()),
        )
        .await
        .map_err(browser_websocket_error)?;

        let protocol_version =
            ProtocolVersion::match_from_str(&ws_meta.protocol()).ok_or_else(|| {
                e!(ConnectError::BadVersionHeader {
                    server_version: None
                })
            })?;

        let conn = match Conn::new(
            ws_stream,
            self.key_cache.clone(),
            &self.secret_key,
            protocol_version,
        )
        .await
        {
            Ok(conn) => conn,
            Err(handshake::Error::ServerDeniedAuth { .. }) => {
                self.note_authorization_rejected();
                return Err(e!(ConnectError::AuthorizationRejected {}));
            }
            Err(_err) => return Err(browser_websocket_error(())),
        };

        trace!("connect done");

        Ok(Client {
            conn,
            local_addr: None,
        })
    }
}

/// A relay client.
#[derive(Debug)]
pub struct Client {
    conn: Conn,
    local_addr: Option<SocketAddr>,
}

impl Client {
    /// Splits the client into a sink and a stream.
    pub fn split(self) -> (ClientStream, ClientSink) {
        let (sink, stream) = split(self.conn);
        (
            ClientStream {
                stream,
                local_addr: self.local_addr,
            },
            ClientSink { sink },
        )
    }
}

impl Stream for Client {
    type Item = Result<RelayToClientMsg, RecvError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.conn).poll_next(cx)
    }
}

impl Sink<ClientToRelayMsg> for Client {
    type Error = SendError;

    fn poll_ready(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.conn).poll_ready(cx)
    }

    fn start_send(mut self: Pin<&mut Self>, item: ClientToRelayMsg) -> Result<(), Self::Error> {
        Pin::new(&mut self.conn).start_send(item)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.conn).poll_flush(cx)
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.conn).poll_close(cx)
    }
}

/// The send half of a relay client.
#[derive(Debug)]
pub struct ClientSink {
    sink: SplitSink<Conn, ClientToRelayMsg>,
}

impl Sink<ClientToRelayMsg> for ClientSink {
    type Error = SendError;

    fn poll_ready(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.sink).poll_ready(cx)
    }

    fn start_send(mut self: Pin<&mut Self>, item: ClientToRelayMsg) -> Result<(), Self::Error> {
        Pin::new(&mut self.sink).start_send(item)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.sink).poll_flush(cx)
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.sink).poll_close(cx)
    }
}

/// The receive half of a relay client.
#[derive(Debug)]
pub struct ClientStream {
    stream: SplitStream<Conn>,
    local_addr: Option<SocketAddr>,
}

impl ClientStream {
    /// Returns the local address of the client.
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
    }
}

#[cfg(test)]
mod registration_tests {
    use super::*;
    use crate::{relay_map::RelayAuthBinding, relay_token_source};

    fn make_builder(url: RelayUrl, secret: SecretKey) -> ClientBuilder {
        ClientBuilder::new(
            url,
            secret,
            #[cfg(not(wasm_browser))]
            DnsResolver::new(),
        )
    }

    fn relay_url() -> RelayUrl {
        "https://builder-owner.test".parse().expect("valid relay URL")
    }

    #[test]
    fn bound_registration_never_falls_back_to_static_auth() {
        let url = relay_url();
        let secret = SecretKey::from_bytes(&[31; 32]);
        let key = *secret.public().as_bytes();

        let (_old_tx, old_rx) = tokio::sync::watch::channel(Some("old-live".to_owned()));
        let old_owner = relay_token_source::register(url.clone(), key, old_rx, None);
        let (new_tx, new_rx) = tokio::sync::watch::channel(Some("new-live".to_owned()));
        let new_owner = relay_token_source::register(url.clone(), key, new_rx, None);

        let builder = make_builder(url.clone(), secret.clone())
        .auth_token("stale-static")
        .registration_binding(RelayAuthBinding::BoundRequired(Some(old_owner)));

        assert!(matches!(
            builder.auth_token_for_connect(),
            Err(ConnectError::RegistrationSuperseded { .. })
        ));

        let current_builder = make_builder(url.clone(), secret.clone())
            .auth_token("stale-static")
            .registration_binding(RelayAuthBinding::BoundRequired(Some(new_owner.clone())));
        assert_eq!(
            current_builder.auth_token_for_connect().unwrap(),
            Some("new-live".to_owned())
        );
        let redial_builder = current_builder.clone();
        new_tx.send(Some("new-refresh".to_owned())).unwrap();
        assert_eq!(
            redial_builder.auth_token_for_connect().unwrap(),
            Some("new-refresh".to_owned())
        );

        let (_empty_tx, empty_rx) = tokio::sync::watch::channel(None);
        let empty_owner = relay_token_source::register(url.clone(), key, empty_rx, None);
        let empty_builder = make_builder(url.clone(), secret.clone())
            .auth_token("stale-static")
            .registration_binding(RelayAuthBinding::BoundRequired(Some(empty_owner)));
        assert_eq!(empty_builder.auth_token_for_connect().unwrap(), None);

        let missing_owner = make_builder(url, secret)
            .auth_token("stale-static")
            .registration_binding(RelayAuthBinding::BoundRequired(None));
        assert!(matches!(
            missing_owner.auth_token_for_connect(),
            Err(ConnectError::RegistrationOwnerMissing { .. })
        ));
    }

    #[test]
    fn browser_websocket_error_mapping_drops_dom_source_and_grant_query() {
        let secret = "grant-secret-should-not-appear";
        let raw = format!(
            "SyntaxError: invalid WebSocket URL wss://relay.test/?token={secret}"
        );
        let mapped = browser_websocket_error(raw);
        let display = format!("{mapped}");
        let debug = format!("{mapped:?}");

        assert!(!display.contains(secret), "{display}");
        assert!(!display.contains("SyntaxError"), "{display}");
        assert!(!debug.contains(secret), "{debug}");
        assert!(!debug.contains("SyntaxError"), "{debug}");
        assert_eq!(display, "Browser WebSocket connection failed");
    }

    #[test]
    fn error_url_keeps_only_the_non_sensitive_origin() {
        let raw = Url::parse(
            "wss://user:password@relay.test:443/private/path?token=grant-secret#fragment",
        )
        .unwrap();
        let redacted = redacted_url(&raw);

        assert_eq!(redacted.as_str(), "wss://relay.test/");
        assert!(!redacted.as_str().contains("password"));
        assert!(!redacted.as_str().contains("grant-secret"));
        assert!(!redacted.as_str().contains("private"));
    }

    #[cfg(wasm_browser)]
    #[test]
    fn wasm_query_uses_the_selected_owner_token_but_log_url_is_redacted() {
        let url = relay_url();
        let secret = SecretKey::from_bytes(&[32; 32]);
        let key = *secret.public().as_bytes();
        let (tx, rx) = tokio::sync::watch::channel(Some("query-token & refresh".to_owned()));
        let owner = relay_token_source::register(url.clone(), key, rx, None);
        let builder = make_builder(url, secret).registration_binding(RelayAuthBinding::BoundRequired(
            Some(owner),
        ));
        let token = builder
            .auth_token_for_connect()
            .expect("current owner")
            .expect("token present");
        let dial_url = Url::parse(
            "wss://user:password@builder-owner.test/private/path?debug=preexisting#fragment",
        )
        .unwrap();
        let (request_url, log_url) = ClientBuilder::wasm_dial_urls(dial_url, Some(&token));

        assert_eq!(
            request_url
                .query_pairs()
                .find(|(key, _)| key == crate::http::AUTH_TOKEN_URL_QUERY_PARAM)
                .map(|(_, value)| value.into_owned()),
            Some("query-token & refresh".to_owned())
        );
        assert_eq!(log_url.as_str(), "wss://builder-owner.test/");
        assert!(!log_url.as_str().contains("debug=preexisting"));
        tx.send(Some("next".to_owned())).unwrap();
        let refreshed = builder.auth_token_for_connect().unwrap().unwrap();
        let (request_url, log_url) = ClientBuilder::wasm_dial_urls(
            Url::parse("wss://builder-owner.test/derp?debug=next").unwrap(),
            Some(&refreshed),
        );
        assert_eq!(
            request_url
                .query_pairs()
                .find(|(key, _)| key == crate::http::AUTH_TOKEN_URL_QUERY_PARAM)
                .map(|(_, value)| value.into_owned()),
            Some("next".to_owned())
        );
        assert_eq!(log_url.as_str(), "wss://builder-owner.test/");
        assert!(!log_url.as_str().contains("debug=next"));
    }
}

impl Stream for ClientStream {
    type Item = Result<RelayToClientMsg, RecvError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.stream).poll_next(cx)
    }
}
