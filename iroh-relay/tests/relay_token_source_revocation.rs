//! F2 of Xross task-10's fix round: the client-side half of the revocation
//! loop.
//!
//! `xross-fabric`'s `Custom` relay-policy arm used to call
//! `RelayConfig::with_auth_token` from the *same* initial value it seeded
//! into this crate's `relay_token_source` registry, so `client.rs`'s
//! `connect()` — `live.as_ref().or(self.auth_token.as_ref())` — fell back to
//! that stale value whenever the registry held `None`: pushing `None` (the
//! only way a runtime says "stop presenting this grant") did not stop
//! anything, because the builder still carried a static copy of the same
//! token. The fix removed that call, making the registry the only source of
//! truth for a `Custom`-policy relay.
//!
//! This drives the fixed shape end to end against a real (in-process) relay,
//! the same way `runtime_auth.rs` drives server-side revocation: a
//! `ClientBuilder` with **no** static `auth_token` — exactly what
//! `xross-fabric` now builds — whose only source of a token is this
//! registry.

#![cfg(feature = "server")]

use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use iroh_base::{EndpointId, RelayUrl, SecretKey};
use iroh_dns::dns::DnsResolver;
use iroh_relay::client::{Client, ClientBuilder, ConnectError};
use iroh_relay::protos::handshake;
use iroh_relay::relay_token_source;
use iroh_relay::RelayConfig as ClientRelayConfig;
use iroh_relay::server::{
    Access, AccessControl, ClientRequest, ConnectionId, RelayConfig as ServerRelayConfig, Server,
    ServerConfig,
};
use iroh_relay::tls::{CaTlsConfig, default_provider};
use n0_error::Result;
use rand::RngExt;

/// Admits a connection only if it presents exactly `"token-a"`. Deliberately
/// simpler than `runtime_auth.rs`'s `TokenAccess`: this test is not about the
/// server's revocation index, only about what the client presents.
#[derive(Debug)]
struct SingleTokenAccess;

impl AccessControl for SingleTokenAccess {
    async fn on_connect(&self, request: &ClientRequest) -> Access {
        match request.auth_token() {
            Some(token) if token == "token-a" => Access::Allow,
            _ => Access::Deny { reason: None },
        }
    }

    fn on_disconnect(&self, _endpoint_id: EndpointId, _connection_id: ConnectionId) {}
}

#[tokio::test]
async fn pushing_none_through_the_registry_makes_the_client_present_nothing() -> Result<()> {
    let mut relay = ServerRelayConfig::new((Ipv4Addr::LOCALHOST, 0));
    relay.access = Arc::new(SingleTokenAccess);
    let mut config = ServerConfig::default();
    config.relay = Some(relay);
    let server = Server::spawn(config).await?;
    let relay_url: RelayUrl = format!("http://{}", server.http_addr().expect("http addr"))
        .parse()
        .expect("valid relay url");

    let secret = SecretKey::from_bytes(&rand::rng().random());
    let endpoint_key = *secret.public().as_bytes();

    // Registered exactly as `xross-fabric`'s fixed `Custom` arm does: a live
    // source seeded with the initial grant, and no `.auth_token()` anywhere
    // on the builder below — the registry is the only place a token can come
    // from.
    let (tx, rx) = tokio::sync::watch::channel(Some("token-a".to_owned()));
    relay_token_source::register(relay_url.clone(), endpoint_key, rx, None);

    let tls = CaTlsConfig::default()
        .client_config(default_provider())
        .expect("valid client config");
    async fn connect(
        relay_url: &RelayUrl,
        secret: &SecretKey,
        tls: &rustls::ClientConfig,
    ) -> Result<Client, ConnectError> {
        ClientBuilder::new(relay_url.clone(), secret.clone(), DnsResolver::new())
            .tls_client_config(tls.clone())
            .connect()
            .await
    }

    // The registry alone supplies the token: the first connection is
    // admitted, with no `.auth_token()` ever called on the builder.
    let _first: Client = connect(&relay_url, &secret, &tls)
        .await
        .expect("the registry's token should admit this connection");

    // Revocation: push `None`. A client dialling fresh must now present
    // nothing at all — not the token it presented a moment ago — because
    // there is no static `auth_token` on the builder to fall back to. Before
    // the fix, `xross-fabric` would also have baked "token-a" into the
    // builder at bind time, and this second connection would have been
    // admitted exactly like the first.
    tx.send(None).expect("receiver still registered");
    let denied = connect(&relay_url, &secret, &tls).await;
    assert!(
        matches!(
            denied,
            Err(ConnectError::Handshake {
                source: handshake::Error::ServerDeniedAuth { .. },
                ..
            })
        ),
        "expected the relay to deny a connection presenting no token, got {denied:?}"
    );

    Ok(())
}

/// Admits `"token-a"` until [`revoked`](Self::revoked) is flipped, then denies
/// every connection regardless of what token it presents — the shape of a
/// live operator revocation, where the token itself does not change but the
/// server's decision about it does.
#[derive(Debug)]
struct RevocableAccess {
    revoked: std::sync::atomic::AtomicBool,
}

impl AccessControl for RevocableAccess {
    async fn on_connect(&self, request: &ClientRequest) -> Access {
        if self.revoked.load(std::sync::atomic::Ordering::SeqCst) {
            return Access::Deny {
                reason: Some("Revoked".to_owned()),
            };
        }
        match request.auth_token() {
            Some(token) if token == "token-a" => Access::Allow,
            _ => Access::Deny { reason: None },
        }
    }

    fn on_disconnect(&self, _endpoint_id: EndpointId, _connection_id: ConnectionId) {}
}

/// The defect this test pins: `relay_token_source_revocation.rs`'s existing
/// test above pushes `None` into the registry and checks that the client
/// then presents nothing — it never drives the case where the client
/// presents a token the *server* rejects, which is what a live revocation
/// looks like. This relay never answers the websocket upgrade with 401/403;
/// `AccessControl::on_connect`'s `Deny` is delivered inside the handshake
/// protocol that runs after the upgrade, as `ServerDeniesAuth`. Before the
/// fix, `client.rs`'s `connect()` only called
/// `relay_token_source::note_rejected` on the 401/403 path, so a real
/// revocation over this relay never reached the registry's rejection
/// notifier at all — which is exactly the symptom the backlog entry
/// ("A revoked device reports `held` while the relay is actively refusing
/// it") describes: `connected: false` but `grant_state: "held"` forever.
#[tokio::test]
async fn a_grant_the_relay_rejects_after_admitting_it_raises_the_reverse_edge() -> Result<()> {
    let access = Arc::new(RevocableAccess {
        revoked: std::sync::atomic::AtomicBool::new(false),
    });
    let mut relay = ServerRelayConfig::new((Ipv4Addr::LOCALHOST, 0));
    relay.access = access.clone();
    let mut config = ServerConfig::default();
    config.relay = Some(relay);
    let server = Server::spawn(config).await?;
    let relay_url: RelayUrl = format!("http://{}", server.http_addr().expect("http addr"))
        .parse()
        .expect("valid relay url");

    let secret = SecretKey::from_bytes(&rand::rng().random());
    let endpoint_key = *secret.public().as_bytes();

    let (_tx, rx) = tokio::sync::watch::channel(Some("token-a".to_owned()));
    let rejections = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = rejections.clone();
    relay_token_source::register(
        relay_url.clone(),
        endpoint_key,
        rx,
        Some(Arc::new(move || {
            counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        })),
    );

    let tls = CaTlsConfig::default()
        .client_config(default_provider())
        .expect("valid client config");
    async fn connect(
        relay_url: &RelayUrl,
        secret: &SecretKey,
        tls: &rustls::ClientConfig,
    ) -> Result<Client, ConnectError> {
        ClientBuilder::new(relay_url.clone(), secret.clone(), DnsResolver::new())
            .tls_client_config(tls.clone())
            .connect()
            .await
    }

    // Admitted while the grant is still good — same token the registry will
    // keep presenting after revocation, because revocation here is an
    // operator decision at the relay, not a change to the token string.
    let _first: Client = connect(&relay_url, &secret, &tls)
        .await
        .expect("token-a should be admitted before revocation");
    assert_eq!(
        rejections.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "no rejection should have been reported yet"
    );

    // The operator revokes the grant server-side. The registry still holds
    // "token-a" — nothing pushed it a new value, because revocation is not a
    // client-side event.
    access.revoked.store(true, std::sync::atomic::Ordering::SeqCst);

    let denied = connect(&relay_url, &secret, &tls).await;
    assert!(
        matches!(
            denied,
            Err(ConnectError::Handshake {
                source: handshake::Error::ServerDeniedAuth { .. },
                ..
            })
        ),
        "expected the relay to deny the now-revoked token during the handshake, got {denied:?}"
    );

    assert_eq!(
        rejections.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "note_rejected must fire on a post-upgrade ServerDeniedAuth, not only on an HTTP 401/403"
    );

    Ok(())
}

#[derive(Debug)]
struct GenerationAccess {
    revoked: std::sync::atomic::AtomicBool,
    presented: Arc<Mutex<Vec<Option<String>>>>,
}

impl AccessControl for GenerationAccess {
    async fn on_connect(&self, request: &ClientRequest) -> Access {
        let token = request.auth_token();
        self.presented.lock().expect("access log lock").push(token.clone());
        if !self.revoked.load(std::sync::atomic::Ordering::SeqCst)
            && matches!(token.as_deref(), Some("new-live" | "new-refresh"))
        {
            Access::Allow
        } else {
            Access::Deny { reason: None }
        }
    }

    fn on_disconnect(&self, _endpoint_id: EndpointId, _connection_id: ConnectionId) {}
}

/// Two endpoint generations for the same device key and relay must not share
/// registry authority. The old builder retains its map snapshot and must fail
/// before reaching the server after the new generation replaces the entry;
/// cloned redial builders for the current generation must see its refresh.
#[tokio::test]
async fn replaced_endpoint_builder_cannot_use_or_notify_for_the_new_generation() -> Result<()> {
    let presented = Arc::new(Mutex::new(Vec::new()));
    let access = Arc::new(GenerationAccess {
        revoked: std::sync::atomic::AtomicBool::new(false),
        presented: presented.clone(),
    });
    let mut relay = ServerRelayConfig::new((Ipv4Addr::LOCALHOST, 0));
    relay.access = access.clone();
    let mut config = ServerConfig::default();
    config.relay = Some(relay);
    let server = Server::spawn(config).await?;
    let relay_url: RelayUrl = format!("http://{}", server.http_addr().expect("http addr"))
        .parse()
        .expect("valid relay url");

    let secret = SecretKey::from_bytes(&rand::rng().random());
    let endpoint_key = *secret.public().as_bytes();
    let old_refusals = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let old_refusal_count = old_refusals.clone();
    let (_old_tx, old_rx) = tokio::sync::watch::channel(Some("old-live".to_owned()));
    let old_owner = relay_token_source::register(
        relay_url.clone(),
        endpoint_key,
        old_rx,
        Some(Arc::new(move || {
            old_refusal_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        })),
    );
    let old_map = iroh_relay::RelayMap::from(
        ClientRelayConfig::from(relay_url.clone())
            .with_auth_token("old-static")
            .with_registration_owner(old_owner),
    );
    old_map.require_registration();
    let (_, old_binding) = old_map.get_with_registration(&relay_url);
    let tls = CaTlsConfig::default()
        .client_config(default_provider())
        .expect("valid client config");
    let old_builder = ClientBuilder::new(relay_url.clone(), secret.clone(), DnsResolver::new())
        .tls_client_config(tls.clone())
        .auth_token("builder-static")
        .registration_binding(old_binding);

    let new_refusals = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let new_refusal_count = new_refusals.clone();
    let (new_tx, new_rx) = tokio::sync::watch::channel(Some("new-live".to_owned()));
    let new_owner = relay_token_source::register(
        relay_url.clone(),
        endpoint_key,
        new_rx,
        Some(Arc::new(move || {
            new_refusal_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        })),
    );
    let new_map = iroh_relay::RelayMap::from(
        ClientRelayConfig::from(relay_url.clone())
            .with_auth_token("new-static")
            .with_registration_owner(new_owner),
    );
    new_map.require_registration();
    let (_, new_binding) = new_map.get_with_registration(&relay_url);
    let new_builder = ClientBuilder::new(relay_url.clone(), secret, DnsResolver::new())
        .tls_client_config(tls)
        .auth_token("builder-static")
        .registration_binding(new_binding);

    let old_result = old_builder.connect().await;
    assert!(matches!(
        old_result,
        Err(ConnectError::RegistrationSuperseded { .. })
    ));
    assert!(presented.lock().expect("access log lock").is_empty());
    assert_eq!(old_refusals.load(std::sync::atomic::Ordering::SeqCst), 0);

    let _first = new_builder
        .connect()
        .await
        .expect("the current generation's live token is accepted");
    assert_eq!(
        presented.lock().expect("access log lock").clone(),
        vec![Some("new-live".to_owned())]
    );

    new_tx.send(Some("new-refresh".to_owned())).unwrap();
    let redial_builder = new_builder.clone();
    let _refreshed = redial_builder
        .connect()
        .await
        .expect("a clone sees the current generation's refreshed token");
    assert_eq!(
        presented.lock().expect("access log lock").clone(),
        vec![Some("new-live".to_owned()), Some("new-refresh".to_owned())]
    );

    access
        .revoked
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let denied = new_builder.connect().await;
    assert!(matches!(
        denied,
        Err(ConnectError::Handshake {
            source: handshake::Error::ServerDeniedAuth { .. },
            ..
        })
    ));
    assert_eq!(old_refusals.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(new_refusals.load(std::sync::atomic::Ordering::SeqCst), 1);

    Ok(())
}

#[tokio::test]
async fn native_http_refusals_notify_only_the_matching_registration_owner() -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    for status in [401, 403] {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let addr = listener.local_addr()?;
        let response_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept client");
            let mut request = Vec::new();
            loop {
                let mut chunk = [0; 1024];
                let read = stream.read(&mut chunk).await.expect("read request");
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let request = String::from_utf8_lossy(&request);
            assert!(
                request
                    .to_ascii_lowercase()
                    .contains("authorization: bearer owner-token")
            );
            let reason = if status == 401 {
                "Unauthorized"
            } else {
                "Forbidden"
            };
            let response = format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("write refusal response");
        });
        let relay_url: RelayUrl = format!("http://{addr}").parse().expect("valid relay url");
        let secret = SecretKey::from_bytes(&rand::rng().random());
        let endpoint_key = *secret.public().as_bytes();
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = calls.clone();
        let (_tx, rx) = tokio::sync::watch::channel(Some("owner-token".to_owned()));
        let owner = relay_token_source::register(
            relay_url.clone(),
            endpoint_key,
            rx,
            Some(Arc::new(move || {
                counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            })),
        );
        let map = iroh_relay::RelayMap::from(
            ClientRelayConfig::from(relay_url.clone()).with_registration_owner(owner),
        );
        map.require_registration();
        let (_, binding) = map.get_with_registration(&relay_url);
        let tls = CaTlsConfig::default()
            .client_config(default_provider())
            .expect("valid client config");
        let result = ClientBuilder::new(relay_url, secret, DnsResolver::new())
            .tls_client_config(tls)
            .registration_binding(binding)
            .auth_token("stale-static")
            .connect()
            .await;
        assert!(
            matches!(result, Err(ConnectError::UnexpectedUpgradeStatus { code, .. }) if code.as_u16() == status),
            "expected HTTP {status} refusal, got {result:?}"
        );
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        response_task.await.expect("HTTP refusal server task");
    }
    Ok(())
}
