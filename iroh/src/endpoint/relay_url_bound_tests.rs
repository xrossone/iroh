//! Relay URL length bound at the endpoint's own ingress points (Xross fork).
//!
//! Every relay URL that reaches an endpoint either comes from a string or serde ingress,
//! which [`iroh_base::RelayUrl`] bounds itself, or from the infallible `From<Url>`
//! conversion. These tests cover the latter at each point where the endpoint accepts a
//! relay URL: dialing a remote address, the configured relay map at bind time, and runtime
//! relay map inserts. Each test names the guard whose removal makes it fail.

use std::sync::Arc;

use iroh_base::{EndpointAddr, MAX_RELAY_URL_LEN, RelayUrl, SecretKey, TransportAddr};
use iroh_relay::RelayConfig;
use n0_error::Result;

use super::{BindError, ConnectWithOptsError, Endpoint, presets};
use crate::{RelayMap, RelayMode};

const ALPN: &[u8] = b"xross/relay-url-bound/test";

fn url_of_len(len: usize) -> RelayUrl {
    let prefix = "https://r.example/";
    let s = format!("{prefix}{}", "a".repeat(len - prefix.len()));
    RelayUrl::from(url::Url::parse(&s).expect("valid url"))
}

async fn endpoint() -> Endpoint {
    Endpoint::builder(presets::Minimal)
        .alpns(vec![ALPN.to_vec()])
        .bind()
        .await
        .expect("bind")
}

/// Guard: the relay URL check at the top of `Endpoint::connect_with_opts`. Without it the
/// dial spawns a remote state actor (visible through `remote_info`) holding the URL.
#[tokio::test]
async fn connect_refuses_overlong_relay_url_before_remote_state() -> Result {
    let ep = endpoint().await;
    let remote = SecretKey::from_bytes(&[7; 32]).public();
    let addr = EndpointAddr::from_parts(
        remote,
        [TransportAddr::Relay(url_of_len(MAX_RELAY_URL_LEN + 1))],
    );

    let res = ep.connect_with_opts(addr, ALPN, Default::default()).await;
    assert!(
        matches!(res, Err(ConnectWithOptsError::RelayUrlTooLong { .. })),
        "{:?}",
        res.err()
    );
    assert!(
        ep.remote_info(remote).await.is_none(),
        "no remote state may exist for a refused address"
    );
    ep.close().await;
    Ok(())
}

/// The limit is inclusive: a URL of exactly `MAX_RELAY_URL_LEN` bytes is still dialable.
#[tokio::test]
async fn connect_accepts_relay_url_at_limit() -> Result {
    let ep = endpoint().await;
    let remote = SecretKey::from_bytes(&[8; 32]).public();
    let addr = EndpointAddr::from_parts(
        remote,
        [TransportAddr::Relay(url_of_len(MAX_RELAY_URL_LEN))],
    );
    let res = ep.connect_with_opts(addr, ALPN, Default::default()).await;
    assert!(
        !matches!(res, Err(ConnectWithOptsError::RelayUrlTooLong { .. })),
        "{:?}",
        res.err()
    );
    ep.close().await;
    Ok(())
}

/// Guard: the configured relay map check in `EndpointInner::bind`. Without it the endpoint
/// binds and starts a relay actor and net-report probes for the URL.
#[tokio::test]
async fn bind_refuses_overlong_configured_relay_url() {
    let map = RelayMap::from(url_of_len(MAX_RELAY_URL_LEN + 1));
    let res = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Custom(map))
        .bind()
        .await;
    assert!(
        matches!(res, Err(BindError::RelayUrlTooLong { .. })),
        "{:?}",
        res.err()
    );
}

/// Guard: `RelayMap::insert` refusing overlong URLs. Without it the URL enters the live
/// relay map, from which the relay actor and net report pick relays to connect to.
#[tokio::test]
async fn insert_relay_refuses_overlong_relay_url() -> Result {
    let ep = endpoint().await;
    let long = url_of_len(MAX_RELAY_URL_LEN + 1);
    let config = Arc::new(RelayConfig::from(long.clone()));
    assert!(ep.insert_relay(long.clone(), config).await.is_none());
    assert!(
        ep.remove_relay(&long).await.is_none(),
        "the refused URL must not be in the relay map"
    );
    ep.close().await;
    Ok(())
}
