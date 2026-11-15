//! Strict path confinement tests (Xross fork).
//!
//! Each test reads [`PathPolicy::stats`], which counts datagrams actually handed to a
//! concrete transport or to QUIC after the policy check, plus an outside witness where one
//! exists (a trap socket, the relay server, the remote's candidate set). The comment on each
//! test names the guard whose removal must make it fail.

use std::{net::SocketAddr, time::Duration};

use iroh_base::{EndpointAddr, TransportAddr};
use iroh_relay::tls::CaTlsConfig;
use n0_error::{Result, StdResultExt};
use n0_future::{StreamExt, time};
use n0_tracing_test::traced_test;
use tokio::task::JoinHandle;
use tracing::info;

use super::{BindError, ConnectWithOptsError, Connection, Endpoint, presets};
use crate::{
    RelayMap, RelayMode,
    endpoint::{PathClasses, PathPolicy, PathPolicyError, PathPolicyStats},
    test_utils::run_relay_server,
};

const ALPN: &[u8] = b"xross/strict-seam/test";
const DIRECT: usize = 0;
const RELAY: usize = 1;

async fn endpoint(
    policy: PathPolicy,
    relay: Option<RelayMap>,
    ip: bool,
) -> Result<Endpoint, BindError> {
    let mut builder = Endpoint::builder(presets::Minimal)
        .alpns(vec![ALPN.to_vec()])
        .ca_tls_config(CaTlsConfig::insecure_skip_verify())
        .path_policy(policy);
    if let Some(map) = relay {
        builder = builder.relay_mode(RelayMode::Custom(map));
    }
    if !ip {
        builder = builder.clear_ip_transports();
    }
    builder.bind().await
}

/// Accepts connections and drains every uni stream; returns the number of bytes read.
fn sink(ep: Endpoint) -> JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(incoming) = ep.accept().await {
            let Ok(conn) = incoming.await else { continue };
            tokio::spawn(async move {
                while let Ok(mut recv) = conn.accept_uni().await {
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 4096];
                        while let Ok(Some(_)) = recv.read(&mut buf).await {}
                    });
                }
            });
        }
    })
}

/// Keeps writing to a uni stream on `conn` until aborted.
fn pump(conn: Connection) -> JoinHandle<()> {
    tokio::spawn(async move {
        let Ok(mut send) = conn.open_uni().await else {
            return;
        };
        loop {
            if send.write_all(&[7u8; 1200]).await.is_err() {
                return;
            }
            time::sleep(Duration::from_millis(10)).await;
        }
    })
}

async fn wait_for_path(conn: &Connection, ip: bool) -> Result {
    let mut paths = conn.paths_stream();
    time::timeout(Duration::from_secs(20), async {
        while let Some(list) = paths.next().await {
            if list
                .iter()
                .any(|p| if ip { p.is_ip() } else { p.is_relay() })
            {
                return;
            }
        }
    })
    .await
    .std_context("waiting for path")?;
    Ok(())
}

async fn relay_addr(ep: &Endpoint) -> EndpointAddr {
    ep.online().await;
    let mut addr = ep.addr();
    addr.addrs.retain(|a| a.is_relay());
    addr
}

async fn remote_has(
    ep: &Endpoint,
    remote: &EndpointAddr,
    f: impl Fn(&TransportAddr) -> bool,
) -> bool {
    ep.remote_info(remote.id)
        .await
        .map(|info| info.addrs().any(|a| f(a.addr())))
        .unwrap_or(false)
}

fn moved(before: &PathPolicyStats, after: &PathPolicyStats) -> Vec<&'static str> {
    let mut out = Vec::new();
    if before.sends_dispatched != after.sends_dispatched {
        out.push("sends_dispatched");
    }
    if before.recvs_delivered != after.recvs_delivered {
        out.push("recvs_delivered");
    }
    if before.path_opens != after.path_opens {
        out.push("path_opens");
    }
    out
}

/// Guards: bind refusal (N0-style IP sockets under a relay-only policy) and the candidate
/// filter (the trap address must not enter the remote's candidate set). The trap socket and
/// the DIRECT counters are the outside witness that nothing direct was attempted.
#[tokio::test]
#[traced_test]
async fn strict_relay_never_opens_direct() -> Result {
    let (relay_map, _url, _server) = run_relay_server().await?;
    let relay_only = || PathPolicy::strict(PathClasses::RELAY, 1).unwrap();

    // Default IP sockets are a direct-class transport: refused, not silently dropped.
    let err = endpoint(relay_only(), Some(relay_map.clone()), true)
        .await
        .expect_err("binding IP sockets under a relay-only policy must fail");
    assert!(
        matches!(err, BindError::PathPolicyViolation { .. }),
        "{err:?}"
    );

    let server = endpoint(relay_only(), Some(relay_map.clone()), false).await?;
    let client = endpoint(relay_only(), Some(relay_map.clone()), false).await?;
    assert!(client.bound_sockets().is_empty(), "no IP socket may exist");
    let _sink = sink(server.clone());

    // Hand the client the server's relay URL *and* a direct address that we watch.
    let trap = tokio::net::UdpSocket::bind("127.0.0.1:0").await.anyerr()?;
    let trap_addr: SocketAddr = trap.local_addr().anyerr()?;
    let mut dst = relay_addr(&server).await;
    dst.addrs.insert(TransportAddr::Ip(trap_addr));

    let conn = client.connect(dst.clone(), ALPN).await?;
    wait_for_path(&conn, false).await?;
    let pumping = pump(conn.clone());
    time::sleep(Duration::from_millis(1500)).await;
    pumping.abort();

    let mut buf = [0u8; 64];
    let trapped = time::timeout(Duration::from_millis(300), trap.recv_from(&mut buf)).await;
    assert!(trapped.is_err(), "a datagram reached the trap: {trapped:?}");
    assert!(
        !remote_has(&client, &dst, |a| a.is_ip()).await,
        "a direct candidate entered the remote's candidate set"
    );
    for ep in [&client, &server] {
        let s = ep.path_policy().stats();
        info!(?s, "relay-only stats");
        assert_eq!(s.sends_dispatched[DIRECT], 0);
        assert_eq!(s.recvs_delivered[DIRECT], 0);
        assert_eq!(s.path_opens[DIRECT], 0);
        assert!(s.sends_dispatched[RELAY] > 0);
    }
    assert!(client.path_policy().stats().candidates_denied[DIRECT] >= 1);

    conn.close(0u32.into(), b"done");
    client.close().await;
    server.close().await;
    Ok(())
}

/// Guards: bind refusal (a relay transport under a direct-only policy) and the candidate
/// filter (the relay URL must not enter the candidate set). The relay counters and the
/// published address are the witness that nothing relay-class was attempted.
#[tokio::test]
#[traced_test]
async fn strict_direct_never_opens_relay() -> Result {
    let (relay_map, relay_url, _server) = run_relay_server().await?;
    let direct_only = || PathPolicy::strict(PathClasses::DIRECT, 1).unwrap();

    let err = endpoint(direct_only(), Some(relay_map.clone()), true)
        .await
        .expect_err("a relay transport under a direct-only policy must fail");
    assert!(
        matches!(err, BindError::PathPolicyViolation { .. }),
        "{err:?}"
    );

    let server = endpoint(direct_only(), None, true).await?;
    let client = endpoint(direct_only(), None, true).await?;
    let _sink = sink(server.clone());

    let mut dst = EndpointAddr::new(server.id());
    for sock in server.bound_sockets() {
        let ip = if sock.ip().is_unspecified() {
            if sock.is_ipv4() {
                std::net::Ipv4Addr::LOCALHOST.into()
            } else {
                std::net::Ipv6Addr::LOCALHOST.into()
            }
        } else {
            sock.ip()
        };
        dst.addrs
            .insert(TransportAddr::Ip(SocketAddr::new(ip, sock.port())));
    }
    dst.addrs.insert(TransportAddr::Relay(relay_url.clone()));

    let conn = client.connect(dst.clone(), ALPN).await?;
    wait_for_path(&conn, true).await?;
    let pumping = pump(conn.clone());
    time::sleep(Duration::from_millis(1500)).await;
    pumping.abort();

    assert!(
        !remote_has(&client, &dst, |a| a.is_relay()).await,
        "a relay candidate entered the remote's candidate set"
    );
    assert!(
        !server.addr().addrs.iter().any(|a| a.is_relay()),
        "a relay address is advertised"
    );
    for ep in [&client, &server] {
        let s = ep.path_policy().stats();
        info!(?s, "direct-only stats");
        assert_eq!(s.sends_dispatched[RELAY], 0);
        assert_eq!(s.recvs_delivered[RELAY], 0);
        assert_eq!(s.path_opens[RELAY], 0);
        assert!(s.sends_dispatched[DIRECT] > 0);
    }
    assert!(client.path_policy().stats().candidates_denied[RELAY] >= 1);

    conn.close(0u32.into(), b"done");
    client.close().await;
    server.close().await;
    Ok(())
}

/// Guards: the send gate (dispatch must stop) and the receive gate (delivery must stop) on
/// the fenced endpoint, for a cached connection that keeps writing and for a dial racing the
/// fence. New dials are refused outright.
#[tokio::test]
#[traced_test]
async fn strict_transition_fences_cached_and_racing_dials() -> Result {
    let (relay_map, _url, _server) = run_relay_server().await?;
    let server = endpoint(PathPolicy::permissive(), Some(relay_map.clone()), true).await?;
    let client = endpoint(PathPolicy::permissive(), Some(relay_map.clone()), true).await?;
    let second = endpoint(PathPolicy::permissive(), Some(relay_map.clone()), true).await?;
    let _sink = sink(server.clone());
    let _sink2 = sink(second.clone());

    let dst = relay_addr(&server).await;
    let conn = client.connect(dst.clone(), ALPN).await?;
    wait_for_path(&conn, true).await?;
    let pumping = pump(conn.clone());
    time::sleep(Duration::from_millis(300)).await;

    // A dial that races the fence.
    let dst2 = relay_addr(&second).await;
    let racing = {
        let client = client.clone();
        tokio::spawn(async move {
            time::timeout(Duration::from_secs(5), client.connect(dst2, ALPN)).await
        })
    };
    tokio::task::yield_now().await;

    let epoch = client.path_policy().snapshot().epoch;
    client.path_policy().fence(epoch + 1).unwrap();
    // Let datagrams already past the gate on other threads finish.
    time::sleep(Duration::from_millis(200)).await;
    let before = client.path_policy().stats();
    time::sleep(Duration::from_secs(2)).await;
    let after = client.path_policy().stats();
    info!(?before, ?after, "fenced client");
    assert_eq!(
        moved(&before, &after),
        Vec::<&str>::new(),
        "traffic after fence"
    );
    assert!(
        after.sends_denied.iter().sum::<u64>() > before.sends_denied.iter().sum::<u64>(),
        "the cached connection kept trying and was refused"
    );

    let raced = racing.await.anyerr()?;
    assert!(
        !matches!(raced, Ok(Ok(_))),
        "a dial racing the fence produced a connection"
    );
    let err = client
        .connect(dst, ALPN)
        .await
        .expect_err("a fenced endpoint must refuse new dials");
    assert!(
        matches!(
            err,
            super::ConnectError::Connect {
                source: ConnectWithOptsError::PathPolicyFenced { .. },
                ..
            }
        ),
        "{err:?}"
    );

    pumping.abort();
    client.close().await;
    server.close().await;
    second.close().await;
    Ok(())
}

/// Guards: the send gate, the receive gate and the hole-punch guard after narrowing a live
/// direct connection to relay-only under a newer epoch. Stale epochs, epoch reuse and
/// widening are refused.
#[tokio::test]
#[traced_test]
async fn strict_stale_epoch_cannot_send() -> Result {
    let (relay_map, _url, _server) = run_relay_server().await?;
    let server = endpoint(PathPolicy::permissive(), Some(relay_map.clone()), true).await?;
    let client = endpoint(PathPolicy::permissive(), Some(relay_map.clone()), true).await?;
    let _sink = sink(server.clone());

    let dst = relay_addr(&server).await;
    let conn = client.connect(dst, ALPN).await?;
    wait_for_path(&conn, true).await?;
    let pumping = pump(conn.clone());
    time::sleep(Duration::from_millis(300)).await;

    let old = client.path_policy().snapshot().epoch;
    for ep in [&client, &server] {
        ep.path_policy()
            .restrict(old + 1, PathClasses::RELAY)
            .unwrap();
    }
    let policy = client.path_policy();
    assert_eq!(
        policy.check_epoch(old),
        Err(PathPolicyError::Stale { current: old + 1 })
    );
    assert_eq!(
        policy.restrict(old + 1, PathClasses::RELAY),
        Err(PathPolicyError::EpochNotIncreasing { current: old + 1 })
    );
    assert_eq!(
        policy.restrict(old + 2, PathClasses::ALL),
        Err(PathPolicyError::Widening)
    );

    time::sleep(Duration::from_millis(200)).await;
    let before = [client.path_policy().stats(), server.path_policy().stats()];
    #[cfg(feature = "metrics")]
    let hp_before = client.metrics().socket.holepunch_attempts.get();
    // A major network change makes the actor try to hole-punch again.
    client.inner.force_network_change(true).await;
    time::sleep(Duration::from_secs(6)).await;
    let after = [client.path_policy().stats(), server.path_policy().stats()];
    info!(?before, ?after, "narrowed to relay");
    for (b, a) in before.iter().zip(&after) {
        assert_eq!(
            b.sends_dispatched[DIRECT], a.sends_dispatched[DIRECT],
            "direct send"
        );
        assert_eq!(
            b.recvs_delivered[DIRECT], a.recvs_delivered[DIRECT],
            "direct recv"
        );
        assert_eq!(b.path_opens[DIRECT], a.path_opens[DIRECT], "direct open");
    }
    assert!(
        after[0].sends_denied[DIRECT] > before[0].sends_denied[DIRECT],
        "the stale direct path kept trying and was refused"
    );
    // Outside witness first: no hole-punching round actually started.
    #[cfg(feature = "metrics")]
    assert_eq!(
        client.metrics().socket.holepunch_attempts.get(),
        hp_before,
        "a hole-punching round ran after direct paths were refused"
    );
    assert!(after[0].holepunch_denied > before[0].holepunch_denied);

    pumping.abort();
    client.close().await;
    server.close().await;
    Ok(())
}
