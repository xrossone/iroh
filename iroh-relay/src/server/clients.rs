//! The "Server" side of the client. Uses the `ClientConnManager`.
// Based on tailscale/derp/derp_server.go

use std::{collections::HashSet, sync::Arc};

use dashmap::DashMap;
use iroh_base::EndpointId;
use n0_future::IterExt;
use tokio::sync::mpsc::error::TrySendError;
use tracing::{debug, trace};

use super::{
    ConnectionId, OnDisconnectGuard, RelayMetering,
    client::{Client, Config, ForwardPacketError},
};
use crate::{
    protos::{
        relay::{Datagrams, Status},
        streams::BytesStreamSink,
    },
    server::{client::SendError, metrics::Metrics},
};

/// Registry of connected relay clients.
///
/// This type manages the collection of active client connections and
/// handles routing messages between them.
#[derive(Debug, Clone, Default)]
pub struct Clients(Arc<Inner>);

#[derive(Debug, Default)]
struct Inner {
    /// The list of all currently connected clients.
    clients: DashMap<EndpointId, ClientState>,
    /// Map of which client has sent where
    sent_to: DashMap<EndpointId, HashSet<EndpointId>>,
    /// Observer for relayed traffic, per endpoint pair. `None` disables it and
    /// leaves the forwarding path exactly as it was.
    metering: Option<Arc<dyn RelayMetering>>,
}

impl Clients {
    /// A registry that reports every forwarded frame to `metering`.
    ///
    /// `Clients::default()` is the unmetered form and stays the cheap one: with
    /// `None` here the forwarding path costs one `Option` check per frame.
    pub fn with_metering(metering: Option<Arc<dyn RelayMetering>>) -> Self {
        Self(Arc::new(Inner {
            metering,
            ..Default::default()
        }))
    }
}

#[derive(Debug)]
struct ClientState {
    active: Client,
    inactive: Vec<Client>,
}

impl ClientState {
    async fn shutdown_all(mut self) {
        [self.active]
            .into_iter()
            .chain(self.inactive.drain(..))
            .map(Client::shutdown)
            .join_all()
            .await;
    }
}

impl Clients {
    /// Shuts down all connected clients.
    ///
    /// This method gracefully disconnects all active client connections managed by
    /// this registry. It will wait for all clients to complete their shutdown before
    /// returning.
    pub async fn shutdown(&self) {
        let keys: Vec<_> = self.0.clients.iter().map(|x| *x.key()).collect();
        trace!("shutting down {} clients", keys.len());
        let clients = keys.into_iter().filter_map(|k| self.0.clients.remove(&k));
        n0_future::join_all(clients.map(|(_, state)| state.shutdown_all())).await;
    }

    /// Builds the client handler and starts the read & write loops for the connection.
    ///
    /// Once the client disconnects, the [`OnDisconnectGuard`] set in `config` will be dropped,
    /// allowing callers to be notified of the disconnect.
    pub fn register<S>(&self, client_config: Config<S>, metrics: Arc<Metrics>)
    where
        S: BytesStreamSink + Send + 'static,
    {
        let endpoint_id = client_config.guard.endpoint_id;
        trace!(remote_endpoint = %endpoint_id.fmt_short(), "registering client");

        let client = Client::new(client_config, self, metrics.clone());
        match self.0.clients.entry(endpoint_id) {
            dashmap::Entry::Occupied(mut entry) => {
                let state = entry.get_mut();
                let old_client = std::mem::replace(&mut state.active, client);
                debug!(
                    remote_endpoint = %endpoint_id.fmt_short(),
                    "multiple connections found, deactivating old connection",
                );
                old_client
                    .try_send_health(Status::SameEndpointIdConnected)
                    .ok();
                state.inactive.push(old_client);
                metrics.clients_inactive_added.inc();
            }
            dashmap::Entry::Vacant(entry) => {
                entry.insert(ClientState {
                    active: client,
                    inactive: Vec::new(),
                });
            }
        }
    }

    /// Removes the client from the map of clients, & sends a notification
    /// to each client that peers has sent data to, to let them know that
    /// peer is gone from the network.
    ///
    /// Must be passed a matching connection_id.
    pub(super) fn unregister(&self, guard: OnDisconnectGuard, metrics: &Metrics) {
        let endpoint_id = guard.endpoint_id;
        let connection_id = guard.connection_id;
        trace!(
            endpoint_id = %endpoint_id.fmt_short(),
            %connection_id, "unregistering client"
        );

        let mut notify_peers = None;

        self.0.clients.remove_if_mut(&endpoint_id, |_id, state| {
            if state.active.connection_id() == connection_id {
                // The unregistering client is the currently active client
                if let Some(last_inactive_client) = state.inactive.pop() {
                    metrics.clients_inactive_removed.inc();
                    // There is an inactive client, promote to active again.
                    state.active = last_inactive_client;
                    // Inform the old client that it is healthy again.
                    state.active.try_send_health(Status::Healthy).ok();
                    // Don't remove the entry from client map.
                    false
                } else {
                    // No inactive clients: collect sent_to set for peer-gone notifications.
                    notify_peers = self.0.sent_to.remove(&endpoint_id).map(|(_, peers)| peers);
                    // Remove entry from the client map.
                    true
                }
            } else {
                // The unregistering client is already inactive. Remove from the list of inactive clients.
                state
                    .inactive
                    .retain(|client| client.connection_id() != connection_id);
                metrics.clients_inactive_removed.inc();
                // Active client is unmodified: keep entry in map.
                false
            }
        });

        // Inform peers that this endpoint is gone.
        // Done outside the remove_if_mut closure to avoid DashMap deadlocks.
        if let Some(peers) = notify_peers {
            for peer_id in peers {
                if let Some(peer) = self.0.clients.get(&peer_id) {
                    match peer.active.try_send_peer_gone(endpoint_id) {
                        Ok(_) => {}
                        Err(TrySendError::Full(_)) => {
                            debug!(
                                dst = %peer_id.fmt_short(),
                                "client too busy to receive peer gone notification, dropping"
                            );
                        }
                        Err(TrySendError::Closed(_)) => {
                            debug!(
                                dst = %peer_id.fmt_short(),
                                "can no longer write to client, dropping peer gone notification"
                            );
                        }
                    }
                }
            }
        }
    }

    /// Disconnects connections registered for `endpoint_id`.
    ///
    /// With `Some(connection_id)`, disconnects only that connection (active or
    /// an inactive duplicate). With `None`, disconnects every connection for the
    /// endpoint. Returns `true` if a matching connection was found, or `false`
    /// otherwise.
    ///
    /// Shutdown happens asynchronously: each per-connection actor exits its run
    /// loop and unregisters itself after this call returns.
    pub fn disconnect(&self, endpoint_id: EndpointId, connection_id: Option<ConnectionId>) -> bool {
        let Some(state) = self.0.clients.get(&endpoint_id) else {
            return false;
        };
        let mut clients = state.inactive.iter().chain([&state.active]);
        if let Some(id) = connection_id {
            let Some(client) = clients.find(|c| c.connection_id() == id) else {
                return false;
            };
            client.start_shutdown();
        } else {
            for client in clients {
                client.start_shutdown();
            }
        }
        true
    }

    /// Attempt to send a packet to client with [`EndpointId`] `dst`.
    pub(super) fn send_packet(
        &self,
        dst: EndpointId,
        data: Datagrams,
        src: EndpointId,
        metrics: &Metrics,
    ) -> Result<(), ForwardPacketError> {
        let Some(client) = self.0.clients.get(&dst) else {
            debug!(dst = %dst.fmt_short(), "no connected client, dropped packet");
            metrics.send_packets_dropped.inc();
            return Ok(());
        };
        // Read before the move. This is the one place in the server where the
        // sender, the recipient and the payload size are all in hand at once,
        // which is why the metering hook lives here rather than at the two
        // per-connection byte counters in `client.rs` — neither of those knows
        // the endpoint at the *other* end.
        let relayed_bytes = data.contents.len();

        match client.active.try_send_packet(src, data) {
            Ok(_) => {
                // Record sent_to relationship
                self.0.sent_to.entry(src).or_default().insert(dst);
                // Only on success: a frame the relay dropped is a frame the
                // relay did not carry, and billing for it would charge a sender
                // for the recipient's backpressure.
                if let Some(metering) = &self.0.metering {
                    metering.on_relay(src, dst, relayed_bytes);
                }
                Ok(())
            }
            Err(TrySendError::Full(_)) => {
                debug!(
                    dst = %dst.fmt_short(),
                    "client too busy to receive packet, dropping packet"
                );
                Err(ForwardPacketError::new(SendError::Full))
            }
            Err(TrySendError::Closed(_)) => {
                debug!(
                    dst = %dst.fmt_short(),
                    "can no longer write to client, dropping message and pruning connection"
                );
                client.active.start_shutdown();
                Err(ForwardPacketError::new(SendError::Closed))
            }
        }
    }

    #[cfg(test)]
    fn active_connection_id(&self, endpoint_id: EndpointId) -> Option<ConnectionId> {
        self.0
            .clients
            .get(&endpoint_id)
            .map(|s| s.active.connection_id())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use iroh_base::SecretKey;
    use n0_error::{Result, StdResultExt};
    use n0_future::{Stream, StreamExt};
    use n0_tracing_test::traced_test;
    use rand::{RngExt, SeedableRng};

    use super::*;
    use crate::{
        client::conn::Conn,
        http::ProtocolVersion,
        protos::{common::FrameType, relay::RelayToClientMsg, streams::WsBytesFramed},
        server::streams::{MaybeTlsStream, RateLimited, ServerRelayedStream},
    };

    /// Records what a [`RelayMetering`] hook was told, for the tests below.
    #[derive(Debug, Default)]
    struct Recorder(std::sync::Mutex<Vec<(EndpointId, EndpointId, usize)>>);

    impl RelayMetering for Recorder {
        fn on_relay(&self, src: EndpointId, dst: EndpointId, bytes: usize) {
            self.0.lock().expect("not poisoned").push((src, dst, bytes));
        }
    }

    impl Recorder {
        fn calls(&self) -> Vec<(EndpointId, EndpointId, usize)> {
            self.0.lock().expect("not poisoned").clone()
        }
    }

    #[tokio::test]
    #[traced_test]
    async fn metering_reports_a_forwarded_frame_once_with_both_endpoints() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);
        let a_key = SecretKey::from_bytes(&rng.random()).public();
        let b_key = SecretKey::from_bytes(&rng.random()).public();

        let (a_builder, mut a_rw) = test_client_builder(a_key);
        let recorder = Arc::new(Recorder::default());
        let clients = Clients::with_metering(Some(recorder.clone()));
        let metrics = Arc::new(Metrics::default());
        clients.register(a_builder, metrics.clone());

        let data = b"hello world!";
        clients.send_packet(a_key, Datagrams::from(&data[..]), b_key, &metrics)?;
        recv_frame(FrameType::RelayToClientDatagram, &mut a_rw).await?;

        // `b` sent to `a`, and the size is the datagram contents -- not the
        // relay framing around them.
        assert_eq!(recorder.calls(), vec![(b_key, a_key, data.len())]);
        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn metering_says_nothing_about_a_frame_with_no_destination() -> Result {
        // Nobody is registered for `a_key`, so the frame is dropped. Reporting
        // it would bill a sender for traffic that never reached anyone -- and
        // the drop is already counted in `send_packets_dropped`.
        //
        // Note what this row does NOT cover: `send_packet` returns before the
        // metering point when the destination is absent, so moving the hook
        // ahead of the send would leave this green. That case is
        // `metering_counts_only_the_frames_the_queue_accepted`.
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(1u64);
        let a_key = SecretKey::from_bytes(&rng.random()).public();
        let b_key = SecretKey::from_bytes(&rng.random()).public();

        let recorder = Arc::new(Recorder::default());
        let clients = Clients::with_metering(Some(recorder.clone()));
        let metrics = Arc::new(Metrics::default());

        clients.send_packet(a_key, Datagrams::from(&b"dropped"[..]), b_key, &metrics)?;

        assert!(recorder.calls().is_empty());
        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn metering_counts_only_the_frames_the_queue_accepted() -> Result {
        // The row that actually pins the hook to the `Ok` arm. The destination
        // is registered but nobody reads its stream, so its send queue fills and
        // further frames are refused with `TrySendError::Full`. A hook placed
        // before the send would report every attempt and bill a sender for the
        // recipient's backpressure.
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(3u64);
        let a_key = SecretKey::from_bytes(&rng.random()).public();
        let b_key = SecretKey::from_bytes(&rng.random()).public();

        let (mut config, _a_rw) = test_client_builder(a_key);
        config.channel_capacity = 1;

        let recorder = Arc::new(Recorder::default());
        let clients = Clients::with_metering(Some(recorder.clone()));
        let metrics = Arc::new(Metrics::default());
        clients.register(config, metrics.clone());

        // `_a_rw` is never read, so the client actor stalls writing and the
        // queue stops draining. Send until one is refused, then keep going, so
        // the test does not depend on exactly where the boundary falls.
        let data = b"backpressure";
        let mut accepted = 0usize;
        let mut refused = 0usize;
        for _ in 0..256 {
            match clients.send_packet(a_key, Datagrams::from(&data[..]), b_key, &metrics) {
                Ok(()) => accepted += 1,
                Err(_) => refused += 1,
            }
        }

        assert!(
            refused > 0,
            "the queue never filled, so this test proved nothing"
        );
        assert_eq!(
            recorder.calls().len(),
            accepted,
            "the meter counted attempts rather than accepted frames"
        );
        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn an_unmetered_registry_still_forwards() -> Result {
        // `Clients::default()` is the unmetered form, and it is what every
        // existing embedder gets. This asserts the hook changed nothing when it
        // is absent.
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(2u64);
        let a_key = SecretKey::from_bytes(&rng.random()).public();
        let b_key = SecretKey::from_bytes(&rng.random()).public();

        let (a_builder, mut a_rw) = test_client_builder(a_key);
        let clients = Clients::default();
        let metrics = Arc::new(Metrics::default());
        clients.register(a_builder, metrics.clone());

        let data = b"hello world!";
        clients.send_packet(a_key, Datagrams::from(&data[..]), b_key, &metrics)?;
        let frame = recv_frame(FrameType::RelayToClientDatagram, &mut a_rw).await?;
        assert_eq!(
            frame,
            RelayToClientMsg::Datagrams {
                remote_endpoint_id: b_key,
                datagrams: data.to_vec().into(),
            }
        );
        Ok(())
    }

    async fn recv_frame<
        E: std::error::Error + Sync + Send + 'static,
        S: Stream<Item = Result<RelayToClientMsg, E>> + Unpin,
    >(
        frame_type: FrameType,
        mut stream: S,
    ) -> Result<RelayToClientMsg> {
        match stream.next().await {
            Some(Ok(frame)) => {
                if frame_type != frame.typ() {
                    n0_error::bail_any!(
                        "Unexpected frame, got {:?}, but expected {:?}",
                        frame.typ(),
                        frame_type
                    );
                }
                Ok(frame)
            }
            Some(Err(err)) => Err(err).anyerr(),
            None => n0_error::bail_any!("Unexpected EOF, expected frame {frame_type:?}"),
        }
    }

    fn test_client_builder(
        key: EndpointId,
    ) -> (Config<WsBytesFramed<RateLimited<MaybeTlsStream>>>, Conn) {
        let (server, client) = tokio::io::duplex(1024);
        let guard = OnDisconnectGuard::empty(key);
        let protocol_version = ProtocolVersion::default();
        let mut config = Config::new(guard, ServerRelayedStream::test(server), protocol_version);
        config.write_timeout = Duration::from_secs(1);
        config.channel_capacity = 10;
        (config, Conn::test(client, protocol_version))
    }

    #[tokio::test]
    #[traced_test]
    async fn test_clients() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);
        let a_key = SecretKey::from_bytes(&rng.random()).public();
        let b_key = SecretKey::from_bytes(&rng.random()).public();

        let (builder_a, mut a_rw) = test_client_builder(a_key);

        let clients = Clients::default();
        let metrics = Arc::new(Metrics::default());
        clients.register(builder_a, metrics.clone());

        // send packet
        let data = b"hello world!";
        clients.send_packet(a_key, Datagrams::from(&data[..]), b_key, &metrics)?;
        let frame = recv_frame(FrameType::RelayToClientDatagram, &mut a_rw).await?;
        assert_eq!(
            frame,
            RelayToClientMsg::Datagrams {
                remote_endpoint_id: b_key,
                datagrams: data.to_vec().into(),
            }
        );

        {
            let client = clients.0.clients.get(&a_key).unwrap();
            // shutdown client a, this should trigger the removal from the clients list
            client.active.start_shutdown();
        }

        // need to wait a moment for the removal to be processed
        let c = clients.clone();
        tokio::time::timeout(Duration::from_secs(1), async move {
            loop {
                if !c.0.clients.contains_key(&a_key) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .std_context("timeout")?;
        clients.shutdown().await;

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn test_clients_same_endpoint_id() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);
        let a_key = SecretKey::from_bytes(&rng.random()).public();
        let b_key = SecretKey::from_bytes(&rng.random()).public();

        let (a1_builder, mut a1_rw) = test_client_builder(a_key);

        let clients = Clients::default();
        let metrics = Arc::new(Metrics::default());

        // register client a
        clients.register(a1_builder, metrics.clone());
        let a1_conn_id = clients.active_connection_id(a_key).unwrap();

        // send packet and verify it is send to a1
        let data = b"hello world!";
        clients.send_packet(a_key, Datagrams::from(&data[..]), b_key, &metrics)?;
        let frame = recv_frame(FrameType::RelayToClientDatagram, &mut a1_rw).await?;
        assert_eq!(
            frame,
            RelayToClientMsg::Datagrams {
                remote_endpoint_id: b_key,
                datagrams: data.to_vec().into(),
            }
        );

        // register new client with same endpoint id
        let (a2_builder, mut a2_rw) = test_client_builder(a_key);
        clients.register(a2_builder, metrics.clone());
        let a2_conn_id = clients.active_connection_id(a_key).unwrap();
        assert!(a2_conn_id != a1_conn_id);

        // a1 is marked inactive and should receive a health frame
        let frame = recv_frame(FrameType::Status, &mut a1_rw).await?;
        assert_eq!(
            frame,
            RelayToClientMsg::Status(Status::SameEndpointIdConnected)
        );

        // send packet and verify it is send to a2
        clients.send_packet(a_key, Datagrams::from(&data[..]), b_key, &metrics)?;
        let frame = recv_frame(FrameType::RelayToClientDatagram, &mut a2_rw).await?;
        assert_eq!(
            frame,
            RelayToClientMsg::Datagrams {
                remote_endpoint_id: b_key,
                datagrams: data.to_vec().into(),
            }
        );

        // disconnect a2
        clients
            .0
            .clients
            .get(&a_key)
            .unwrap()
            .active
            .start_shutdown();

        // need to wait a moment for the removal to be processed
        tokio::time::timeout(Duration::from_secs(1), {
            let clients = clients.clone();
            async move {
                // wait until the active connection is no longer a2 (which we unregistered)
                while clients.active_connection_id(a_key) == Some(a2_conn_id) {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        })
        .await
        .std_context("timeout")?;

        // a1 should be marked active again now
        assert_eq!(clients.active_connection_id(a_key), Some(a1_conn_id));

        // a1 is marked active again and should receive a health frame
        let frame = recv_frame(FrameType::Status, &mut a1_rw).await?;
        assert_eq!(frame, RelayToClientMsg::Status(Status::Healthy));

        // a1 should receive packets
        clients.send_packet(a_key, Datagrams::from(&data[..]), b_key, &metrics)?;
        let frame = recv_frame(FrameType::RelayToClientDatagram, &mut a1_rw).await?;
        assert_eq!(
            frame,
            RelayToClientMsg::Datagrams {
                remote_endpoint_id: b_key,
                datagrams: data.to_vec().into(),
            }
        );

        // after shutting down the now-active client, there should no longer be an entry for that endpoint id
        clients
            .0
            .clients
            .get(&a_key)
            .unwrap()
            .active
            .start_shutdown();

        // need to wait a moment for the removal to be processed
        tokio::time::timeout(Duration::from_secs(1), {
            let clients = clients.clone();
            async move {
                // wait until the active connection is no longer a2 (which we unregistered)
                while clients.0.clients.contains_key(&a_key) {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        })
        .await
        .std_context("timeout")?;

        clients.shutdown().await;

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn test_peer_gone_notification() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);
        let a_key = SecretKey::from_bytes(&rng.random()).public();
        let b_key = SecretKey::from_bytes(&rng.random()).public();

        let clients = Clients::default();
        let metrics = Arc::new(Metrics::default());

        // Register both clients
        let (builder_a, _a_rw) = test_client_builder(a_key);
        let (builder_b, mut b_rw) = test_client_builder(b_key);
        clients.register(builder_a, metrics.clone());
        clients.register(builder_b, metrics.clone());

        // A sends a packet to B (records sent_to[A] = {B})
        let data = b"hello b!";
        clients.send_packet(b_key, Datagrams::from(&data[..]), a_key, &metrics)?;

        // B receives the packet
        let frame = recv_frame(FrameType::RelayToClientDatagram, &mut b_rw).await?;
        assert_eq!(
            frame,
            RelayToClientMsg::Datagrams {
                remote_endpoint_id: a_key,
                datagrams: data.to_vec().into(),
            }
        );

        // Disconnect A
        {
            let client = clients.0.clients.get(&a_key).unwrap();
            client.active.start_shutdown();
        }

        // Wait for A to unregister
        tokio::time::timeout(Duration::from_secs(1), {
            let clients = clients.clone();
            async move {
                while clients.0.clients.contains_key(&a_key) {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        })
        .await
        .std_context("timeout waiting for A to unregister")?;

        // B should receive EndpointGone(a_key): notifying B that A is gone
        let frame = recv_frame(FrameType::EndpointGone, &mut b_rw).await?;
        assert_eq!(frame, RelayToClientMsg::EndpointGone(a_key));

        clients.shutdown().await;
        Ok(())
    }
}
