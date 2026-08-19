// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Node-side Ponor session state.
//!
//! This is deliberately sans-I/O: TCP/TLS/HTTP upgrade belongs to the daemon
//! transport, while this type makes it impossible to forward a PHREATIC or
//! AVEN datagram before the relay's pinned ML-DSA identity has authenticated.

use karst_relay_proto::consts::{
    ENDPOINT_LEN, FRAME_HEADER, FRAME_PAYLOAD_MAX, ID_LEN, REFLECT_KEY_LEN,
};
use karst_relay_proto::{frame, ClientHandshake, Frame, Role, Signer, Verifier};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

use crate::netmap::Relay;

/// A fully pinned node-to-relay Ponor conversation.
#[derive(Debug)]
pub struct Session {
    handshake: ClientHandshake,
    /// `ClientHandshake` intentionally keeps its internal state private. Keep
    /// the small amount the transport needs here so receiving a packet before
    /// `RelayAuth` is not an operation a caller can express.
    awaiting_auth: bool,
}

/// One consequence of an authenticated relay frame.
#[derive(Debug, PartialEq, Eq)]
pub enum Event {
    /// Bytes the client must write to complete the Ponor handshake.
    Send(Vec<u8>),
    /// A relay-stamped packet from an admitted node.
    Packet {
        /// The Ponor node id the relay authenticated as the source.
        source_id: [u8; ID_LEN],
        /// The opaque PHREATIC or AVEN datagram.
        payload: Vec<u8>,
    },
    /// This relay runs an AVEN reflector — `ponor-v1.md` §7.7.
    ///
    /// Only ever produced **after** the relay's ML-DSA-65 signature has
    /// verified, which is the whole security argument for the key it carries:
    /// it comes from the identity the netmap pinned, not from whoever answered
    /// the TCP connection.
    Reflector {
        /// The §5.3 reflect key, live for this connection only.
        key: [u8; REFLECT_KEY_LEN],
        /// Where to send `Reflect`. Undecoded here — `karst-disco` owns
        /// `aven-v1.md` §6.2 and this module owns Ponor framing.
        endpoint: [u8; ENDPOINT_LEN],
    },
}

/// Incremental, bounded decoder for one node-to-relay connection.
///
/// The TCP/TLS driver feeds this with each read. It owns the partial-frame
/// buffer, while [`Session`] owns authentication state, so a packet split over
/// reads cannot be mistaken for a packet that was authenticated on a prior
/// connection. A complete Ponor frame is at most `FRAME_HEADER` plus
/// `FRAME_PAYLOAD_MAX`; the additional 8 KiB allows one ordinary read to
/// overshoot that boundary without granting an unauthenticated peer an
/// unbounded allocation.
#[derive(Debug)]
pub struct Decoder {
    session: Session,
    buffer: Vec<u8>,
}

/// Maximum buffered input while awaiting a complete Ponor frame.
const BUFFER_MAX: usize = FRAME_HEADER + FRAME_PAYLOAD_MAX + 8192;

impl Decoder {
    /// Start a bounded decoder for a freshly configured relay.
    #[must_use]
    pub fn new(session: Session) -> Self {
        Self {
            session,
            buffer: Vec::with_capacity(FRAME_HEADER + FRAME_PAYLOAD_MAX),
        }
    }

    /// Feed bytes from one ordered TLS connection and return all consequences.
    ///
    /// # Errors
    /// Returns a protocol error for an oversized, malformed, or out-of-order
    /// frame. The caller must close that connection rather than attempting to
    /// resynchronise an authenticated byte stream after a framing failure.
    pub fn push(
        &mut self,
        bytes: &[u8],
        signer: &impl Signer,
        verifier: &impl Verifier,
    ) -> Result<Vec<Event>, karst_relay_proto::Error> {
        if self.buffer.len().saturating_add(bytes.len()) > BUFFER_MAX {
            return Err(karst_relay_proto::Error::FrameTooLarge(
                self.buffer.len().saturating_add(bytes.len()),
            ));
        }
        self.buffer.extend_from_slice(bytes);

        let mut events = Vec::new();
        loop {
            let decoded = frame::decode(&self.buffer)?;
            let Some((frame, used)) = decoded else {
                break;
            };
            let event = self.session.on_frame(&frame, signer, verifier)?;
            self.buffer.drain(..used);
            if let Some(event) = event {
                events.push(event);
            }
        }
        Ok(events)
    }

    /// Whether the pinned relay completed its Ponor authentication.
    #[must_use]
    pub fn established(&self) -> bool {
        self.session.established()
    }

    /// Encode an opaque packet for a destination after authentication.
    #[must_use]
    pub fn send_packet(&self, destination: [u8; ID_LEN], payload: &[u8]) -> Option<Vec<u8>> {
        self.session.send_packet(destination, payload)
    }
}

/// A connected, TLS-protected Ponor client.
///
/// Its construction performs the whole HTTP and Ponor handshake. Consequently
/// [`Self::send_packet`] and [`Self::receive`] cannot touch a relay stream that
/// has not authenticated its registry-pinned ML-DSA identity.
pub struct Connection {
    tls: TlsStream<TcpStream>,
    decoder: Decoder,
    /// Events read past the end of the handshake — see
    /// [`write_handshake_events`].
    deferred: Vec<Event>,
}

impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection")
            .field("established", &self.decoder.established())
            .finish_non_exhaustive()
    }
}

/// Failure while connecting to a relay.
#[derive(Debug)]
pub enum ConnectError {
    /// Socket I/O or the HTTP upgrade failed.
    Io(std::io::Error),
    /// TLS could not establish a validated connection.
    Tls(rustls::Error),
    /// The relay did not return the required HTTP upgrade response.
    Upgrade,
    /// TLS setup or Ponor framing/authentication failed.
    Protocol(String),
}

impl std::fmt::Display for ConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "relay connection: {error}"),
            Self::Tls(error) => write!(f, "relay TLS: {error}"),
            Self::Upgrade => f.write_str("relay did not accept the Ponor HTTP upgrade"),
            Self::Protocol(error) => write!(f, "relay protocol: {error}"),
        }
    }
}

impl std::error::Error for ConnectError {}

const UPGRADE_MAX: usize = 4096;
const UPGRADE: &[u8] =
    b"GET /ponor HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: ponor\r\nPonor-Version: 1\r\n\r\n";

impl Connection {
    /// Connect, validate TLS, upgrade HTTP, and authenticate the pinned relay.
    ///
    /// # Errors
    /// Any TCP, TLS, HTTP, framing, or Ponor authentication failure. The caller
    /// must discard the connection and may retry with exponential backoff.
    pub async fn connect(
        session: Session,
        signer: &impl Signer,
        verifier: &impl Verifier,
        tls: std::sync::Arc<rustls::ClientConfig>,
        relay: &Relay,
    ) -> Result<Self, ConnectError> {
        let stream = TcpStream::connect(&relay.address)
            .await
            .map_err(ConnectError::Io)?;
        let _ = stream.set_nodelay(true);
        let name = crate::relay_tls::server_name(relay)
            .map_err(|error| ConnectError::Protocol(error.to_string()))?;
        let connector = tokio_rustls::TlsConnector::from(tls);
        let mut tls = connector
            .connect(name, stream)
            .await
            .map_err(ConnectError::Io)?;
        tls.write_all(UPGRADE).await.map_err(ConnectError::Io)?;
        tls.flush().await.map_err(ConnectError::Io)?;

        let mut head = Vec::with_capacity(256);
        read_upgrade(&mut tls, &mut head).await?;
        let head_len = upgrade_head_len(&head).ok_or(ConnectError::Upgrade)?;
        if !head
            .get(..head_len)
            .is_some_and(|response| response.starts_with(b"HTTP/1.1 101 "))
        {
            return Err(ConnectError::Upgrade);
        }

        let mut decoder = Decoder::new(session);
        let tail = head.get(head_len..).ok_or(ConnectError::Upgrade)?;
        let events = decoder
            .push(tail, signer, verifier)
            .map_err(|error| ConnectError::Protocol(error.to_string()))?;
        let deferred = write_handshake_events(&mut tls, events).await?;
        let mut connection = Self {
            tls,
            decoder,
            deferred,
        };
        while !connection.decoder.established() {
            let events = connection.read_events(signer, verifier).await?;
            let more = write_handshake_events(&mut connection.tls, events).await?;
            connection.deferred.extend(more);
        }
        Ok(connection)
    }

    /// Read relay packets that arrived on this authenticated connection.
    ///
    /// # Errors
    /// Returns an error when the TLS stream closes, I/O fails, or the relay
    /// sends malformed Ponor framing.
    pub async fn receive(
        &mut self,
        signer: &impl Signer,
        verifier: &impl Verifier,
    ) -> Result<Vec<Event>, ConnectError> {
        if !self.deferred.is_empty() {
            return Ok(std::mem::take(&mut self.deferred));
        }
        self.read_events(signer, verifier).await
    }

    /// Forward one opaque PHREATIC or AVEN datagram through this relay.
    ///
    /// # Errors
    /// Returns I/O failure if the established TLS stream cannot accept bytes.
    pub async fn send_packet(
        &mut self,
        destination: [u8; ID_LEN],
        payload: &[u8],
    ) -> Result<(), ConnectError> {
        let bytes = self
            .decoder
            .send_packet(destination, payload)
            .ok_or_else(|| {
                ConnectError::Protocol("packet before relay authentication".to_owned())
            })?;
        self.tls.write_all(&bytes).await.map_err(ConnectError::Io)
    }

    /// Split an established connection so sends and receives proceed
    /// independently.
    ///
    /// **The two halves cannot share a task.** A worker that alternated between
    /// reading and draining a send queue would add its polling interval to every
    /// relayed packet's latency in one direction and stall reads behind a slow
    /// write in the other. Once the relay path carries tunnel data rather than
    /// just rendezvous messages, that interval is the tunnel's latency.
    ///
    /// Consumes an established `Connection`, so a [`Sender`] cannot exist for a
    /// relay that has not authenticated — the property [`Session::send_packet`]
    /// enforces per call, hoisted into the type once the handshake is over.
    #[must_use]
    pub fn split(self) -> Option<(Sender, Receiver)> {
        if !self.decoder.established() {
            return None;
        }
        let (read, write) = tokio::io::split(self.tls);
        Some((
            Sender { tls: write },
            Receiver {
                tls: read,
                decoder: self.decoder,
                // Carried across the split rather than returned separately: a
                // caller that had to remember to drain it would be a caller
                // that could forget, and the symptom of forgetting is a node
                // with no reflector and no error.
                deferred: self.deferred,
            },
        ))
    }

    async fn read_events(
        &mut self,
        signer: &impl Signer,
        verifier: &impl Verifier,
    ) -> Result<Vec<Event>, ConnectError> {
        let mut bytes = [0u8; 8192];
        let read = self.tls.read(&mut bytes).await.map_err(ConnectError::Io)?;
        if read == 0 {
            return Err(ConnectError::Protocol(
                "relay closed the connection".to_owned(),
            ));
        }
        self.decoder
            .push(
                bytes
                    .get(..read)
                    .ok_or_else(|| ConnectError::Protocol("invalid TLS read length".to_owned()))?,
                signer,
                verifier,
            )
            .map_err(|error| ConnectError::Protocol(error.to_string()))
    }
}

/// The send half of an established relay connection.
///
/// Its existence is the proof the relay authenticated: it is reachable only
/// through [`Connection::split`], which refuses an unestablished connection.
#[derive(Debug)]
pub struct Sender {
    tls: tokio::io::WriteHalf<TlsStream<TcpStream>>,
}

impl Sender {
    /// Forward one opaque PHREATIC or AVEN datagram through this relay.
    ///
    /// # Errors
    /// Returns I/O failure if the TLS stream cannot accept bytes, and
    /// [`ConnectError::Protocol`] for a payload outside the frame's bounds —
    /// which is a caller error rather than a network one, since
    /// `consts::PAYLOAD_MAX` is sized to hold the largest datagram PHREATIC
    /// emits.
    pub async fn send_packet(
        &mut self,
        destination: [u8; ID_LEN],
        payload: &[u8],
    ) -> Result<(), ConnectError> {
        if payload.is_empty() || payload.len() > FRAME_PAYLOAD_MAX {
            return Err(ConnectError::Protocol(format!(
                "relayed payload is {} bytes",
                payload.len()
            )));
        }
        let bytes = Frame::SendPacket {
            dst_id: destination,
            payload,
        }
        .to_vec();
        self.tls.write_all(&bytes).await.map_err(ConnectError::Io)
    }

    /// Flush whatever the last sends buffered.
    ///
    /// # Errors
    /// I/O failure on the TLS stream.
    pub async fn flush(&mut self) -> Result<(), ConnectError> {
        self.tls.flush().await.map_err(ConnectError::Io)
    }
}

/// The receive half of an established relay connection.
#[derive(Debug)]
pub struct Receiver {
    tls: tokio::io::ReadHalf<TlsStream<TcpStream>>,
    decoder: Decoder,
    /// Events the handshake read past — a `ReflectOffer` coalesced with
    /// `RelayAuth`. Delivered by the first [`Receiver::receive`], before it
    /// blocks on the socket.
    deferred: Vec<Event>,
}

impl Receiver {
    /// Read whatever the relay has forwarded.
    ///
    /// # Errors
    /// Returns an error when the TLS stream closes, I/O fails, or the relay
    /// sends malformed Ponor framing. A framing failure must close the
    /// connection: an authenticated byte stream cannot be resynchronised.
    pub async fn receive(
        &mut self,
        signer: &impl Signer,
        verifier: &impl Verifier,
    ) -> Result<Vec<Event>, ConnectError> {
        // Before the socket, or a reflector offered during the handshake waits
        // for the next frame the relay happens to send — which on an idle
        // connection is thirty seconds away.
        if !self.deferred.is_empty() {
            return Ok(std::mem::take(&mut self.deferred));
        }
        let mut bytes = [0u8; 8192];
        let read = self.tls.read(&mut bytes).await.map_err(ConnectError::Io)?;
        if read == 0 {
            return Err(ConnectError::Protocol(
                "relay closed the connection".to_owned(),
            ));
        }
        self.decoder
            .push(
                bytes
                    .get(..read)
                    .ok_or_else(|| ConnectError::Protocol("invalid TLS read length".to_owned()))?,
                signer,
                verifier,
            )
            .map_err(|error| ConnectError::Protocol(error.to_string()))
    }
}

async fn read_upgrade(
    tls: &mut TlsStream<TcpStream>,
    buffer: &mut Vec<u8>,
) -> Result<(), ConnectError> {
    let mut chunk = [0u8; 1024];
    while upgrade_head_len(buffer).is_none() {
        let read = tls.read(&mut chunk).await.map_err(ConnectError::Io)?;
        if read == 0 {
            return Err(ConnectError::Upgrade);
        }
        let bytes = chunk.get(..read).ok_or(ConnectError::Upgrade)?;
        buffer.extend_from_slice(bytes);
        if buffer.len() > UPGRADE_MAX {
            return Err(ConnectError::Upgrade);
        }
    }
    Ok(())
}

fn upgrade_head_len(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|offset| offset.saturating_add(4))
}

/// Write the handshake's replies and hand back anything that outlives it.
///
/// **`ReflectOffer` routinely arrives in the same TCP segment as `RelayAuth`**,
/// because §7.7 has the relay send it immediately after. Handing it back rather
/// than acting on it here keeps this function about the handshake — and
/// dropping it, which the first version did, loses the reflector silently and
/// leaves a node that never learns its mapped address with nothing to explain
/// why.
async fn write_handshake_events(
    tls: &mut TlsStream<TcpStream>,
    events: Vec<Event>,
) -> Result<Vec<Event>, ConnectError> {
    let mut deferred = Vec::new();
    for event in events {
        match event {
            Event::Send(bytes) => tls.write_all(&bytes).await.map_err(ConnectError::Io)?,
            Event::Packet { .. } => {
                return Err(ConnectError::Protocol(
                    "relay packet arrived before handshake completion".to_owned(),
                ));
            }
            // Only ever produced once the relay's signature has verified, so
            // reaching here means the handshake finished mid-buffer.
            reflector @ Event::Reflector { .. } => deferred.push(reflector),
        }
    }
    tls.flush().await.map_err(ConnectError::Io)?;
    Ok(deferred)
}

impl Session {
    /// Start a client handshake from this node's control-plane handle.
    ///
    /// KARST-CONTROL renders node identifiers as base64 for its own wire
    /// format, while Ponor carries the 32-byte digest. Keeping the conversion
    /// at this boundary prevents a caller from accidentally signing the
    /// display spelling as though it were a Ponor identity.
    #[must_use]
    pub fn from_control_handle(
        node_handle: &[u8],
        relay: &Relay,
        random: [u8; ID_LEN],
    ) -> Option<Self> {
        let handle = std::str::from_utf8(node_handle).ok()?;
        let node_id = karst_control_client::handle_bytes(handle)?;
        Some(Self::new(node_id, relay, random))
    }

    /// Start a client handshake for a relay registry entry.
    #[must_use]
    pub fn new(node_id: [u8; ID_LEN], relay: &Relay, random: [u8; ID_LEN]) -> Self {
        Self {
            handshake: ClientHandshake::new(
                Role::Client,
                node_id,
                relay.relay_id,
                relay.identity_key.clone(),
                random,
            ),
            awaiting_auth: false,
        }
    }

    /// Handle the first frame from a relay, producing `ClientAuth` only when
    /// its advertised id matches the pin from the netmap.
    ///
    /// # Errors
    /// Returns the Ponor handshake error and permanently fails the session.
    pub fn on_hello(
        &mut self,
        frame: &Frame<'_>,
        signer: &impl Signer,
    ) -> Result<Vec<u8>, karst_relay_proto::Error> {
        self.handshake.on_relay_hello(frame, signer)
    }

    /// Verify the relay signature and establish this session.
    ///
    /// # Errors
    /// Returns the Ponor handshake error and permanently fails the session.
    pub fn on_auth(
        &mut self,
        frame: &Frame<'_>,
        verifier: &impl Verifier,
    ) -> Result<(), karst_relay_proto::Error> {
        let result = self.handshake.on_relay_auth(frame, verifier);
        if result.is_ok() {
            self.awaiting_auth = false;
        }
        result
    }

    /// Advance the node-side Ponor state machine by one decoded frame.
    ///
    /// The caller may write only the [`Event::Send`] bytes returned here, and
    /// may act on [`Event::Packet`] only after both the relay-id pin and its
    /// ML-DSA signature have verified. Keeping this transition beside the
    /// session prevents future TCP/TLS code from growing a pre-auth receive
    /// shortcut.
    ///
    /// # Errors
    /// Returns [`karst_relay_proto::Error::OutOfOrder`] for any frame not legal
    /// in the current state. A connection that receives one must be closed.
    pub fn on_frame(
        &mut self,
        frame: &Frame<'_>,
        signer: &impl Signer,
        verifier: &impl Verifier,
    ) -> Result<Option<Event>, karst_relay_proto::Error> {
        if self.established() {
            // §7.7. Legal only here — a `ReflectOffer` before `RelayAuth` is a
            // key from a party this node has not authenticated, which is
            // exactly the offer an impostor relay would make.
            if let Frame::ReflectOffer {
                reflect_key,
                endpoint,
            } = frame
            {
                return Ok(Some(Event::Reflector {
                    key: *reflect_key,
                    endpoint: *endpoint,
                }));
            }
            return self
                .received(frame)
                .map(|(source_id, payload)| Event::Packet { source_id, payload })
                .map(Some)
                .ok_or(karst_relay_proto::Error::OutOfOrder);
        }
        if self.awaiting_auth {
            self.on_auth(frame, verifier)?;
            return Ok(None);
        }
        let auth = self.on_hello(frame, signer)?;
        self.awaiting_auth = true;
        Ok(Some(Event::Send(auth)))
    }

    /// Wrap an opaque datagram for a reachable peer. `None` means the relay is
    /// not authenticated yet, never a best-effort send.
    #[must_use]
    pub fn send_packet(&self, destination: [u8; ID_LEN], payload: &[u8]) -> Option<Vec<u8>> {
        self.handshake.may_send().then(|| {
            Frame::SendPacket {
                dst_id: destination,
                payload,
            }
            .to_vec()
        })
    }

    /// Extract a relay-stamped incoming datagram after authentication.
    #[must_use]
    pub fn received(&self, frame: &Frame<'_>) -> Option<([u8; ID_LEN], Vec<u8>)> {
        // Kept as a separate helper from `on_frame` so the established-state
        // check below cannot be bypassed by a future caller.
        if !self.handshake.may_send() {
            return None;
        }
        match frame {
            Frame::RecvPacket { src_id, payload } => Some((*src_id, payload.to_vec())),
            _ => None,
        }
    }

    #[must_use]
    pub fn established(&self) -> bool {
        self.handshake.is_established()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::panic)]

    use karst_relay_proto::consts::SIG_LEN;
    use sha2::{Digest as _, Sha256};

    use super::*;

    struct TestSigner;

    impl Signer for TestSigner {
        fn sign(&self, _: &[u8]) -> Result<Vec<u8>, Box<dyn core::error::Error + Send + Sync>> {
            Ok(vec![0x55; SIG_LEN])
        }
    }

    struct TestVerifier;

    impl Verifier for TestVerifier {
        fn verify(&self, _: &[u8], _: &[u8], signature: &[u8]) -> bool {
            signature.len() == SIG_LEN
        }
    }

    fn relay() -> Relay {
        let identity_key = vec![0x44; 1952];
        let mut h = Sha256::new();
        h.update(b"karst-relay-id-v1");
        h.update(&identity_key);
        Relay {
            address: "127.0.0.1:443".to_owned(),
            tls_server_name: "relay.test".to_owned(),
            relay_id: h.finalize().into(),
            identity_key,
            region: "test".to_owned(),
        }
    }

    #[test]
    fn control_handle_becomes_the_raw_ponor_node_id() {
        let node_handle = karst_control_client::handle(&[0x11; 1952]);
        let relay = relay();
        let mut session =
            Session::from_control_handle(node_handle.as_bytes(), &relay, [0x22; ID_LEN])
                .expect("valid control handle");

        let auth = session
            .on_hello(
                &Frame::RelayHello {
                    relay_id: relay.relay_id,
                    relay_random: [0x33; ID_LEN],
                },
                &TestSigner,
            )
            .expect("pinned relay hello");
        assert!(!auth.is_empty());
        session
            .on_auth(
                &Frame::RelayAuth {
                    signature: &[0x66; SIG_LEN],
                },
                &TestVerifier,
            )
            .expect("relay auth");
        assert!(session.established());
    }

    #[test]
    fn malformed_control_handles_cannot_start_a_relay_session() {
        assert!(Session::from_control_handle(b"not a handle", &relay(), [0; ID_LEN]).is_none());
        assert!(Session::from_control_handle(&[0xff], &relay(), [0; ID_LEN]).is_none());
    }

    #[test]
    fn packets_are_unavailable_until_the_pinned_relay_authenticates() {
        let relay = relay();
        let mut session = Session::new([0x11; ID_LEN], &relay, [0x22; ID_LEN]);
        let packet = Frame::RecvPacket {
            src_id: [0x77; ID_LEN],
            payload: b"not before auth",
        };
        assert_eq!(
            session.on_frame(&packet, &TestSigner, &TestVerifier),
            Err(karst_relay_proto::Error::OutOfOrder)
        );
    }

    #[test]
    fn the_frame_driver_exposes_only_authenticated_recv_packets() {
        let relay = relay();
        let mut session = Session::new([0x11; ID_LEN], &relay, [0x22; ID_LEN]);

        let hello = Frame::RelayHello {
            relay_id: relay.relay_id,
            relay_random: [0x33; ID_LEN],
        };
        let Some(Event::Send(auth)) = session
            .on_frame(&hello, &TestSigner, &TestVerifier)
            .expect("relay hello")
        else {
            panic!("hello did not yield ClientAuth");
        };
        assert!(!auth.is_empty());

        assert_eq!(
            session
                .on_frame(
                    &Frame::RelayAuth {
                        signature: &[0x66; SIG_LEN],
                    },
                    &TestSigner,
                    &TestVerifier,
                )
                .expect("relay auth"),
            None
        );
        assert!(session.established());

        assert_eq!(
            session
                .on_frame(
                    &Frame::RecvPacket {
                        src_id: [0x77; ID_LEN],
                        payload: b"relay payload",
                    },
                    &TestSigner,
                    &TestVerifier,
                )
                .expect("authenticated packet"),
            Some(Event::Packet {
                source_id: [0x77; ID_LEN],
                payload: b"relay payload".to_vec(),
            })
        );
    }

    #[test]
    fn decoder_handles_split_and_coalesced_tls_reads() {
        let relay = relay();
        let session = Session::new([0x11; ID_LEN], &relay, [0x22; ID_LEN]);
        let mut decoder = Decoder::new(session);

        let hello = Frame::RelayHello {
            relay_id: relay.relay_id,
            relay_random: [0x33; ID_LEN],
        }
        .to_vec();
        let split = hello.len() / 2;
        let first = hello.get(..split).expect("split is within hello");
        let second = hello.get(split..).expect("split is within hello");
        assert!(decoder
            .push(first, &TestSigner, &TestVerifier)
            .expect("partial hello")
            .is_empty());
        let events = decoder
            .push(second, &TestSigner, &TestVerifier)
            .expect("finished hello");
        assert!(matches!(events.as_slice(), [Event::Send(_)]));

        let mut coalesced = Frame::RelayAuth {
            signature: &[0x66; SIG_LEN],
        }
        .to_vec();
        coalesced.extend_from_slice(
            &Frame::RecvPacket {
                src_id: [0x77; ID_LEN],
                payload: b"coalesced",
            }
            .to_vec(),
        );
        assert_eq!(
            decoder
                .push(&coalesced, &TestSigner, &TestVerifier)
                .expect("coalesced frames"),
            vec![Event::Packet {
                source_id: [0x77; ID_LEN],
                payload: b"coalesced".to_vec(),
            }]
        );
        assert!(decoder.established());
    }

    #[test]
    fn decoder_bounds_an_incomplete_frame_buffer() {
        let relay = relay();
        let session = Session::new([0x11; ID_LEN], &relay, [0x22; ID_LEN]);
        let mut decoder = Decoder::new(session);
        let too_much = vec![0; BUFFER_MAX + 1];
        assert!(matches!(
            decoder.push(&too_much, &TestSigner, &TestVerifier),
            Err(karst_relay_proto::Error::FrameTooLarge(_))
        ));
    }

    #[test]
    fn upgrade_parser_preserves_a_coalesced_first_ponor_frame() {
        let mut bytes = b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n\r\n".to_vec();
        bytes.extend_from_slice(&[0x01, 0x02, 0x03]);
        let head = upgrade_head_len(&bytes).expect("complete response");
        assert_eq!(bytes.get(head..), Some(&[0x01, 0x02, 0x03][..]));
    }
}
