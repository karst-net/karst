# ADR-0020: QUIC as an alternate relay transport

- **Status:** Accepted
- **Date:** 2026-09-12
- **Deciders:** TBD
- **Supersedes:** —
- **Related:** ADR-0008 (relay infrastructure), ADR-0018 (relay/control TLS
  transport unchanged), `spec/ponor-v1.md`, GitHub issue #122

---

## Context

`spec/ponor-v1.md` §4.1 runs the relay transport as TCP + TLS 1.3 (hybrid
`X25519MLKEM768` via `aws-lc-rs`) + an HTTP/1.1 `Upgrade: ponor` to a binary
frame protocol, on port 443. Open item §13 #5 names the cost: every peer a
node relays through shares that one TCP connection, so a lost segment stalls
delivery to all of them, and a relayed PHREATIC session runs TCP's
retransmission inside its own. `PLAN.md` §5 flagged "HTTP/3 + QUIC datagrams"
as a Phase 6 idea for this. Issue #122 (Phase 7's relay performance roadmap)
asks to specify and implement QUIC relay carriage while preserving Ponor's
identity, authorization and end-to-end-encryption properties, add
interoperability/failure tests, and compare performance against the existing
transport.

Ponor's frame protocol (`crates/karst-relay-proto`) is already sans-I/O: the
handshake state machines (`RelayHandshake`/`ClientHandshake`), the relay's
`Hub` (keyed by an opaque `ConnId`, queueing pre-encoded frame bytes) and the
mesh `Dialler` (which only ever produces an address and a name to dial) never
touch a socket type. What they lean on the transport for is exactly what
TCP+TLS supplies today: an ordered, reliable, confidential and
integrity-protected byte stream. Ponor derives no session key of its own —
§1.2 is explicit that it is "not a transport," and open item §13 #3 records
that "nothing protects the frame stream but TLS" once the handshake
completes. Any replacement transport has to supply the same three properties
(order, reliability, TLS-grade record protection) or that residual-risk
argument stops holding.

## Decision

**Add QUIC as a second, opt-in transport that carries the unmodified Ponor
frame protocol over one ordered, reliable bidirectional stream per
connection. This is a transport swap, not a wire-protocol change.**

Concretely:

- **Library: `quinn`**, feature-gated to `runtime-tokio` +
  `rustls-aws-lc-rs`, no default features. Quinn drives QUIC's TLS 1.3
  handshake (RFC 9001) through an ordinary `rustls::ServerConfig`/
  `ClientConfig` (`quinn::crypto::rustls::QuicServerConfig`/
  `QuicClientConfig`), so `tls::provider()`, `tls::server_config()` and
  `tls::client_config()` are reused unchanged — the same `CryptoProvider`
  enforces the same `X25519MLKEM768`-preferred requirement `tls.rs` already
  checks at startup, on both transports. `quiche` was rejected because it is
  BoringSSL-based rather than rustls-based, which would mean a second,
  independently-audited PQC-hybrid TLS stack; `s2n-quic` was rejected because
  its bundled TLS provider does not give the same flexibility to plug a
  custom hybrid named group.
- **ALPN replaces the HTTP/1.1 upgrade.** A QUIC connection negotiates
  `ponor/1` at the TLS layer; there is no `GET /ponor` request and no 101
  response on this path. Everything from the Ponor handshake onward
  (`RelayHello`/`ClientAuth`/`RelayAuth`, then the frame stream) is
  byte-for-byte identical to the TCP path.
- **One bidirectional stream per Ponor connection**, opened immediately after
  the QUIC handshake, carrying every frame type exactly as the single TCP
  byte stream does today — including `Ping`'s priority-jump-the-queue
  behavior (`hub.rs`'s `enqueue_priority`), which assumes one linear stream.
  Splitting frame types across independent QUIC streams is exactly what would
  fix §13 #5's head-of-line-blocking gap, and is deliberately **not** part of
  this decision — see Alternatives rejected.
- **No netmap or control-plane schema change.** A relay listens for QUIC on
  the same `listen` host:port already configured for TCP, just over UDP —
  the same "port 443 either way" convention the TCP transport already relies
  on to survive restrictive networks. Whether a node tries QUIC is a local,
  node-side opt-in setting; on failure or timeout it falls back to the
  existing TCP+TLS path. Advertising per-relay QUIC support through the
  netmap for automatic discovery is left to a future ADR.

### Alternatives rejected

- **Also split Ponor into per-destination-peer QUIC streams now**, to fix
  §13 #5 properly rather than only fixing TCP-in-TCP retransmission and
  giving each connection independent loss recovery. Rejected for this
  decision: Ponor v1 has no capability-negotiation field (§13.10 already
  flags this gap), so multiplexing by peer would need a wire-version bump,
  new Verifpal/ProVerif models, and a migration story — a materially larger
  change than "carry the same bytes over a different transport." Tracked as
  follow-up work, not abandoned.
- **QUIC datagrams** for the relayed payload, per `PLAN.md`'s original
  phrasing. Rejected for the same reason: Ponor's frames assume reliable,
  ordered delivery throughout (§1.2), and datagram carriage would need its
  own retransmission/ordering story above what QUIC's unreliable datagram
  extension provides — a protocol redesign, not a transport swap.
- **Advertise QUIC support via the netmap/relay registry now.** Rejected for
  scope: it reaches into the Go control server and the netmap protobuf, a
  much larger cross-language surface, for a capability that a same-port UDP
  probe with TCP fallback already delivers without it.

## Consequences

### Positive

- A lost packet no longer stalls retransmission twice (once in QUIC, once in
  the PHREATIC-carrying TCP stream it used to ride inside) — QUIC's own loss
  recovery replaces TCP's for this hop.
- No change to Ponor's wire format, versioning, or security argument: the
  same handshake, the same frame types, the same "TLS protects the stream"
  residual-risk model, now provided by QUIC's TLS 1.3 instead of TCP's.
- `tls.rs`'s existing PQC-hybrid enforcement (`provider()`,
  `post_quantum_is_preferred`) covers the QUIC listener for free, since it is
  the same `rustls::ServerConfig` underneath.

### Negative

- §13 #5's head-of-line-blocking gap remains open: this transport still
  multiplexes every relayed peer onto one stream, so a lost packet for peer A
  still stalls frames queued for peer B on the same connection. Only the
  retransmission cost changes, not the multiplexing.
- Two transports means two code paths to keep behaviorally identical
  (established by shared interop tests, not by construction) and two
  listeners to operate.
- QUIC's UDP transport is more filterable in some restrictive networks than
  TCP/443, which is exactly why this is opt-in with TCP fallback rather than
  a replacement.

### Reconsider if

Per-destination-peer stream multiplexing becomes a priority — at that point
this ADR's "one stream per connection" carries over the same TCP-era
limitation and should be revisited alongside the capability-negotiation field
§13.10 already calls for.
