<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-0041: Peer-to-peer file transfer

- **Status:** Accepted
- **Date:** 2026-09-30
- **Deciders:** TBD
- **Related:** #212 (this ADR's tracking issue), `spec/phreatic-v1.md` §8 and
  §13.13 (the transport phase this rides, and why a second outer type is
  unsafe without the AAD fix that section made), GitHub issue #59 (Bedrock's
  peer-head-exchange — the inner-control-marker precedent this reuses),
  `server/management/internals/karst/policy/schema.go` (the ACL engine this
  reuses rather than duplicates), `bins/karstd/src/filter.rs` (where that
  compiled policy is enforced locally), `plans/phase-6/07-acl-gated-ssh.md`
  (the other feature that gates a control-plane concern through the general
  ACL via a virtual service port, the direct precedent for this one)

---

## Context

#212 asks for a way for two mesh peers — already mutually authenticated by
PHREATIC (`spec/phreatic-v1.md`) and already policy-checked by the same ACL
that decides whether they may reach each other at all — to send a file
directly, without standing up a separate app (SCP, a shared drive, email)
just to move bytes between two nodes that already share an authenticated,
encrypted session.

Two things constrain the design before any preference applies:

- **PHREATIC's transport phase carries opaque IP packets, not an
  application protocol.** §8 gives the transport frame no length field —
  the receiver recovers a packet's size from its own inner IP header — and
  §13.13 is explicit that adding a second outer type byte was unsafe until
  the transport header became the AEAD's associated data, which it now is,
  but no second type exists today. A file-transfer control channel is
  therefore not "a new PHREATIC message type"; it is something riding
  *inside* an already-sealed transport packet's plaintext, the same way
  Bedrock's peer-head exchange (issue #59) already does with a
  `CONTROL_MARKER` byte (`0x00`, not a legal IP version) at the front of the
  plaintext before anything that could be mistaken for tunnelled traffic.
- **The ACL engine this should reuse already exists and is already
  bidirectional.** `server/management/internals/karst/policy/schema.go`
  compiles an account's `tag:`/`group:` rules into per-node ingress/egress
  rule sets, carried to each node over the netmap
  (`karst_control_client::transport::pb::KarstFilterRule`/`KarstEgressRule`)
  and enforced locally by `bins/karstd/src/filter.rs`'s `PacketFilter` —
  exactly the mechanism `plans/phase-6/07-acl-gated-ssh.md`'s independent
  SSH admission gate already uses for a control-plane concern with no real
  socket of its own, via a virtual port matched against the general rule
  set rather than a parsed IP packet's actual destination port. File
  transfer has the identical shape: a concern that needs "may peer A reach
  peer B," gated against rules the account admin already wrote for
  something else entirely.

## Decision

A small offer/accept/chunk/complete/receipt protocol (`bins/karstd/src/filetransfer.rs`),
riding the live PHREATIC session between two peers, gated by the general ACL
at a virtual service port, with a bounded local audit log and no
coordination-server involvement beyond the ACL it already distributes.

### Wire framing

Every frame is `CONTROL_MARKER (0x00) || KIND || TransferId (16 B) || …`,
sent as an ordinary transport-phase payload. `KIND` starts at `0x02` —
`0x01` is Bedrock's own head-claim kind — so the two control-frame families
can never collide. Six kinds: `Offer`, `Accept`, `Reject`, `Chunk`,
`Complete`, `Receipt`. Every variable-length field is explicitly
length-prefixed, for the reason Bedrock's own encoder gives: the transport
pads plaintext to a multiple of 16 bytes and carries no length of its own,
so a frame that is not self-describing cannot tell its own content from
trailing padding.

`TransferId` is a sender-chosen, CSPRNG-drawn 16-byte identifier, scoped to
the pair — the same discipline `reassembly_id` uses (§5). A `Chunk` carries
up to 1024 bytes of plaintext, comfortably under the transport's
single-datagram budget once the frame's own 18-byte header is added.

### ACL gating

`PacketFilter` gains `ingress_service`/`egress_service`, evaluated against a
virtual `SERVICE_PORT` (50440) in the same general `acls` rule set an
ordinary packet is checked against — no second allow-list, per the issue's
own framing. **Ingress is the check that carries the security property**,
exactly as `filter.rs`'s own module doc already states for ordinary
traffic: a compromised peer will ignore its own egress filter, so a
received `Offer` is checked against this node's ingress rules before it is
even admitted to `pending` state, and a denial is answered with silence —
§11's discipline, reused here for the same reason `on_head_claim` never
answers a bad claim — rather than a reply that would turn this node into a
probe for its own policy. Egress is checked too, on `offer_file`, purely as
the "fail locally and immediately" courtesy `filter.rs` already documents
for the general case.

### State machine and integrity

`PeerTransfers` (per peer, behind the same per-peer lock every other piece
of per-peer engine state uses) tracks outgoing, pending, and incoming
transfers. An inbound `Offer` sits in `pending` until this node's own
user/agent calls `accept` — nothing here buffers a byte from an
unaccepted transfer. A received transfer is verified against the offered
size and a SHA-384 checksum (the suite's own transcript hash, for the
reason §9.2 gives for the fragment MAC: one hash primitive per suite) before
it is ever handed to the caller to write to disk.

### Landing a file

The engine only decrypts and validates — `Output::files_received` names
completed transfers the same way `Output::packets` names decrypted tunnel
packets, and `run::dispatch`'s caller performs the actual disk I/O
(`filetransfer::save_received_file`), the same split the TUN write already
uses. Files land in `$HOME/Downloads/Karst` (`%USERPROFILE%` on Windows),
overridable by `KARST_INCOMING_DIR`. The offered name is passed through
`safe_filename` first: separators and NUL from *either* platform's
convention are stripped, an empty or dot-only result falls back to a fixed
name, and a collision gets a numeric suffix rather than overwriting —
because the name arrives from the sending peer and is therefore untrusted.

### Audit trail

`Engine::file_transfer_receipts` is a bounded (256-entry) ring buffer of
resolved transfers — sent or received, completed, failed, declined, or
denied by policy — in the spirit of
`server/management/internals/karst/node/node.go`'s `SessionObservation`: a
self-reported local fact, not key material, not reported to the
coordination server. `Engine::Stats` gains three counters
(`file_transfer_denied`/`completed`/`failed`), surfaced everywhere
`ssh_denied` already is (`karst status`, its `--json` form, `bugreport`).

### Driving it: the IPC/CLI surface

Without this, the protocol exists but nothing can invoke it. `karstd`'s
admin control socket (`ipc::Command`) gains five commands —
`file-send PEER PATH`, `file-accept PEER ID`, `file-reject PEER ID
[REASON]`, `file-pending`, `file-receipts` — handled by `run::file_transfer_command`,
which flushes any produced datagram through the exact same `dispatch`
function the datapath workers use, over the same socket, rather than a
second send path to keep in sync with the real one. A file's bytes are read
from disk by `karstd` itself, given a path, never carried over the control
socket — that protocol is one line in, one reply out
(`ipc.rs`'s module doc), with no framing for an arbitrarily large payload.
`karst-cli` exposes these as `karst file send|accept|reject|pending|receipts`.
This is deliberately the whole of the CLI surface: an accept/reject
*prompt*, transfer progress, and any GUI integration are explicitly out of
scope below.

### Alternatives rejected

- **A new PHREATIC transport type byte.** Rejected per §13.13: the
  transport's cleartext type byte is not itself authenticated coverage for
  a second handler selector without a wire-format change closer to the
  protocol's own spec than a karstd-internal feature warrants, and the
  inner-control-marker channel Bedrock already established does the job
  with zero spec changes.
- **A dedicated real TCP/UDP socket and port, like the SSH gate's actual
  admitted traffic.** Rejected because SSH's *traffic* is real TCP the
  kernel already round-trips through the TUN device; file transfer has no
  existing traffic to admit — the transfer itself is the thing being
  invented — so there is nothing for a real socket to carry that the
  existing authenticated session does not already provide more cheaply.
  `SERVICE_PORT` is virtual for exactly this reason: it exists only to give
  the ACL matcher a port to check, mirroring the SSH gate's own precedent
  for a control-plane concern with no packet of its own.
- **A separate file-transfer allow-list.** Rejected directly by the issue:
  the general ACL already expresses which peers may reach which, and a
  second permission model would be a second thing for an account admin to
  keep in sync with the first, for no additional security property.
  *(Not literally the second `#212` in this project's numbering — pointing
  at the same well-established principle `filter.rs`'s own module doc
  states for ordinary traffic.)*
- **Reporting every transfer receipt to the coordination server.** Rejected
  for this landing: `SessionObservation`-style server-side audit is a real
  future option, but the issue's own acceptance criteria ask for "a receipt
  record on both sides," which the bounded local log satisfies, and
  reporting to the control plane is additional protocol surface
  (schema, retention, access control on who may read another node's
  transfer history) this pass does not need to open.
- **Reassembly, retransmission, or resumption for a dropped or reordered
  chunk.** Rejected for this landing. A chunk that never arrives, or
  arrives out of order, stalls the transfer rather than recovering it. This
  is acceptable for the protocol/plumbing scope #212 asks for and is called
  out explicitly in the module doc; real reliability is follow-up work, not
  a correctness gap in what shipped — a stalled transfer is observable
  (it simply never produces a `Complete`/`Receipt`) rather than silently
  wrong.
- **Streaming a file's bytes through the IPC command line, rather than
  having `karstd` read the path itself.** Rejected because the control
  socket is a one-line-command, read-to-EOF-reply protocol with no length
  framing for an arbitrarily large request; asking it to carry file
  contents would need a new framing scheme for this one command alone.
  `karstd` already does local disk I/O for the receiving side
  (`save_received_file`); having it do the same for the sending side is the
  smaller change.
- **Client-side UX — an accept/reject prompt, transfer progress, a platform
  notification.** Explicitly out of scope, per the issue: this lands the
  protocol and a scriptable CLI hook: an operator or a future per-platform
  UI calls `karst file accept`/`reject` directly today; a GUI that turns a
  pending offer into a system notification is a separate, per-platform
  follow-up.

---

## Consequences

### Positive

- No protocol or wire-format change to PHREATIC itself — this is entirely
  a karstd-internal feature riding an already-specified inner control
  channel.
- Reuses the account's existing ACL exactly as the issue asks: an admin who
  already wrote `tag:`/`group:` rules governing which peers may reach which
  gets file-transfer gating for free, with no second policy surface to
  configure or audit.
- The receiving node's ingress check is what actually enforces the
  boundary, so a compromised or modified sender cannot originate a transfer
  its own egress filter would have refused — the same property the general
  ACL already has for ordinary traffic.
- A name arriving from an untrusted peer can neither escape the incoming
  directory (`safe_filename` neutralizes every path-meaningful character on
  either platform's convention) nor silently overwrite an existing file
  (the numeric-suffix fallback).
- Fully scriptable today via `karst file …` — not blocked on any future
  per-platform UI to be useful to an operator or a test harness.

### Negative

- **No reliability.** A dropped or reordered chunk stalls the transfer with
  no retransmission or resumption. For a large file over a lossy path this
  can mean restarting from zero. Acceptable for this landing per the
  Alternatives section; a real follow-up needs its own design (a
  window, selective repeat, or falling back to a reliable substrate
  entirely).
- **Whole-file buffering in memory, both directions.** `Outgoing::data` and
  `Incoming::buffer` hold the complete file in RAM for the duration of a
  transfer — there is no streaming from or to disk mid-transfer. A very
  large file is therefore bounded by available memory on both ends, not
  just disk space. No size cap is enforced at this layer; an operator
  relying on this in a memory-constrained deployment should be aware
  nothing here refuses an oversized offer on that basis alone.
- **No coordination-server audit.** A transfer's receipt lives only in each
  node's own bounded local log, lost on daemon restart (256-entry ring
  buffer, in memory, not persisted). An account-level "who sent what to
  whom" view across the fleet does not exist yet — see Alternatives above.
- **The CLI surface is intentionally thin.** No progress reporting during a
  transfer, no interactive accept/reject prompt, no way to cancel a
  transfer already in flight (a rejection after `accept` has no wire
  message — only pre-accept `Reject` exists). An operator or script using
  `karst file accept` is committing to receiving whatever the offer's
  stated size turns out to be.
- **`ipc::Command`'s own module doc calls this socket "not a protocol to
  grow features into," and this ADR grows it by five commands.** Judged
  acceptable because every other admin command already on it
  (`DnsQuery`, `ExitUse`, `Metrics`, `StatusJson`) took the same path for
  the same reason: it is the daemon's only local control surface, and the
  alternative (a second socket, a second protocol) is a larger change for
  a smaller problem.

### Reconsider if

- Anyone actually depends on this for files large enough that whole-buffer
  memory use becomes an operational problem — that would justify a
  streaming redesign before reliability work, not after.
- A deployment needs an account-level audit trail of transfers (compliance,
  DLP-adjacent requirements) — the local-only receipt log does not scale to
  that, and it would need real design: schema, retention, who may read
  another node's history.
- Real-world loss rates make the no-retransmission behavior a frequent
  practical failure rather than a rare one — at that point a selective-repeat
  or windowed scheme stops being deferrable.
