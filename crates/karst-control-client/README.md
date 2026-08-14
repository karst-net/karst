<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# karst-control-client

The node side of **KARST-CONTROL v1** — the control channel between a Karst
node and its coordination server. See [`spec/karst-control-v1.md`] and
[ADR-0011].

## Scope

This crate implements the node side of the protocol: the key schedule, both
signing inputs, the record layer, node-handle derivation, per-pair PSK
derivation, epoch selection, peer digests for delta push, encryption at rest
for the netmap cache, and the gRPC transport.

The cryptographic core was built and pinned against vectors *before* the
transport, deliberately. Transport failures are loud — a refused connection, a
status code. What fails silently is two implementations of one specification
disagreeing by a byte: a label with the wrong text, a missing length prefix,
the nonce in the wrong half of the buffer. None of that produces an error
message; it produces a handshake that never completes, in production, with no
diagnostic.

The gRPC client is **generated at build time from the same `.proto` the Go
server compiles**, so there is one definition of the wire format rather than
two kept in step by hand.

## Cross-implementation vectors

[`spec/vectors/karst-control-v1.json`] is generated from the **Go server's own
code**, not from a reimplementation of it — a vector produced by a second
implementation of the spec proves only that it agrees with itself.

`tests/vectors.rs` checks this crate reproduces every case. When the protocol
changes, the Go side regenerates with `UPDATE_VECTORS=1` and this crate is
expected to fail until it is updated too. That failure is the point.

The vectors cover derivation and framing. They do **not** cover ML-KEM or
ML-DSA themselves: those are library primitives with NIST KATs of their own,
and Go's `crypto/mlkem` exposes no seam for encapsulation randomness, so they
could not be pinned deterministically here anyway.

## Two exit criteria live here

PLAN.md §2.6 asks for a PSK epoch rotation that does not interrupt sessions,
and an on-disk netmap cache unreadable without the node's sealed key. Both are
node-side, so both are in this crate.

**Epoch selection** (`netmap`) implements `phreatic-v1.md` §7.3: a responder
accepts epochs *n* and *n−1* and rejects everything else. Rejection matters as
much as acceptance — §7.3 resolves a *missing* PSK by falling back to 32 zero
bytes, so accepting an arbitrary epoch would let an attacker choose one we have
never held and steer every session into the lattice-only path.

`PskChoice` is an enum rather than a `Psk` for the same reason. §7.3 says
implementations "MUST NOT silently treat a zero PSK as equivalent to a real
one", and a function returning bytes lets a caller fall back and forget to
flag it. Making the two cases different types means the caller cannot reach the
bytes without having seen which one it got.

**The cache** (`cache`) seals opaque bytes rather than parsing the netmap: a
cache that understands the format is a second decoder to keep in step with the
first. Key custody is deliberately the caller's — keystore integration is
per-platform and a password KDF is a parameter-tuning decision, and neither
belongs behind a library API that would make the wrong default invisible.

[`spec/karst-control-v1.md`]: ../../spec/karst-control-v1.md
[`spec/vectors/karst-control-v1.json`]: ../../spec/vectors/karst-control-v1.json
[ADR-0011]: ../../docs/adr/0011-control-channel-authentication.md
