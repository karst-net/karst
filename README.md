<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Karst

**A post-quantum mesh VPN with self-hosted coordination, an admin console, and
user management.**

> **Status: pre-alpha.** Early Phase 1. There is no usable VPN here — no
> daemon, no tunnel, no control plane. What exists is the protocol
> specification, formal models, and the first two crates. **Do not deploy
> this.**

Karst is a Tailscale-equivalent overlay network in which every long-term
cryptographic dependency is post-quantum. The driving threat is
**harvest-now-decrypt-later**: traffic recorded today, decrypted years from now
by a quantum computer. That deadline has already passed for anything you send
over a classical VPN — which is the reason this project exists.

## What actually works today

| | Status |
|---|---|
| [`spec/phreatic-v1.md`](spec/phreatic-v1.md) — protocol specification | Draft 0.2, not externally reviewed |
| `karst-crypto` — suite registry, downgrade protection, ML-KEM-768 | 21 tests |
| `karst-proto` — fragment codec, reassembler | 26 tests, fuzzed |
| Verifpal models ×3 | all verify |
| ProVerif — base model, X25519-broken variant | 4/4 each |
| ProVerif — ML-KEM-broken variant | **does not terminate** |
| Everything else — handshake, datapath, relay, DNS, control plane, console | not started |

Two caveats stated plainly, because a security project that advertises only its
wins is not trustworthy:

- **ADR-0002's "secure if either cryptographic family holds" is not fully
  proved.** The classical-break direction is proved in ProVerif; the
  lattice-break direction has bounded Verifpal verification only. See
  [spec/models/README.md](spec/models/README.md).
- **No external cryptographic review has happened.** Symbolic models check a
  design, not an implementation.

## Design

The plan is decision-complete and every significant choice is recorded with its
rationale, its alternatives, and its costs.

- **[PLAN.md](PLAN.md)** — the implementation plan, phases 0–7
- **[docs/THREAT-MODEL.md](docs/THREAT-MODEL.md)** — assets, adversaries, trust
  boundaries, and a compromise-yield matrix. **§7 lists what Karst deliberately
  does not defend**, which is the section worth reading first
- **[docs/adr/](docs/adr/)** — ten architecture decision records

Notable decisions, each with an ADR:

| | |
|---|---|
| Hybrid X25519 + ML-KEM-768, ML-DSA-65, SLH-DSA-192s | [0001](docs/adr/0001-cryptographic-algorithm-selection.md), [0002](docs/adr/0002-hybrid-key-agreement.md) |
| Greenfield Rust datapath — a 2378-byte handshake breaks WireGuard's framing | [0003](docs/adr/0003-greenfield-rust-datapath.md) |
| Fragmentation with a stateless-under-load responder; per-pair PSK hedge | [0004](docs/adr/0004-handshake-mtu-and-kem-selection.md) |
| MIT/Apache clients, AGPL server, DCO not CLA, no commercial licence | [0007](docs/adr/0007-licensing.md) |
| Relay co-located with the coordination server; TURN fallback | [0008](docs/adr/0008-relay-infrastructure-and-funding.md) |

## Components

| Component | Language | Role |
|---|---|---|
| `karstd` | Rust | Node agent — TUN, peer state, routing, DNS |
| `karst` | Rust | CLI |
| `karst-relay` | Rust | **Ponor** encrypted relay |
| `karst-control` | Go | Coordination server — registration, policy, SSO, audit |
| console / portal | TypeScript | Admin console and user self-service |

The handshake is **PHREATIC**; the network lock is **Bedrock**; the name
service is **KarstDNS**. All named for karst hydrology — see
[ADR-0010](docs/adr/0010-project-name-and-component-naming.md).

## What Karst does not claim

Stated here rather than buried, because a security product that only advertises
its strengths is not trustworthy:

- **Metadata is not protected.** Relays and TURN providers learn who talks to
  whom, when, and how much.
- **Endpoint compromise is total.** Root on a node yields that node's keys.
- **Coordination-server compromise plus a full lattice break is a total
  break**, because the server derives the per-pair PSKs. Server compromise
  alone is not — it cannot decrypt traffic.
- **No WireGuard interoperability.** A post-quantum handshake cannot talk to a
  WireGuard peer.

Full list: [THREAT-MODEL.md §7](docs/THREAT-MODEL.md).

## Building

```sh
just          # list targets
just check    # everything CI runs
```

Requires Rust 1.85+, Go 1.24+, Node 22+ and `pnpm`.

## Contributing

[CONTRIBUTING.md](CONTRIBUTING.md). Sign off your commits (`git commit -s`) —
we use the DCO. **There is no CLA and no copyright assignment**, which is
deliberate and means the project cannot unilaterally relicense.

Security reports: [SECURITY.md](SECURITY.md), which includes an explicit safe
harbour for good-faith research.

## Licence

| Path | Licence |
|---|---|
| `crates/`, `bins/` | `MIT OR Apache-2.0` |
| `server/`, `web/` | `AGPL-3.0-or-later` |
| `spec/`, `docs/` | `CC-BY-4.0` + royalty-free implementation grant |

The AGPL on the server does **not** affect your use of the client — they are
separate programs communicating over a network protocol. See
[LICENSING.md](LICENSING.md).

## Prior art

Karst borrows ideas from work we did not write. Tailscale's **DERP** shaped the
relay design (mesh presence, home-relay selection, relay-first-then-upgrade);
we borrow the design and deliberately not the protocol or the fleet. The
handshake builds on **PQNoise** and **PQ-WireGuard**, and owes **Rosenpass** its
approach to DoS resistance and stateless responders. If the Phase 0 spike
confirms it, the coordination server will be a fork of **NetBird**, with our
generic improvements offered upstream under their BSD-3 licence.

*Karst* is a trademark of the project. Anyone may fork the code; nobody may
call their fork Karst.
