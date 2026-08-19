<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Karst

**A post-quantum mesh VPN with self-hosted coordination, an admin console, and
user management.**

> **Status: pre-alpha. Do not deploy this.** Phase 4 of 7. There is a working
> end-to-end tunnel — two nodes enrol with a coordination server, meet over a
> relay, punch through NATs and carry TCP under a policy — but **nothing here
> has had external cryptographic or security review**, the wire formats are
> still changing without compatibility guarantees, and several protocol gaps are
> recorded and unfixed. It is ready to be *reviewed*, not to be relied on.

Karst is a Tailscale-equivalent overlay network in which every long-term
cryptographic dependency is post-quantum. The driving threat is
**harvest-now-decrypt-later**: traffic recorded today, decrypted years from now
by a quantum computer. That deadline has already passed for anything you send
over a classical VPN — which is the reason this project exists.

## What actually works today

The headline: **two `karstd` daemons, a real relay and a real coordination
server, in separate network namespaces with real TUN devices, reaching a direct
encrypted path and exchanging TCP under a port-scoped ACL.** Including when both
nodes are behind their own NATs, which is the ordinary home-to-home case.

```
A: endpoint = "-"                 state = "connecting"   transport = "relay"
B: endpoint = "-"                 state = "established"  transport = "relay"
...
A: endpoint = "10.99.0.2:51820"   state = "established"  transport = "direct"
B: endpoint = "10.99.0.1:51820"   state = "established"  transport = "direct"
```

| Area | Status |
|---|---|
| **PHREATIC** — handshake and datapath ([spec](spec/phreatic-v1.md)) | Draft 0.2. ML-KEM-768 + X25519, fragmentation, stateless-under-load responder, rekey |
| **KARST-CONTROL** — control channel ([spec](spec/karst-control-v1.md)) | Draft 0.1. Enrolment, netmap, per-pair PSKs and disco keys, encrypted cache |
| **Ponor** — relay ([spec](spec/ponor-v1.md)) | Draft 0.1. TLS 1.3 with `X25519MLKEM768` enforced, ML-DSA-65 relay identity, structural admission |
| **AVEN** — NAT traversal ([spec](spec/aven-v1.md)) | Draft 0.1. Probing, path selection with hysteresis, candidate exchange, server-reflexive discovery |
| `karstd` — node agent | TUN, datapath, stateful packet filter, discovery, relay client |
| `karst-relay` — relay server | Forwarding, presence, rate limiting, AVEN reflector |
| `karst-portmap` — NAT-PMP and PCP | Codec for both, verified against `miniupnpd` rather than against itself; wired into `karstd` |
| `karst-control` — coordination server (Go) | Enrolment, netmap, policy, audit, relay registry |
| Console / portal (TypeScript) | **not started** |
| **KarstDNS**, **Bedrock** network lock | **not started** — Phase 5 |

**772 Rust tests** and **157 Go tests** run unprivileged; a further suite runs
under `sudo` with real network namespaces (`just test-privileged`), including a
twelve-row NAT matrix and **ten end-to-end aquifer topologies** — each one a
whole aquifer, and each ending in a TCP conversation under an ACL.

| Node A is behind | Node B is behind | Result |
|---|---|---|
| *(nothing)* | *(nothing)* | direct |
| **same NAT, one LAN** | **same NAT, one LAN** | **direct** — over private addresses |
| port-restricted cone | *(nothing)* | direct |
| port-restricted cone | port-restricted cone | direct |
| symmetric | *(nothing)* | direct |
| symmetric | address-restricted cone | direct |
| symmetric **with a port mapping** | symmetric | **direct** — PCP/NAT-PMP |
| symmetric | symmetric | relay — not winnable; see below |
| symmetric | port-restricted cone | relay — winnable, unbuilt |
| all UDP dropped | *(nothing)* | relay, and correctly so |

**Seven of ten, and the three that stay relayed are asserted to stay relayed.**
A node that advertises an address it is not reachable at is worse than one that
admits it is relayed, so those rows fail if either end ever reports `direct`.

### Formal models

Nine ProVerif models run in CI, including the ones that **must fail** — gated on
the number of failing queries, so a change that quietly stopped a demonstration
demonstrating anything would break the build.

| Model | Result |
|---|---|
| `phreatic.pv`, `karst-control.pv`, `ponor.pv`, `aven.pv` | ✅ 4/4 each |
| `phreatic-dh-broken.pv` — classical break | ✅ 4/4 |
| `phreatic-kem-broken.pv` — lattice break | ❌ **does not terminate** |
| `karst-control-nofs.pv`, `ponor-norelayid.pv`, `aven-headeronly.pv` | must-fail, and do |

Two of those found real defects before the code shipped: `aven.pv` produced a
**reflector** in draft 0.1 of AVEN (a `Ping` is authenticated, which is not the
same as saying a genuine one cannot be *replayed*), and `ponor-norelayid.pv`
shows a rogue relay replaying a client's authentication to the real one.

### Caveats stated plainly

A security project that advertises only its wins is not trustworthy.

- **No external cryptographic or security review has happened.** Symbolic models
  check a design, not an implementation.
- **ADR-0002's "secure if either cryptographic family holds" is not fully
  proved.** The classical-break direction is proved in ProVerif; the
  lattice-break direction has bounded Verifpal verification only, because
  `phreatic-kem-broken.pv` does not terminate. See
  [spec/models/README.md](spec/models/README.md), which explains why and what
  was tried.
- **Ponor derives no session key** (`ponor-v1.md` §13.3), so the relay's frame
  stream is protected by TLS alone. Bounded — payloads are already end-to-end
  ciphertext — but it is a TLS dependency the other two protocols do not have.
- **`CallMeMaybe` bodies are not encrypted** (`aven-v1.md` §12.3), so a relay
  operator sees the local interface addresses a node advertises.
- **A symmetric NAT connects to some peers and not others.** Facing a
  publicly-reachable peer or an address-restricted cone, it goes direct. Facing
  a *port-restricted* cone or another symmetric NAT, it stays relayed — unless
  one side's gateway offers an explicit port mapping (PCP or NAT-PMP), which
  makes even symmetric-to-symmetric direct. Without a mapping,
  symmetric-to-symmetric is not winnable: published analysis of the alternative
  puts it at 0.01% after twenty seconds.
- **One topology that should connect directly still does not.** A symmetric
  NAT facing a port-restricted cone — a CGNAT subscriber talking to somebody on
  a home router — is reachable in principle (`aven-v1.md` §7.7) and unbuilt in
  the daemon. Seven of ten topologies go direct; of the three that do not, two
  have no direct path to find at all.
- **Wire formats are not stable.** Adding the relay's reflector was a flag day
  (`ponor-v1.md` §13.10), and there will be others before 1.0.

Everything found by review and not yet fixed is in
[FINDINGS.md](FINDINGS.md) — open findings included, with severities.

## Design

The plan is decision-complete and every significant choice is recorded with its
rationale, its alternatives, and its costs.

- **[PLAN.md](PLAN.md)** — the implementation plan, phases 0–7, with what each
  phase actually produced rather than what it intended to
- **[docs/THREAT-MODEL.md](docs/THREAT-MODEL.md)** — assets, adversaries, trust
  boundaries, and a compromise-yield matrix. **§7 lists what Karst deliberately
  does not defend**, which is the section worth reading first
- **[docs/adr/](docs/adr/)** — architecture decision records

Notable decisions, each with an ADR:

| | |
|---|---|
| Hybrid X25519 + ML-KEM-768, ML-DSA-65, SLH-DSA-192s | [0001](docs/adr/0001-cryptographic-algorithm-selection.md), [0002](docs/adr/0002-hybrid-key-agreement.md) |
| Greenfield Rust datapath — a 2378-byte handshake breaks WireGuard's framing | [0003](docs/adr/0003-greenfield-rust-datapath.md) |
| Fragmentation with a stateless-under-load responder; per-pair PSK hedge | [0004](docs/adr/0004-handshake-mtu-and-kem-selection.md) |
| MIT/Apache clients, AGPL server, DCO not CLA, no commercial licence | [0007](docs/adr/0007-licensing.md) |
| Relay co-located with the coordination server; TURN fallback | [0008](docs/adr/0008-relay-infrastructure-and-funding.md) |
| Control plane forked from NetBird rather than greenfield | [0009](docs/adr/0009-control-plane-fork-vs-greenfield.md) |

## Components

| Component | Language | Role |
|---|---|---|
| `karstd` | Rust | Node agent — TUN, peer state, routing, discovery, DNS |
| `karst` | Rust | CLI |
| `karst-relay` | Rust | **Ponor** encrypted relay, and the AVEN reflector |
| `karst-control` | Go | Coordination server — registration, policy, SSO, audit |
| console / portal | TypeScript | Admin console and user self-service |

The handshake is **PHREATIC**; the relay protocol is **Ponor**; NAT traversal is
**AVEN**; the network lock is **Bedrock**; the name service is **KarstDNS**. All
named for karst hydrology — see
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
just                   # list targets
just check             # the Rust gate: fmt, clippy, tests, cargo-deny, licences
just go-test go-lint   # the coordination server
just test-privileged   # namespaces, TUN devices, the NAT matrix — needs sudo
just verify            # Verifpal ×3 + every ProVerif model, must-fail ones included
```

Requires Rust 1.88+, Go 1.27+, Node 22+ and `pnpm`. The privileged tests need
Linux, `nft` and root. Go 1.27 is a hard floor: the control plane uses the
standard library's `crypto/mldsa`, which replaced a third-party shim in
[ADR-0011](docs/adr/0011-control-channel-authentication.md).

## Contributing

[CONTRIBUTING.md](CONTRIBUTING.md). Sign off your commits (`git commit -s`) —
we use the DCO. **There is no CLA and no copyright assignment**, which is
deliberate and means the project cannot unilaterally relicense.

Security reports: [SECURITY.md](SECURITY.md), which includes an explicit safe
harbour for good-faith research. Review is actively wanted — the specifications
carry a royalty-free implementation grant precisely so that a second
implementation can exist to disagree with this one.

## Licence

| Path | Licence |
|---|---|
| `crates/`, `bins/` | `MIT OR Apache-2.0` |
| `server/`, `web/` | `AGPL-3.0-or-later` |
| `spec/`, `docs/` | `CC-BY-4.0` + royalty-free implementation grant |

The AGPL on the server does **not** affect your use of the client — they are
separate programs communicating over a network protocol. Full texts are in
[`LICENSES/`](LICENSES/), the authoritative summary is [LICENSE](LICENSE), and
the reasoning is in [LICENSING.md](LICENSING.md).

## Prior art

Karst borrows ideas from work we did not write. Tailscale's **DERP** shaped the
relay design (mesh presence, home-relay selection, relay-first-then-upgrade) and
its `disco` shaped AVEN; we borrow the designs and deliberately not the
protocols or the fleet. The handshake builds on **PQNoise** and
**PQ-WireGuard**, and owes **Rosenpass** its approach to DoS resistance and
stateless responders. The coordination server is a fork of **NetBird** under
their BSD-3 licence ([ADR-0009](docs/adr/0009-control-plane-fork-vs-greenfield.md)),
with generic improvements offered upstream.

*Karst* is a trademark of the project. Anyone may fork the code; nobody may
call their fork Karst.
