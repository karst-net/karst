<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Karst

**A post-quantum mesh VPN with self-hosted coordination, an admin console, and
user management.**

> **Status: pre-alpha. Usable, not reviewed.** Phase 5 of 7 complete
> (2026-09-02); Phase 6 (hardening and beta) is underway. A non-expert admin
> can install the server, connect nodes across Linux and macOS behind real
> NATs, write an ACL, and lock the network down to a signed authority list —
> entirely from the console and the published installers. But **nothing here
> has had external cryptographic or security review** (that is Phase 8, after
> GA), the wire formats are still changing without compatibility guarantees,
> and two things Phase 5's own exit gate asked for are not yet true:
> deprovisioning a user is measured at 48.9s against a 30s bound
> ([FINDINGS.md](FINDINGS.md) 67, 68), and the gate's outsider-run
> walkthrough has not happened yet. "Usable" and "reviewed" are different
> claims, and Phase 5 only earns the first one.

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
| **KARST-CONTROL** — control channel ([spec](spec/karst-control-v1.md)) | Draft 0.1. Enrollment, netmap, per-pair PSKs and disco keys, encrypted cache |
| **Ponor** — relay ([spec](spec/ponor-v1.md)) | Draft 0.1. TLS 1.3 with `X25519MLKEM768` enforced, ML-DSA-65 relay identity, structural admission |
| **AVEN** — NAT traversal ([spec](spec/aven-v1.md)) | Draft 0.1. Probing, path selection with hysteresis, candidate exchange, server-reflexive discovery |
| `karstd` — node agent | TUN, datapath, stateful packet filter, discovery, relay client |
| `karst-relay` — relay server | Forwarding, presence, rate limiting, AVEN reflector |
| `karst-portmap` — NAT-PMP and PCP | Codec for both, verified against `miniupnpd` rather than against itself; wired into `karstd` |
| `karst-control` — coordination server (Go) | Enrollment, netmap, policy, audit, relay registry, SCIM 2.0 (deprovisioning timing tracked as an open gap, see status above) |
| Console / portal (TypeScript) | Admin console and self-service portal; client-user lifecycle verified against a real server — create/invite a user, enroll a Linux device, revoke, deprovision |
| **KarstDNS** — mesh name resolution ([spec](spec/karstdns-v1.md)) | Resolver, split DNS, host integration. **Linux and macOS both shipping** (`systemd-resolved`/NetworkManager/`resolv.conf` on Linux, `/etc/resolver` on macOS); macOS's resolver *search list* is a stated Phase 6 gap, not silent. Windows is Phase 8 |
| **Bedrock** network lock | Root bootstrap, offline `karst-bedrock` signer, hash-chained audit log, and client enforcement — all exercised end to end against a real server and node. Automated audit anchoring is deferred to Phase 6 pending [ADR-0016](docs/adr/0016-capability-scoped-anchor-authorities.md)'s capability-scoped authority tier |

**874 Rust tests** and **157 Go tests** run unprivileged; a further suite runs
under `sudo` with real network namespaces (`just test-privileged`), including a
twelve-row NAT matrix and **twelve end-to-end aquifer topologies** — each one a
whole aquifer, and each ending in a TCP conversation under an ACL. That suite
also carries ADR-0012's userspace release gate, which runs its daemon with **no
capabilities at all** and reads the kernel's record back to prove it.

| Node A is behind | Node B is behind | Result |
|---|---|---|
| *(nothing)* | *(nothing)* | direct |
| **same NAT, one LAN** | **same NAT, one LAN** | **direct** — over private addresses |
| port-restricted cone | *(nothing)* | direct |
| port-restricted cone | port-restricted cone | direct |
| symmetric | *(nothing)* | direct |
| symmetric | address-restricted cone | direct |
| symmetric **with a port mapping** | symmetric | **direct** — PCP/NAT-PMP |
| symmetric | port-restricted cone **with a port mapping** | **direct** — PCP/NAT-PMP |
| symmetric | port-restricted cone | relay — no mapping to ask for |
| symmetric | symmetric | relay — not winnable; see below |
| all UDP dropped | *(nothing)* | relay, and correctly so |

**Eight of eleven, and the three that stay relayed are asserted to stay
relayed.** The two *symmetric → port-restricted cone* rows are one pairing —
a CGNAT subscriber talking to somebody on a home router, the commonest hard case
there is — and the only difference between them is whether that router
answers PCP. They are kept as a pair because neither is honest alone: the
relayed one reads as a limit of the protocol, and the direct one hides that the
capability comes from the far end's router rather than from Karst.

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
  makes even symmetric-to-symmetric direct. Random port search was specified,
  built and measured for the first of those pairings and then **deliberately
  not adopted**: 64% after eight minutes, for a pair already connected over the
  relay, at the cost of a datapath change. `aven-v1.md` §7.7 records why.
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
| MIT/Apache clients, AGPL server, DCO not CLA, no commercial license | [0007](docs/adr/0007-licensing.md) |
| Relay co-located with the coordination server; TURN fallback | [0008](docs/adr/0008-relay-infrastructure-and-funding.md) |
| Control plane forked from NetBird rather than greenfield | [0009](docs/adr/0009-control-plane-fork-vs-greenfield.md) |
| NAT64 synthesis at the socket boundary; RFC 7050 over RFC 8781 | [0013](docs/adr/0013-nat64-address-synthesis.md) |

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
just check             # the Rust gate: fmt, clippy, tests, cargo-deny, licenses
just go-test go-lint   # the coordination server
just test-privileged   # namespaces, TUN devices, the NAT matrix — needs sudo
just verify            # Verifpal ×3 + every ProVerif model, must-fail ones included
```

Requires Rust 1.88+, Go 1.27+, Node 22+ and `pnpm`. The privileged tests need
Linux, `nft` and root. Go 1.27 is a hard floor: the control plane uses the
standard library's `crypto/mldsa`, which replaced a third-party shim in
[ADR-0011](docs/adr/0011-control-channel-authentication.md).

## Running it

[**docs/GETTING-STARTED.md**](docs/GETTING-STARTED.md) builds every component
from this tree and stands it up on Linux: two nodes with a static roster and no
server at all, the co-located relay and coordination server, the same three
services under systemd, the console and portal, and the offline Bedrock signer.
It also names the failure modes that do not announce themselves — the roster
lease, the relay registry, and default-deny — and says plainly where the
walk-through stops.

## Contributing

[CONTRIBUTING.md](CONTRIBUTING.md). Sign off your commits (`git commit -s`) —
we use the DCO. **There is no CLA and no copyright assignment**, which is
deliberate and means the project cannot unilaterally relicense.

Security reports: [SECURITY.md](SECURITY.md), which includes an explicit safe
harbour for good-faith research. Review is actively wanted — the specifications
carry a royalty-free implementation grant precisely so that a second
implementation can exist to disagree with this one.

## License

| Path | License |
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
their BSD-3 license ([ADR-0009](docs/adr/0009-control-plane-fork-vs-greenfield.md)),
with generic improvements offered upstream.

*Karst* is a trademark of the project. Anyone may fork the code; nobody may
call their fork Karst.
