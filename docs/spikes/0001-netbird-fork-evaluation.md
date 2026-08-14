<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Spike 0001 — NetBird fork evaluation

- **Status:** **Closed.** All deliverables reported; deliverable 2 completed
  2026-08-13 by compiler-driven measurement (§5.2a)
- **Date:** 2026-08-09, extended 2026-08-13
- **Measured against:** `netbirdio/netbird` @ `f65f7b34`, v0.76.3, 3197 commits
- **Gates:** [ADR-0009](../adr/0009-control-plane-fork-vs-greenfield.md) Decision Gate
- **Verdict:** fork viable, **but the risk is the rebase tax, not the identity
  refactor** — see §5. Recommend fork-and-diverge over fork-and-track.

---

## Scope and honesty about it

ADR-0009 defines four deliverables. This document covers **only the first**:

| # | Deliverable | Status |
|---|---|---|
| 1 | Schema diff for PQ identities vs NetBird's peer model | ✅ §1–2 |
| 2 | Vertical slice + blast-radius count | ✅ blast radius §5.2, **identity split measured against the compiler §5.2a** |
| 3 | Console rework estimate (crypto posture, Bedrock views) | ⚠️ partial, §3 |
| 4 | Measured rebase tax over 6 months of upstream commits | ✅ **measured (§5)** |

§1–4 are desk research against published source; **§5 is measured** against a
clone at `f65f7b34`. Where a number is counted rather than estimated, it says
so. The only remaining gap is the running vertical slice, which needs Go and
Rust toolchains not available in this environment.

---

## 1. NetBird's identity spine

The central finding, and it is more consequential than "the key field is the
wrong size."

**The WireGuard X25519 keypair is not merely stored by NetBird — it is the
identity, the database lookup key, and the control-channel encryption key.**

Evidence from `shared/management/proto/management.proto` and
`management/server/`:

```proto
message EncryptedMessage {
  string wgPubKey = 1;   // sender identity AND decryption routing
  bytes  body     = 2;   // NaCl box, sealed to the server's WG public key
}

message PeerKeys        { bytes sshPubKey = 1; bytes wgPubKey = 2; }
message RemotePeerConfig{ string wgPubKey = 1; repeated string allowedIps = 2; }
```

and the store interface `GetPeerByPeerPubKey(ctx, peerPubKey string, ...)`,
used by `MarkPeerConnected` to authenticate every peer on every reconnect.

So the WireGuard key does three jobs at once: **authentication handle, primary
index, and transport encryption key.** Karst has no equivalent. Its identity is
ML-DSA-65 (1952 B) plus an ML-KEM-768 static key (1184 B); the X25519 in
PHREATIC is *ephemeral*, per-handshake, and never a static identity.

**Consequence:** this is not a column-width change. Three distinct concerns are
fused in one field and must be separated before anything else can proceed.

---

## 2. Schema diff

### Must be replaced

| NetBird | Karst | Note |
|---|---|---|
| `EncryptedMessage.wgPubKey` (string) | `peer_id_hint` — 32 B, `H(label ‖ static_kem_pk)` | **Clean mapping.** ADR-0005's hint is already a 32-byte opaque handle; it slots into the routing role directly |
| `EncryptedMessage.body` NaCl box to server WG key | TLS 1.3 with `X25519MLKEM768` | ADR-0001 already specifies this. **Deletes** the envelope rather than porting it — a simplification, but it touches every RPC |
| `PeerKeys.wgPubKey` (bytes) | `{ml_kem_static_pk: 1184 B, ml_dsa_identity_pk: 1952 B}` | Two keys where there was one |
| `RemotePeerConfig.wgPubKey` (string) | `{peer_id_hint: 32 B, ml_kem_static_pk: 1184 B}` | Drives the netmap growth in §4 |
| `GetPeerByPeerPubKey` index | index on `peer_id_hint` | Same shape, same cardinality — cheap |

### Must be added — no counterpart

| Karst concept | Source | Effort |
|---|---|---|
| Per-pair PSK + `psk_epoch`, derived `KDF(master, min, max, epoch)` | §2.6, ADR-0004 | Medium — new derivation service, master custody, rotation |
| Suite ID and minimum-acceptable-suite floor | ADR-0006 | Small |
| **Bedrock signature chain** — SLH-DSA roots, k-of-n quorum, hash-chained log | §4.5 | **Large — the single biggest net-new item** |
| Crypto posture telemetry (per-session suite, lattice-only flag) | §8.1 | Medium |
| Netmap encryption at rest on the node | Phase 3 exit criterion | Small |

### Transfers with little or no change — the good news

| NetBird | Use in Karst |
|---|---|
| Account / Group / Policy model, `Policies`, `Groups` | ACL model (§4.3) |
| Setup keys (reusable, ephemeral, expiring) | Auth keys (§4.2) — same semantics |
| JWT/OIDC login, IdP integration | SSO (§4.4) |
| `FirewallRule{sourcePrefixes, PolicyID}` | Compiled packet filter |
| `NetworkMap.Serial` monotonic ordering | Netmap versioning — reusable as-is |
| IP allocation from `100.64.0.0/10` | **Identical range already planned** |
| `PeerConfig{address, dns, fqdn}`, `DNSSettings` | KarstDNS config distribution |
| `Checks` posture checks | Device posture |
| **`ProtectedHostConfig{uri, user, password}` + `HostConfig stuns/turns`** | **TURN fallback (ADR-0008) has a ready-made slot, credentials included** |

The TURN structure is a genuine windfall: ADR-0008's ephemeral-credential
distribution maps onto an existing, tested message with no schema change.

---

## 3. Console rework (deliverable 3, partial)

Reusable largely intact: peer list, user and group management, policy editor,
setup keys, DNS settings, activity log, posture checks.

Net-new: the **crypto posture view** (§8.1) and the **Bedrock** views — key
inventory, quorum configuration, pending signing requests, signed-log viewer.
Neither has any analogue; both are the product's differentiating surface.

Rough order: 6–9 engineer-weeks of console work, dominated by Bedrock. Unmeasured.

---

## 4. Quantified risk: netmap growth

The most important number in this document.

Per remote peer, the netmap carries:

| | NetBird | Karst |
|---|---|---|
| Identity material | 32 B (WG key) | 32 B hint + 1184 B ML-KEM + 1952 B ML-DSA |
| Per-pair PSK | — | 32 B |
| **Total** | **~32 B** | **~3200 B** |

**A ~100× increase in per-peer netmap payload.**

| Tailnet size | NetBird | Karst |
|---|---|---|
| 50 peers | 1.6 KB | 160 KB |
| 200 peers | 6.4 KB | 640 KB |
| 1,000 peers | 32 KB | 3.2 MB |

NetBird's `NetworkMap` carries `repeated RemotePeerConfig remotePeers` with a
`Serial` for ordering, which is the shape of **full-state push**. If a
1,000-peer tailnet pushes a 3.2 MB netmap to every peer on every membership
change, that is roughly 3.2 GB of fan-out per change. That does not work.

**This is the finding most likely to change the plan.** Mitigations, in order
of preference:

1. **Incremental delta push** — send only changed peers. May already be partly
   present; must be verified in deliverable 2. If absent, this is significant
   new work in a core code path.
2. **Lazy identity fetch** — netmap carries hint + PSK (64 B/peer); the 1184 B
   ML-KEM key and 1952 B ML-DSA key are fetched on first contact. Cuts the
   netmap 50×. **But this reintroduces exactly the control-plane dependency
   ADR-0004 rejected Classic McEliece to avoid** — a node could not handshake
   with an uncached peer while the control plane is down. Would need its own ADR.
3. **Omit the ML-DSA identity key** where Bedrock is disabled — saves 60%, but
   makes the security posture depend on netmap shape. Unattractive.

### A tension worth naming

ADR-0005 moved 1184 bytes *out* of the handshake by sending a 32-byte hint and
recovering the key from the netmap. That decision was correct — handshakes are
far more frequent than netmap changes, and the netmap travels over TLS rather
than fragmented UDP. But it **relocated the cost onto the netmap**, and the
netmap is fanned out to every peer on every change. The cost did not disappear;
it moved to a place we had not yet measured. This is the first time the two
decisions have been looked at together.

---

## 5. Measured results

Counted against a clone at `f65f7b34` (v0.76.3). Reproduce with the commands in
§7.

### 5.1 Netmap push is full-state — §4's risk is confirmed

No delta or incremental machinery exists in `management/`. The relevant
functions all pass complete maps:

```go
GetNetworkMap(ctx, peerID) (*types.NetworkMap, error)
ToSyncResponse(..., networkMap *types.NetworkMap, turnCredentials *Token,
               relayCredentials *Token, ...) *proto.SyncResponse
```

NetBird optimises **fan-out**, not payload: `affectedPeerIDsFromNetworkMap`,
`syncPeerAffectedPeers` and `markConnectedAffectedPeers` compute *which* peers
to notify, but each notified peer receives a full map. That bounds the damage —
not every change notifies everyone — but a group or policy change can affect
the whole tailnet.

**§4's projection stands: at ~3200 B/peer, a 1,000-peer tailnet pushes 3.2 MB
per notified peer.** Delta push must be built. Treat it as new work in a core
path, not an adaptation.

Incidental confirmation: `ToSyncResponse` already carries `turnCredentials` and
`relayCredentials` as ephemeral `*Token`s — ADR-0008's credential distribution
maps onto existing, exercised machinery.

### 5.2 Abort criterion 2 — **passes comfortably**

| Measure | Value |
|---|---|
| Non-test, non-generated `.go` files | 1403 |
| Files mentioning `wgPubKey` / `peerPubKey` | **24 (1.7%)** |
| Including tests and generated code | 39 |
| Raw call sites | 214 |
| Packages | `management/server` (10), `shared/management` (6), `management/internals` (4), `client/internal` (3), `client/iface` (1) |

Threshold was 30%. The identity spine is **conceptually fused but
architecturally localised** — five packages, twenty-four files. This is the
single most encouraging result in the spike.

### 5.2a The identity split, measured by the compiler (2026-08-13)

§5.2 counted *files that mention* the key. That over-counts: most mentions pass
it around as an opaque string, which is exactly what a PQ identity handle would
also be. The question the vertical slice was narrowed to — is separating the
three roles clean *in practice* — is answered better by making the type change
and letting the compiler enumerate every site that assumes identity *is* a key.

`parseRequest` turns out to be a **single chokepoint**: it parses `wgPubKey`,
NaCl-opens the body with it, and returns it for callers to use as the auth
handle. Changing its return type from `wgtypes.Key` to an opaque
`PeerIdentity struct{ h string }` gives:

| Stage | Errors | Files |
|---|---|---|
| Opaque type, no methods | **44** | 2 |
| After adding `func (p PeerIdentity) String() string` | **12** | 2 |

**A one-line method removes 73% of the apparent blast radius.** Those 32 sites
were `.String()` calls — the identity used as a label, for logging and map
keys, which a 1952-byte ML-DSA handle serves as well as an X25519 one.

The residual 12 are the real work, and they split cleanly in two:

| Kind | Sites | What they are |
|---|---|---|
| **Genuine crypto** | **5** | `encryptResponse` ×3, `encryption.EncryptMessage` ×2 — the response half of the NaCl box. This is the only role that cannot survive a PQ identity unchanged |
| Signature cascade | 7 | `authenticateExposePeer` ×3, `sendInitialSync`, `handleUpdates`, `processJwtToken`, one `return` — parameters typed `wgtypes.Key` that only ever use it as a handle; they change type and stop |

**Verdict: the separation is clean.** The fusion is real, but it is five call
sites in two files, all on the message-encryption path, all reached through one
function. Replacing that path is a bounded piece of work — and it has to be
replaced regardless, because a NaCl box keyed on a static X25519 identity is
not something a post-quantum control channel can keep.

Reproduce by patching `parseRequest`'s return type in
`management/internals/shared/grpc/server.go` and running
`go build -gcflags=-e ./management/...` — `-gcflags=-e` matters, or the
compiler stops at ten errors and the count is meaningless.

**What this does not show.** No ML-DSA identity was registered end to end; this
measures separability, not a working PQ registration. The runtime slice is now
a Phase 3 implementation task rather than a spike question, because its
remaining risk is in code we have yet to write rather than in code we forked.

### 5.3 Abort criterion 3 — **at risk**

| Measure | Value (6 months) |
|---|---|
| Commits touching those 24 files | **173** |
| Total commits in period | 609 |
| **Share of all upstream commits** | **28%** |
| Line churn on those files | **+20,437 / −3,462** |

Roughly **29 commits per month** land on precisely the files where our fork
diverges most. Whether that exceeds one engineer-week per month depends on
conflict rate, but 20k lines of churn on a rewritten identity spine is
substantial merge surface — and where conflicts resolve as "keep ours," the
cost simply changes form: we forgo the upstream improvement instead of paying
to merge it.

### 5.4 The risk profile inverted

Deliverable 1 predicted criterion 2 would be the danger and criterion 3 the
unknown. **The measurements reverse that.** The refactor is small and
contained; the ongoing divergence cost is the real exposure. That reversal is
the most decision-relevant thing in this spike.

### 5.5 The fork contradicts our stated persistence stack

Found while building the fork, and not previously noticed by this spike or by
ADR-0009. **PLAN.md §4.1 specifies `pgx` + `sqlc`, "no ORM". NetBird is GORM
throughout**, with `gorm.io/gorm` and drivers for Postgres, MySQL and SQLite in
`go.mod`, `gorm:"primaryKey"` struct tags on the domain models, and a
hand-written migration layer built around them.

This is not a detail that can be deferred, because the store layer is a large
share of what forking is supposed to save. Three options, and they are not
close in cost:

| | Cost | Consequence |
|---|---|---|
| **Inherit GORM** | free | §4.1 is wrong and should be amended. We take on an ORM the plan rejected, in the layer holding PSK material |
| Rewrite the store on `pgx`+`sqlc` | large | Forfeits much of the 8–12 week saving; the store is most of the forked surface |
| GORM inside the fork, `pgx`+`sqlc` for new Karst tables | moderate | Two persistence idioms in one binary — the worst option to maintain, and the easiest to arrive at accidentally |

**Recommendation: inherit GORM and amend §4.1.** The "no ORM" preference was
recorded for a greenfield build; it did not survive the decision to fork, and
paying to rewrite a working store layer contradicts the reason for forking at
all. The one thing that must not happen by default is the third option.

The related fact that §4.1 also holds up: NetBird already carries `pgx/v5` as a
direct dependency, so the two are not mutually exclusive at the module level —
only at the level of how we want to write queries.

---

## 6. Recommendation

**Fork — but fork-and-diverge, not fork-and-track.**

Given 28% commit overlap on the divergence surface, continuously tracking
upstream is expensive and the benefit is uncertain, because most of that churn
lands on code we will have rewritten. The better posture:

- Fork once at a known tag (v0.76.3 or later), and treat it as a **starting
  codebase, not a living dependency**.
- Cherry-pick **security fixes only**, deliberately, with review — not routine
  feature merges.
- Own the security posture of the forked code ourselves rather than assuming
  upstream covers it.

This changes two things in ADR-0009 and both should be written down:

1. *"Inherits a matured ACL model and IdP integration surface"* becomes a
   **one-time** benefit, not an ongoing one.
2. *"NetBird enters the dependency review cycle as a first-class component"*
   becomes stronger, not weaker — under fork-and-diverge we are the only ones
   patching our copy.

### Effect on the estimate

ADR-0009 projected 8–12 weeks saved. Holding at **8–12 weeks** but with the
composition changed: the identity refactor is cheaper than feared (§5.2),
delta push is new work that was not costed (§5.1), and the rebase tax is
largely eliminated by diverging rather than tracking. Net effect is roughly
neutral. **The saving is real; it is still not transformative.**

### To close the spike

One item remains: **the running vertical slice** — a Rust node registering
against a forked management server with an ML-DSA identity. It needs Go and
Rust toolchains. Its purpose is now narrower than originally framed: criterion 2
is already answered, so the slice exists to confirm that separating the three
fused roles of `wgPubKey` (auth handle, primary index, transport encryption
key) is clean in practice rather than merely localised on paper.

---

## 7. Reproducing the measurements

```sh
git clone --filter=blob:none https://github.com/netbirdio/netbird.git && cd netbird

# blast radius (criterion 2)
TOTAL=$(find . -name '*.go' -not -name '*_test.go' -not -name '*.pb.go' | wc -l)
grep -rl -i "wgpubkey\|peerpubkey" --include='*.go' --include='*.proto' . \
  | grep -v '_test.go' | grep -v '\.pb\.go' | wc -l

# rebase tax (criterion 3)
FILES=$(grep -rl -i "wgpubkey\|peerpubkey" --include='*.go' --include='*.proto' . \
  | grep -v '_test.go' | grep -v '\.pb\.go')
git log --since="6 months ago" --oneline -- $FILES | wc -l
git log --since="6 months ago" --numstat --format="" -- $FILES \
  | awk '{i+=$1; d+=$2} END {printf "+%d / -%d\n", i, d}'
```

---

## Sources

- [netbirdio/netbird — `shared/management/proto/management.proto`](https://github.com/netbirdio/netbird/blob/main/shared/management/proto/management.proto)
- [Peer Management — DeepWiki](https://deepwiki.com/netbirdio/netbird/3.2-peer-management)
- [`management/server/peer` — pkg.go.dev](https://pkg.go.dev/github.com/netbirdio/netbird/management/server/peer)
- [How NetBird Works](https://docs.netbird.io/about-netbird/how-netbird-works)
