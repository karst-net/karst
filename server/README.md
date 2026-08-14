# karst-control

Coordination server. A **pruned fork of [NetBird](https://github.com/netbirdio/netbird)**
per [ADR-0009](../docs/adr/0009-control-plane-fork-vs-greenfield.md) and
[Spike 0001](../docs/spikes/0001-netbird-fork-evaluation.md).

| | |
|---|---|
| Forked from | `netbirdio/netbird` |
| Tag | `v0.76.3` |
| Commit | `f65f7b34` |
| Vendored | 2026-08-13 |
| Toolchain | Go 1.25.5+ (`go.mod`; Go's toolchain switching fetches it) |

## Fork-and-diverge, not fork-and-track

Spike 0001 §5.3 measured **28% of upstream commits** landing on the files we
diverge most on, with +20k lines of churn over six months. Tracking that is
expensive and the benefit is uncertain. So: **security fixes are cherry-picked
deliberately, with review. Routine upstream churn is not merged.** Generic
improvements we make are still offered upstream under BSD-3.

## What was pruned

Only the management server and its transitive dependencies are vendored —
**35 MB → 9.6 MB**, 586 Go files across 133 packages. Removed: `client/`
(except `client/ssh/auth`),
`signal/`, `relay/`, `flow/`, `stun/`, `sharedsock/`, `monotime/`, `e2e/`,
`upload-server/`, `agent-network/`, `combined/`, `trustedproxy/`, `tools/`,
CI config, and upstream deployment templates.

Reproduce the prune set against a fresh clone with:

```sh
go list -deps ./management | grep '^github.com/netbirdio/netbird'
```

…but **that set is wrong on its own** — see the third item below. The real set
is its closure over `TestImports` and `XTestImports`, which is 133 packages
rather than 129.

Three things that pruning gets wrong if done naively, all of which broke this
tree before being fixed:

- **`//go:embed` assets.** `idp/dex/web` embeds `static/`, `templates/`,
  `themes/` and `robots.txt`. They contain no Go code, so a package-graph walk
  drops them and the build fails on `pattern themes/*: no matching files`.
  Embed roots must be kept **recursively**.
- **Directories kept only as ancestors.** `client/` is kept solely as a path to
  `client/ssh/auth`, but `client/main.go` imports pruned packages. Ancestor
  directories keep the path and lose their own `.go` files.
- **Test-only packages.** `go list -deps` walks the *build* graph, so
  `encryption/testprotos`, `management/server/mock_server`,
  `management/server/http/testing/testing_tools` and `shared/testing_helpers`
  are invisible to it and get pruned. `go build ./...` still passes; the damage
  only shows under `go vet ./...`, which compiles test files. Upstream's tests
  are how a cherry-picked security fix gets validated, so losing them would
  have quietly removed the main reason to keep this code at all.

- **`testdata/` fixtures.** Found later, and the worst of the four because it
  was invisible to every check in place at the time. `testdata` holds no Go
  code, so the package-graph walk deleted all three directories. `go build`
  passes, and so does `go vet` — **vet compiles test files but never runs
  them**, and a fixture is only read at run time. Upstream's tests were
  therefore uncompilable-clean and unrunnable, which is precisely the failure
  the previous item claims to guard against.

  `management/server/testdata` and `management/server/http/testing/testdata`
  are restored (216 KB). `client/testdata` is not, since `client/` is pruned to
  `client/ssh/auth`.

**Neither `go build` nor `go vet` is sufficient here — upstream tests must
actually be run.** `go test ./management/server/ -run Test_RegisterPeerByUser`
is a cheap smoke test that touches the store fixture and will fail if the
fixtures go missing again.

## The module path is still `github.com/netbirdio/netbird`

Deliberate, and not yet the end state. Renaming it to
`github.com/karst-net/karst/server` is a mechanical rewrite of 393 files, and
it was attempted and reverted: **`github.com/netbirdio/management-integrations`
is an external module that imports this one by its original path**, so renaming
breaks the build until that dependency is also forked or dropped.

The rename is a follow-up, not a blocker. Doing it means deciding what to do
about `management-integrations` first — it is the open-source shim for
enterprise features and is a candidate for dropping outright.

## Licensing

Upstream is **BSD-3-Clause**; `LICENSE-NETBIRD-BSD-3` is retained verbatim and
its notice must stay with any redistribution. `LICENSES/` holds third-party
texts inherited from upstream.

The combined work is **AGPL-3.0-or-later**, distinct from the MIT/Apache-2.0
Rust crates — see [LICENSING.md](../LICENSING.md) and
[ADR-0007](../docs/adr/0007-licensing.md). BSD-3 permits this provided the
notice and disclaimer are retained, which is what the file above is for.
**This arrangement has not had legal review.**

## Persistence

**GORM**, inherited from the fork. `PLAN.md` §4.1 previously specified
`pgx`+`sqlc`; that preference was written for a greenfield build and was
amended on 2026-08-13 — see Spike 0001 §5.5. New Karst tables (PSK schedule,
Bedrock, crypto posture) go through GORM as well; two persistence idioms in one
binary is the outcome nobody chose.

## Running it

```sh
go build -o karst-control ./cmd/karst-control
KARST_POLICY_FILE=policy.json ./karst-control management \
    --config management.json --port 33073 --datadir ./data \
    --log-file console --single-account-mode-domain karst.local
```

`cmd/karst-control` is the fork's daemon with `KarstControlService` attached —
built as a *separate main* so `management/main.go` stays untouched. It logs the
two pins a node must be given at enrolment; handing out only the KEM half
silently downgrades forward secrecy, so both are logged together.

With no `KARST_POLICY_FILE` the packet filter is empty, which is **default
deny**, not unfiltered.

gRPC and HTTP share the port. A minimal SQLite-backed config is enough to get
it up; the store engine is selected with `NB_STORE_ENGINE=sqlite`.

## What Karst has added so far

Everything Karst adds lives under a `karst` path so it is trivially separable
from forked code:

| Path | What |
|---|---|
| `shared/management/proto/karst_control.proto` | Envelope, handshake and `KarstControlService` (ADR-0011). A separate file, so upstream's `management.proto` stays byte-identical to the fork point |
| `management/internals/karst/channel/` | The control-channel handshake and record layer — ML-KEM-768 ×2, HKDF-SHA-512, ChaCha20-Poly1305 |
| `management/internals/karst/identity/` | ML-DSA-65 node identities on `cloudflare/circl` |
| `management/internals/karst/control/` | The gRPC service, node-side client, login/netmap handlers, and OIDC registration |
| `management/internals/karst/node/` | Node handles and the Karst-owned identity table |
| `management/internals/karst/psk/` | Per-pair PSK derivation (§2.6); the key type refuses to print |
| `management/internals/karst/audit/` | Append-only hash-chained activity log |
| `management/internals/karst/policy/` | ACL parser, compiler and reference evaluator (§4.3) |
| `management/internals/karst/bootstrap/` | Server key persistence, PSK epoch, and gRPC registration |
| `cmd/karst-control/` | The Karst daemon: the fork plus `KarstControlService` |

**144 tests**, race-clean. `go test -race ./management/internals/karst/...`.

Most run against narrow fakes of the account manager.
**`TestRegistrationAgainstTheRealAccountManager` does not**: it builds the real
`DefaultAccountManager` over a real SQLite store loaded from upstream's own
fixture, and drives a Karst node through the post-quantum handshake on a real
gRPC connection until a peer row exists. That is the test that proves the
handle actually fits the forked schema rather than merely fitting the
interface.

### How a PQ identity reaches the forked schema

The forked `peers` table keys on a 44-character base64 WireGuard key with a
uniqueness index (`idx_peers_key_unique`). An ML-DSA-65 public key is 1952
bytes — 2604 base64 characters — which is not a sensible index and would force
a change to forked migrations.

So a node's **handle** is `base64(SHA-256("karst-node-handle-v1" ‖ identity_pk))`:
exactly 44 characters, dropping into the existing column and index unchanged.
The full identity key lives in `karst_node_identities`, a Karst-owned table,
because verifying a signature on reconnect needs the real key and the peer row
has nowhere to put 1952 bytes.

This is the same shape as ADR-0005's `peer_id_hint` — a hash of a public key
used as a lookup handle rather than as key material — with its own domain
label so the two constructions cannot collide.

### The fork has not been edited

**No forked `.go` file has been modified.** Diffing this tree against the
pruned fork shows exactly two changed files — `go.mod` and `go.sum` — plus
Karst's additions.

That is not an accident, and it is worth preserving. Spike 0001 §5.3 measured
**28% of upstream commits** landing on the files we would otherwise diverge on;
every line changed there is a future cherry-pick conflict on a security fix.
Two choices bought it:

- **A parallel service, not a rewrite.** `KarstControlService` sits alongside
  `ManagementService` rather than replacing `parseRequest` inside it.
- **Reusing the business layer as-is.** Spike 0001 §5.2a found the identity
  fusion is confined to the gRPC layer: below it, `LoginPeer`,
  `GetAccountIDForPeerKey` and the login filter all take the peer handle as a
  plain `string` and never perform a key operation on it. So Karst passes its
  own handle into the same calls.

One consequence to be honest about: `types.PeerLogin.WireGuardPubKey` will
carry a Karst node handle, which makes the field name a lie. Renaming it is a
forked-code change and therefore a cherry-pick cost; it is deferred
deliberately, not overlooked.

`go.mod` also lost a stale `replace` pinning `cloudflare/circl` to a 2023
codeberg fork predating FIPS 204, and `go mod tidy` after the prune took
`go.mod` from 341 to 241 lines and `go.sum` from 943 to 677.

## The work ahead

The PQ identity refactor. Spike 0001 §5.2a measured it against the compiler:
making the peer identity opaque breaks 44 sites, of which a one-line `String()`
method fixes 32, leaving **5 genuine crypto sites in 2 files** — `encryptResponse`
×3 and `encryption.EncryptMessage` ×2, all on the NaCl-box path, all reached
through `parseRequest`. That function is the chokepoint: it parses `wgPubKey`,
opens the body with it, and hands callers an identity handle. Replacing it is
the first real Phase 3 task.
