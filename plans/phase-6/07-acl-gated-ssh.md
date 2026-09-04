# ACL-gated SSH

**PLAN.md Phase 6, workstream 7 · W6–W7 · Go 2.**

This is the detailed plan behind [00-overview.md](00-overview.md) §2 item 7. It
is a re-baseline against the tree on 2026-09-04. §1 below corrects a claim in
the overview's own re-baseline table (§1's row for this workstream, and its
line "the `\"ssh\"` HuJSON block is still a parsed no-op") against what the
current `policy` package actually does with that key.

## 1. What already exists, and one correction to the overview

PLAN.md §4.3's schema sketch shows `"ssh": [ /* Phase 6 */ ]` as a sibling of
`"acls"` in the Tailscale-shaped policy document, and describes the compiler
as turning the whole document into "a per-node packet filter shipped in the
netmap and enforced in the Rust datapath on both ingress and egress."

The overview's re-baseline table (§1) and workstream table (§2 item 7) both
describe the `"ssh"` block as "a parsed no-op." That is not what the code
does today. `server/management/internals/karst/policy/policy.go`'s
`Document.Parse` decodes with `json.Decoder.DisallowUnknownFields()`
(policy.go:88), so a document containing an `"ssh"` key is rejected outright
by `ValidateDocument` / `Store.Write`
(`server/management/internals/karst/policy/store.go:104,112`) — a `400`, not
silent acceptance. There is no dead field anywhere in `Document`, `Rule`, or
the compiled `Filter`/`EgressFilter` types that decodes an `"ssh"` array and
drops it. This workstream is not "wire up a field that already round-trips";
it is genuinely greenfield from the schema down. Correct the overview's table
when this plan lands (§8 below has the exact edit).

What Karst does have, and what this workstream builds on rather than
replaces:

| Layer | Present now | What this workstream adds |
|---|---|---|
| Policy document | `Document{Groups, TagOwners, ACLs}` (policy.go:45); `ACLs` is accept-only, `src`→`dst:ports`, evaluated against `group:`/`tag:`/user/handle selectors (`matches`, policy.go:432) | An `Ssh []SshRule` field with the same selector vocabulary, its own validation, and its own compiled output |
| Compilation | `Document.Compile` → `Filter` (ingress) and `Document.CompileEgress` → `EgressFilter`, both normalized for a stable netmap-version hash (policy.go:281,347,489) | `Document.CompileSSH` → a third compiled artifact, keyed by destination node the same way `Filter` is |
| Netmap wire | `KarstFilterRule`/`KarstEgressRule` (`karst_control.proto:449,458`), attached to `KarstNetmapResponse` as `packet_filter`/`egress_filter` fields 9/12, content-hashed in `writeField` (`netmap.go:723-738`) | A third field, `ssh_filter`, same message shape, hashed alongside the other two |
| Datapath enforcement | `bins/karstd/src/filter.rs`'s `PacketFilter` compiles `KarstFilterRule`/`KarstEgressRule` into `Rule`s keyed by `PeerIndex`, evaluated per packet in `ingress()`/`egress()` (filter.rs:186-218) | An independent `SshFilter` evaluated once per new TCP flow to port 22, ANDed with the existing ingress `Filter`, not folded into it |
| Console | `web/console/src/views/access.tsx` — a raw-JSON policy editor with server-side `validate`/`preview`/`test`/`save`, optimistic-concurrency versioning, and a version history list (access.tsx:1-104). No structured ACL authoring exists yet; routes' structured editor from workstream 6 §5 W6 is the only precedent | Diagnostics, preview, and test-result rendering that understand `ssh` rules as their own kind, not raw JSON the operator has to parse by eye; a v1 that stays in the same raw-document editor rather than a new structured surface (§3.5) |

## 2. Outcome and scope

An administrator writes an `"ssh"` block naming which identities may open an
SSH connection to which destinations. A connection whose network path is
otherwise permitted by `"acls"` is still refused at the destination node if no
`"ssh"` rule grants it — reachability and shell authorization are independent
gates, evaluated by the same node, from the same netmap, at connection time.

In scope:

- an `"ssh"` policy block using the same `group:`/`tag:`/user/handle selector
  vocabulary as `"acls"`, `action: "accept"` only;
- destination-node compilation and netmap delivery of the compiled SSH grant,
  content-hashed into the existing netmap-version mechanism;
- enforcement in `karstd` at new-flow admission to TCP/22 on the overlay
  interface, independent of and in addition to the general ingress filter;
- `karst policy test` and the console's existing validate/preview/test/save
  flow extended to explain `ssh` rules;
- `karst status` and the diagnostics bundle reporting whether SSH policy is
  enforced and how many rules apply, mirroring `PacketFilter::is_enforcing`
  and `rule_counts` (filter.rs:229,235).

Out of scope for this pass, named explicitly so they are decisions rather
than gaps found later:

- **No `"check"` action.** Tailscale's SSH policy re-authenticates a session
  after a TTL via a browser challenge. Karst has no session-recheck channel
  today, and building one is a project on its own, not a two-week addition to
  this one. `"ssh"` rules support `action: "accept"` only, matching `"acls"`'
  own accept-only stance (policy.go:52's comment on why a deny form is absent
  applies here for the same reason).
- **No `"users"` field / local-user mapping.** Tailscale SSH's rule can
  restrict which Unix user the connection may authenticate as. Karst's SSH
  gate answers "may this identity reach this node's SSH port at all," not
  "as which local account" — that remains OpenSSH's own `AllowUsers`/PAM
  configuration on the destination host, unmodified by Karst.
  `GETTING-STARTED.md` gets a line saying so (§7 below).
- **No session recording, no proxying, no certificate issuance.** `karstd`
  does not intercept the SSH byte stream, does not run an SSH server itself,
  and does not touch host `sshd` configuration. It answers one yes/no
  question — does this flow get to open a TCP connection to port 22 — before
  the kernel's own accept() ever returns to `sshd`. Genuine identity-bound
  SSH certificates (replacing host/user keypairs entirely) are a distinct,
  larger feature and not implied by "ACL-gated."
- **No non-22 SSH ports.** `sshd` listening elsewhere is out of scope for v1;
  §3.3 covers why this is a deliberate simplification and not an oversight.

## 3. Decisions to lock before implementation

### 3.1 A second, independent gate — not a rewrite of `"acls"` semantics

`"ssh"` rules do not replace or override `"acls"` rules on port 22; both must
grant the flow. This is why `PacketFilter` gets a third, separately-evaluated
rule set rather than folding SSH grants into the existing ingress `Filter`:
an operator who already writes `{"action":"accept","src":["group:eng"],
"dst":["tag:prod:22"]}` for general reachability (e.g. so a jump host's health
checks can reach port 22) should not have that rule silently start granting
interactive shell access the moment this feature ships. Combining the checks
requires two `"accept"`s, one from each block, which is the entire point of a
named "ACL-gated SSH" feature distinct from "another `acls` port rule."

### 3.2 Absent `"ssh"` key means "no additional gate," not "deny all SSH"

An account with no `"ssh"` block in its policy document keeps today's
behavior exactly: SSH reachability is governed by `"acls"` alone, unaffected
by anything in this workstream. This is a deliberate backward-compatibility
choice, matching `PacketFilter::unrestricted()`'s existing precedent for "no
policy source at all" (filter.rs:154) — an *absent* SSH block and an SSH block
that grants nothing must not compile to the same enforcement outcome, for the
identical reason the module's own doc comment gives for ingress/egress
filters (filter.rs §"Empty is deny"): the difference between "this feature
was never turned on" and "this feature was turned on and denies everything"
has to be visible in behavior, or a typo that empties the block silently
becomes a lockout indistinguishable from "I haven't adopted this yet." An
account that writes `"ssh": []` gets deny-all-SSH-beyond-acls immediately;
one that omits the key entirely is unaffected. `karst status` must report
which of the three states (`absent` / `enforcing, N rules` / `enforcing,
zero rules`) applies, the same three-way distinction `PacketFilter`'s own
`Debug` impl already makes for ingress/egress (filter.rs:139-146).

### 3.3 Port 22 only, no configurable port field, for this pass

Real deployments run `sshd` on non-standard ports. Making the SSH gate
port-aware would require either a new selector grammar (`dst:
["tag:prod:2222"]` inside the `ssh` block, duplicating `"acls"`' own port
syntax) or a global per-account SSH-port setting. Both are reasonable
follow-ups; neither is required to make the phase's stated exit line true
("the `\"ssh\"` block is enforced, not parsed and ignored"), and guessing
wrong on the grammar now is more expensive than shipping the fixed-port
version and widening it once someone needs it — the same reasoning `"acls"`'
own accept-only stance uses. File the follow-up as a GitHub issue at
implementation time rather than silently deferring it.

### 3.4 Enforcement point: new-flow admission, not per-packet

The general ingress `Filter` is evaluated on every packet (filter.rs:186's
`ingress()`, called from the datapath's per-packet path). Re-running a rule
match per packet for SSH would work but is the wrong altitude: SSH is a
single long-lived TCP stream, and the decision that matters is "may this flow
begin." `SshFilter` is evaluated once, at the point `karstd` observes a new
inbound flow to local port 22 — the same place `bins/karstd/src/flow.rs`
already tracks flow state for connection-tracking purposes (referenced by
filter.rs's module doc as the reason `Direction` lives where it does). A
flow admitted at open time is not re-checked mid-stream; a policy change that
revokes access takes effect on the *next* connection attempt, not by tearing
down one already open — consistent with how a route or ACL change today
reaches a node only through the next netmap push, not a live mid-flow
teardown. State this plainly in the docs rather than let it be discovered.

### 3.5 The console stays in the raw-document editor for this pass

`access.tsx`'s textarea-plus-validate/preview/test/save loop already handles
arbitrary policy documents, `"ssh"` included, once the server accepts the
key. Workstream 6 built a structured, group-picker-backed editor for routes
because raw comma-separated group IDs were an existing, already-shipped UX
problem being fixed. No `"ssh"`-specific structured editor exists to replace,
and building one from scratch in a 2-week, one-engineer workstream competes
directly with getting enforcement itself right. Scope the console work to:
extending `validate`'s diagnostics, `preview`'s added/removed-flow rendering,
and `test`'s pass/fail output to describe `ssh` rules by name rather than
leaving them invisible to those three tools while every `acls` rule is
explained. A structured SSH-rule editor is a reasonable follow-up once the
raw-editor version has real users to learn from, the same posture 06's plan
takes toward its own out-of-scope items.

## 4. Wire and data model

### 4.1 Document and validation (Go, `policy.go`)

```go
// SshRule is one accept entry gating interactive SSH access, independent of
// "acls"' general reachability grants (§3.1).
type SshRule struct {
    Action string   `json:"action"` // "accept" only, for now (§2)
    Src    []string `json:"src"`
    Dst    []string `json:"dst"`   // node/tag/group selectors, no ports (§3.3)
}
```

Add `Ssh []SshRule` to `Document`. `Validate` gains: `action` must be
`"accept"`; `src`/`dst` non-empty; every `dst` selector must resolve as a
node/tag selector with **no trailing `:port`** (the opposite constraint from
`"acls"`' `splitDst`, since the port is implicit) — reject a `dst` containing
`:` immediately with an error naming §3.3's fixed-port design, so an operator
who copies an `"acls"`-style `"tag:prod:22"` entry into `"ssh"` gets a precise
rejection instead of a confusing selector-not-found error; the same undefined-
group check `"acls"` already runs (policy.go:150-159).

### 4.2 Compilation

```go
// CompileSSH produces the SSH-gate rules for one node, mirroring Compile
// (§3.1: evaluated independently, never merged with the general Filter).
func (d *Document) CompileSSH(target Node, all []Node) (*Filter, error)
```

Reuses the existing `Filter`/`FilterRule` types — the shape (`srcs` + `ports`)
is identical, with `ports` always compiling to the single range `{22, 22}`
rather than whatever the (absent) `"ssh"` port spec would have said. This
keeps one wire message type instead of inventing a parallel one, at the cost
of a field that is always the same value; documented, not left implicit, in
`karst_control.proto`'s comment on the new field (§4.3). `nil` `Ssh` (key
absent, §3.2) compiles to `nil *Filter`, distinct from `Ssh: []` compiling to
an empty, deny-all `*Filter{}` — the same `nil`-vs-empty distinction
`compileFilter` already threads through today for the case of no policy
loaded at all (`netmap.go:523`).

### 4.3 Netmap wire

```protobuf
// The independent SSH-access gate for this node (plans/phase-6/07 §3.1).
// Absent means "no ssh block in policy" (§3.2) — the general packet_filter
// governs port 22 alone in that case. Present-but-empty means deny-all SSH
// beyond packet_filter. Reuses KarstFilterRule; `ports` is always {22, 22}.
repeated KarstFilterRule ssh_filter = 17;
optional bool ssh_filter_present = 18; // disambiguates nil vs. empty (§3.2)
```

Field 17/18 pending an actual free-number check against
`karst_control.proto` at implementation time — the overview's workstream 5
table shows field 16 already taken by `KarstTurnServer`, so 17 is the next
free slot as of this plan's writing, not a number to trust without
re-checking. `compileFilter` (netmap.go:506) gains the third compilation call
and both new fields; `writeField`'s content-hash walk (netmap.go:723-738)
gains a `karst-ssh-filter` section covering both the rules and the presence
flag, so a policy edit that only touches the `"ssh"` block still changes
`netmap_version` and triggers a push — the same requirement 06's plan states
for route changes (06's §3.4 last bullet) and for the identical reason.

Update together: `spec/karst-control-v1.md`, `karst_control.proto` and
generated bindings (Go + Rust), `spec/vectors/karst-control-v1.json` with
accepted and rejected SSH-rule cases (undefined group, malformed `dst` with a
port suffix, empty `src`).

### 4.4 Datapath (`bins/karstd/src/filter.rs`)

```rust
/// The independent SSH-access gate (plans/phase-6/07 §3.1). `None` means no
/// "ssh" block in policy (§3.2) — SSH reachability is governed by the
/// ingress `Filter` alone. `Some(rules)` with an empty `rules` is deny-all.
pub struct SshFilter(Option<Vec<Rule>>);

impl SshFilter {
    pub fn compile(rules: &[pb::KarstFilterRule], present: bool, handles: &[Vec<u8>]) -> Self { .. }

    /// Called once per new inbound flow to local port 22 (§3.4), never per
    /// packet. `Verdict::Unclassifiable` cannot occur here — flow admission
    /// runs after TCP state already identifies the destination port.
    pub fn admit(&self, from: PeerIndex) -> Verdict { .. }
}
```

Wired at the flow-admission point already tracked for connection-tracking
(the module this plan does not yet have a confirmed file/line for — locate
`bins/karstd/src/flow.rs`'s new-flow hook during W6 implementation and cite
it precisely in the PR, rather than in this plan). The check is: `filter.rs`'s
existing `ingress()` `Filter` **and** (if `SshFilter` is `Some`) `SshFilter`'s
`admit()` must both permit; either denying denies the flow. `PacketFilter`
gains an `ssh: SshFilter` field alongside `ingress`/`egress`, and
`is_enforcing`/`rule_counts` (filter.rs:229-236) gain SSH-aware variants for
`karst status`.

## 5. Implementation sequence

### W6 — schema, compilation, netmap wire (Go 2)

1. Table-driven tests first, mirroring 06's W4 §5.1 pattern: valid accept
   rule, undefined group reference, `dst` with a trailing port (rejected per
   §4.1), empty `src`/`dst`, `"ssh"` absent vs. `"ssh": []` compiling to
   distinguishable `nil`/`present-empty` states, multiple rules across
   `group:`/`tag:`/handle selectors.
2. Add `SshRule`, `Document.Ssh`, validation, and `CompileSSH` to
   `policy.go`, reusing `Filter`/`normalize` (§4.2).
3. Confirm the next free proto field numbers against the tree (§4.3's caveat)
   and add `ssh_filter`/`ssh_filter_present`; regenerate Go bindings.
4. Wire `compileFilter` (netmap.go:506) to call `CompileSSH` and populate the
   two new response fields; extend the content-hash walk (netmap.go:723).
5. Extend `karst policy test`'s reference evaluator and the console's
   `validate`/`preview`/`test` endpoints to describe `ssh` rules by name
   (§3.5) — a `preview` diff should say "SSH access granted: eng → prod
   fleet," not lump it silently into the generic ACL diff or omit it.

### W7 — datapath enforcement, `karst status`, documentation (Go 2)

1. Add `SshFilter` and the flow-admission hook to `karstd` (§4.4); regenerate
   Rust bindings; property/unit tests for the compiled-rule evaluator
   mirroring `PacketFilter`'s own existing test module.
2. Namespace or aquifer-topology integration test: two nodes, an `"ssh"` rule
   granting one src and not another, confirm the granted node's `ssh
   -o ConnectTimeout=5 <target>` reaches a TCP handshake and the ungranted
   node's times out — not merely that the compiled `Filter` object says
   `Denied` in a unit test.
3. `karst status` and the diagnostics bundle report the three-way SSH-gate
   state (§3.2) and rule count.
4. GETTING-STARTED.md / operations doc gets the `"ssh"` block's syntax,
   the port-22-only and no-`"check"`/no-user-mapping limitations (§2), and
   the "absent means unaffected, empty means deny-all" distinction (§3.2)
   stated as plainly as this plan states it — an operator reading only the
   docs, not this plan, needs to reach the same understanding.
5. Update `spec/karst-control-v1.md` and shared vectors; run the exit
   demonstration (§6) against a deployment built from published artifacts,
   not a workspace binary, matching 06's own W7 §5 and 04-pentest.md's
   standing precedent for this phase.

## 6. Security and correctness tests

- A destination node whose `"acls"` permit port 22 from a source, but whose
  `"ssh"` block does not name that source, refuses the SSH connection.
- A destination node whose `"ssh"` block names a source, but whose `"acls"`
  do not permit port 22 from that source, refuses the connection — the
  packet never reaches the SSH-gate check at all, because the general
  ingress filter denies it first.
- `"ssh"` absent from the document: SSH behaves exactly as `"acls"` alone
  would dictate, verified by a test that removes the block from an otherwise
  identical document and confirms no behavior change.
- `"ssh": []`: every SSH connection is refused regardless of `"acls"`.
- A group referenced in an `"ssh"` rule but not defined in `"groups"` is
  rejected at `ValidateDocument`/`Store.Write` time, not silently compiled to
  an empty grant.
- A `dst` selector with a trailing port (`"tag:prod:22"`) inside `"ssh"` is
  rejected with an error naming the fixed-port design (§3.3), not a generic
  parse failure.
- Removing a node from the granting group, or deleting the `"ssh"` rule,
  changes `netmap_version` and the next connection attempt (not an
  already-open one, per §3.4) is refused.
- A non-SSH flow to port 22 (there is no such thing at the TCP layer, but a
  crafted packet claiming source port 22 while destined elsewhere) does not
  spuriously trigger the SSH gate — the check keys on *destination* port only,
  confirmed by a test with a peer's SYN carrying an arbitrary source port.
- Fuzzed/malformed `KarstFilterRule` values on the wire (out-of-range ports,
  empty `srcs`) added to the shared rejected-vector suite, matching 06's own
  requirement for its route messages.

## 7. Exit demonstration

From a deployment installed from published packages, not a workspace build:

1. Enroll two client nodes and one node running `sshd`.
2. Write a policy with `"acls"` permitting both clients to reach the `sshd`
   node on port 22, and an `"ssh"` block granting only one of them.
3. Show the granted client's `ssh` reaching a login prompt and the denied
   client's connection attempt timing out at the TCP layer (no RST, no
   application-layer rejection — the flow is never admitted).
4. Edit the policy to grant the second client and revoke the first; show the
   change take effect on each client's *next* connection attempt after the
   netmap push, per §3.4, without restarting either `karstd`.
5. Remove the `"ssh"` block entirely; show both clients regain access,
   governed by `"acls"` alone, matching pre-workstream behavior exactly.
6. Run this from the console's existing `access.tsx` editor for the policy
   edits in steps 2 and 4 — `validate`, `preview`, and `test` all correctly
   describe the `ssh` rule's effect before `save` is clicked.

Evidence retained with the phase gate: the three policy documents used, the
console's preview/test output for each, `karst status` output showing the
SSH-gate state on each node, and a packet capture or `karst bugreport`
excerpt showing the denied client's connection never reaching a TCP
handshake.

## 8. Definition of done

- The Phase 6 exit line is demonstrably true: the `"ssh"` block is enforced,
  not parsed and ignored — and, per §1's correction, no longer *rejected* by
  `DisallowUnknownFields` either.
- `"acls"` and `"ssh"` are independent gates; neither can be satisfied by the
  other, verified by the two negative cases in §6's first two bullets.
- Absent-vs-empty `"ssh"` compiles to observably different enforcement,
  verified by §6's third and fourth bullets and reported distinctly by
  `karst status`.
- The namespace/aquifer integration test in §5 W7 step 2 passes in CI, using
  a real TCP handshake attempt, not only the Go/Rust unit-level compiled
  evaluators.
- Documentation states the port-22-only, no-`"check"`, no-user-mapping scope
  boundaries as explicitly as §2 does, so an operator relying only on
  published docs reaches the same understanding this plan does.
- Shared accepted/rejected vectors cover `"ssh"` parsing and compilation in
  both languages; `go test ./management/internals/karst/policy/...` and the
  new `bins/karstd` filter/flow tests both pass.
- `plans/phase-6/00-overview.md`'s §1 table and §2 item 7 row are corrected
  to drop "parsed no-op" (§1's finding) once this lands, and its status
  updated to reflect what actually shipped — the same discipline the
  overview already applies to every other completed workstream.
- Any discovered high/critical security finding (e.g., a flow-admission
  bypass, or a state where an `"ssh"` rule appears to apply but does not) is
  fixed and re-tested before the public beta gate, per PLAN.md's standing
  rule for every workstream in this phase.
