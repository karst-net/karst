# Observability

**PLAN.md Phase 6, workstream 8 · W4–W7 · SRE + Rust 3.**

This is the detailed plan behind [00-overview.md](00-overview.md) §2 item 8. It
is a re-baseline against the tree on 2026-09-04. The server already has a
working Prometheus/OTel-metrics pipeline with an established per-domain file
convention; nothing under `internals/karst/` uses it. `karstd` has no metrics,
no tracing, and no structured logging at all — it writes to stdout/stderr with
bare `println!`/`eprintln!`. `karst bugreport` is further along than the
overview's short description suggests: it already reports host, interface,
crypto/PSK, policy, routing, and Bedrock sections, built from real engine
state (`bins/karstd/src/run.rs::bug_report`). This is therefore two workstreams
of uneven size wearing one name: extending an existing, idiomatic Go metrics
pipeline into Karst's own objects, and building a client-side metrics/tracing
surface on `karstd` that does not exist in any form today.

## 1. Outcome and scope

An operator scrapes `/metrics` on `karst-control` and sees Karst-specific
gauges and histograms (Bedrock chain depth, PSK epoch age, relay-registry
size, netmap-push latency) alongside the inherited NetBird metrics, using the
same naming and registration idiom those already follow. A `karstd` node
exposes an equivalent, minimal metrics surface — reachable without opening any
new network-facing port by default — covering handshake/session counts,
datapath drop reasons already tracked in `Engine::Stats`, and route/gateway
state already surfaced in `bug_report`. A small number of OTel trace spans
cover the request paths that are actually opaque today (netmap compute+push,
Bedrock anchor scheduling, control-session handshake), not a blanket
instrumentation pass. `karst bugreport` gains the sections named by the phase
line ("per-node diagnostics bundle") that it does not have yet, while keeping
the redaction discipline the existing sections already established (no PSKs,
no private keys, no setup keys — every new field is checked against that rule
before it is added).

In scope:

- four new Karst-aware Prometheus metrics on the Go server: Bedrock chain
  depth, PSK epoch age, relay-registry size, netmap-push latency;
- OTel trace spans on the three request paths named above, exported through
  the exporter the server already imports;
- a `karstd`-side metrics surface (counters/gauges drawn from `Engine::Stats`
  and route/gateway state) with a decided transport (§3.1);
- structured logging on `karstd` sufficient to correlate a metric spike with a
  log line (§3.2) — today there is neither;
- broadening `karst bugreport` with the sections it is still missing relative
  to server-side state a support request would need (Bedrock chain
  divergence detail beyond the peer-agreement counts already there,
  relay/TURN reachability, control-channel session health);
- documentation: what each metric means, its labels, and a Grafana/PromQL
  starter query for the four new server metrics and the netmap-push latency
  measurement item 0.1 needed a durable number for.

Out of scope:

- OTel traces on every request path — only the three named above;
- a hosted or bundled Grafana/Alertmanager deployment — this workstream
  exports metrics and documents queries against them, it does not ship a
  dashboard-as-code artifact (that is HA's or documentation's call, not
  observability's);
- client-side crash reporting or telemetry phone-home — `karstd` metrics are
  pull-based and local-only by default, never sent anywhere without an
  operator wiring up their own scrape target;
- changing what `karst bugreport` already reports correctly — only adding
  what is missing.

## 2. What already exists

| Layer | Present now | Gap this workstream closes |
|---|---|---|
| Server metrics plumbing | `server/management/server/telemetry/`: eleven `*_metrics.go` files, all following one idiom — a struct of `metric.Int64Histogram`/`Int64Counter` fields built in a `New*Metrics(ctx, meter)` constructor, named `management.<domain>.<name>.<unit>`, backed by `go.opentelemetry.io/otel/exporters/prometheus` wired in `app_metrics.go`'s `NewDefaultAppMetrics` and exposed over HTTP by `defaultAppMetrics.Expose` | Nothing under `internals/karst/` calls any of this — zero references to `AppMetrics`, `Meter()`, or any `New*Metrics` pattern anywhere in `bedrock/`, `relayreg/`, `psk/`, `control/`, `roster/` |
| Server tracing | `go.opentelemetry.io/otel` (trace API) is an indirect dependency of the metrics exporter; `grep -rn "otel.Tracer\|StartSpan"` across `server/` returns nothing | No tracer provider is constructed, no exporter for traces (only the metrics exporter) is wired, and no span exists anywhere |
| Client metrics | None. No `prometheus`, `metrics`, or `opentelemetry` crate anywhere in `Cargo.toml` across `crates/` or `bins/` | Everything: choice of surface (§3.1), the metrics themselves, wiring into `Engine::Stats` |
| Client logging | None. `bins/karstd/src/run.rs` uses `println!`/`eprintln!` directly (45 call sites); no `log` or `tracing` crate dependency exists | A structured logging baseline, so a metric anomaly can be correlated to a log line with matching fields, not just a raw stdout string |
| `karst bugreport` | Real and substantially built out: `bug_report` (`run.rs:3731`) reports `[karst]` (version/uptime), `[host]`, `[interface]`, `[crypto]` (PSK epoch, lattice-only peer count), `[policy]` (rule counts), `[skipped]` peers, `[bedrock]` (peer agreement/equivocation counts, via `write_bedrock`, `run.rs:4945`), `[stats]` (`Engine::Stats`: tx/rx, unroutable, source violations, MAC failures, ACL denials, relay-dropped), and a `[[peer]]` table per connected peer. Driven over the `karst-cli`/`ipc.rs` `Command::BugReport` verb (`bins/karst-cli/src/main.rs:26`, `bins/karstd/src/ipc.rs:53`) | No control-channel session health (last successful push, time since last netmap update, TLS-vs-plaintext transport per §8 of `04-pentest.md`), no per-relay/TURN candidate reachability detail beyond the aggregate `relay_dropped` counter, no Bedrock detail beyond the two counts already there (no chain depth, no time since last anchor) |
| Underlying counters to build on | `Engine::Stats` already tracks `tx_packets`, `rx_packets`, `unroutable`, `source_violations`, `mac_failures`, `tx_dropped_no_session`, `malformed`, `decrypt_failures`, `acl_denied_in/out/unclassifiable`, `bedrock_equivocation`, `bedrock_head_agreed`; `config.route_offers`/`gateway_active` are already surfaced by `routing_report` (`run.rs:2999`) | These are read once per `bugreport`/`status` call today, not exported continuously as Prometheus counters — the values exist, the export path does not |

The important asymmetry, same shape as workstream 6's: the Go side has a
correct, idiomatic pattern with real subscribers (Grafana users of the
inherited NetBird metrics today) and zero Karst-specific adoption; the Rust
side has zero infrastructure of any kind. Treat them as two separate efforts
with different starting costs, not one uniform "add metrics" task.

## 3. Decisions to lock before implementation

### 3.1 `karstd`'s metrics transport: IPC verb first, opt-in HTTP listener second

`karstd` already has a private, root-owned Unix-socket IPC channel
(`bins/karstd/src/ipc.rs`) with a small closed `Command` enum (`Status`,
`BugReport`, …) that `karst-cli` drives. Do not give `karstd` a new
always-on network listener by default — THREAT-MODEL's existing posture for
this daemon is that its only network-facing surface is the control channel
and the datapath socket, both already justified; a bare Prometheus `/metrics`
HTTP endpoint bound by default would be a new unauthenticated network surface
this workstream did not need to open.

Two-tier design:

1. Add `Command::Metrics` to the IPC enum, returning Prometheus text-exposition
   format over the existing local socket — the same access-control boundary
   `Status`/`BugReport` already have (local, root-owned socket; see
   `ipc.rs`'s own doc comment on `BugReport`'s process-local trust boundary).
   `karst metrics` (new `karst-cli` subcommand, same pattern as `karst status`)
   prints it directly, so a node-exporter `textfile` collector or a cron job
   can capture it with no new listener at all.
2. A config-gated `[metrics] listen = "127.0.0.1:PORT"` (default: unset,
   feature off) starts a minimal loopback-only HTTP server exposing the same
   text under `/metrics`, for operators who want a normal Prometheus scrape
   target instead of a textfile collector. Loopback-only is enforced in code,
   not just documented — reject a configured non-loopback bind address at
   startup rather than silently listening on it.

This mirrors the same consent posture §3.2 of
[06-subnet-routers-and-exit-nodes.md](06-subnet-routers-and-exit-nodes.md)
established for default routes: a capability that changes what the node
exposes needs an explicit opt-in, not a default-on flip.

### 3.2 Minimal structured logging, not a full tracing migration

Introduce the `tracing` crate (not `log` + `env_logger`) as `karstd`'s logging
baseline, because `tracing`'s span/event model is the same one the OTel Rust
SDK consumes, so §3.3's future client-side trace export (if ever pursued) does
not require a second migration. Scope for this workstream is narrow:

- replace the `println!`/`eprintln!` call sites that log operationally
  relevant events (handshake failures, Bedrock equivocation, route/gateway
  state transitions, session establishment/loss) with `tracing::{info,warn,
  error}!` calls carrying structured fields (peer hint, route ID, error kind);
  leave purely user-facing CLI output (e.g. `bugreport`'s own returned string)
  exactly as it is — it is a report body, not a log line;
- wire a `tracing-subscriber` with an env-filter default matching the current
  default verbosity, so this is a transport change for existing messages, not
  a behavior change an operator would need to react to;
- do not migrate every `println!` in one pass — prioritize the call sites
  §5's W4 work needs correlated with the new metrics (handshake/session,
  Bedrock, routing) and leave the rest for a follow-up, tracked as a numbered
  GitHub issue rather than silently left half-done.

### 3.3 No client-side distributed tracing this phase

Server-side spans (§3.4) export through the OTel trace API already present as
an indirect dependency; client-side spans would need a second exporter, a
second collector endpoint, and a decision about whether `karstd` may ever
originate outbound telemetry traffic at all — a bigger question than this
workstream's budget covers. `tracing`'s span model (§3.2) is chosen
specifically so that decision is deferred without foreclosing it, not made by
omission.

### 3.4 Three server-side trace spans, chosen by what is actually opaque today

Not "add tracing everywhere." The overview's own complaint is that
netmap-push latency has no number (item 0.1 needed one and had to measure it
by hand); the anchor scheduler's `AnchorDue`→sign→import pipeline
(`bedrock/scheduler.go`) crosses a DB write, a signing call, and an import,
with no visibility into which leg is slow if it ever is; the control-session
handshake (`control/service.go::Session`) is the one path every node depends
on and currently has no span at all, only log lines on failure. Three spans:

1. `karst.netmap.push` — from the update-manager fan-out entry
   (`s.updates.CreateNotificationChannel`/the goroutine reading `updates` in
   `control/service.go`) through the `ch.Seal`+`stream.Send` pair under
   `KindPush` (service.go:373-380), giving the number item 0.1 had to compute
   ad hoc as a first-class, continuously exported measurement instead.
2. `karst.bedrock.anchor_cycle` — one span per `Scheduler.Tick` call
   (`bedrock/scheduler.go:95`) covering the `AnchorDue` check, `CreatePending`,
   signing, and `CommitPending`/import, with child spans at each of those four
   steps so a slow anchor cycle is diagnosable without reading the scheduler's
   source.
3. `karst.control.session_handshake` — from `Service.Session`'s entry
   (`control/service.go:153`) through the point the session is registered
   with the update manager, covering channel-envelope verification and the
   `s.peers.GetPeerByPeerPubKey` lookup — the leg §9 of `04-pentest.md`
   already showed produces no log line at all on a *successful* duplicate
   registration, which a span makes visible even without the eviction fix's
   own logging.

## 4. Metrics: names, kinds, and labels

Follow the existing `management.<domain>.<name>.<unit>` convention exactly
(§2's table). All four are constructed the same way `NewStoreMetrics` is
(`telemetry/store_metrics.go:21`): a `New*Metrics(ctx, meter)` constructor
returning an error, wired into `AppMetrics` alongside the other eleven.

| Metric | Kind | Labels | Source |
|---|---|---|---|
| `management.karst.bedrock.chain.depth` | `Int64ObservableGauge` (or `Int64Gauge` recorded on write) | `account_id` | `bedrock.Log.Head`/`State` (`logstore.go:226`,`:243`) — the head sequence number, recorded on every `CommitPending`/`Import` |
| `management.karst.bedrock.anchor.age.seconds` | `Int64ObservableGauge` | `account_id` | time since the last successful anchor cycle; the scheduler already computes `lastAnchoredAt` (`scheduler.go:125`) — export it instead of only comparing it against `MaxAge` internally |
| `management.karst.psk.epoch.age.seconds` | `Int64ObservableGauge` | `account_id` | time since the roster's `Epoch` (`netmap.go:329`'s `h.Epoch`) last advanced — this needs a last-bump timestamp added where the epoch is incremented (see §5 W4 item 2 for exactly where), since only the epoch's current value is tracked today, not when it changed |
| `management.karst.relay.registry.size` | `Int64ObservableGauge` | `account_id` | `relayreg.Store.List` (`store.go:98`) count, recorded on every registry mutation (`Create`/`Delete`) rather than polled, to avoid adding a DB read to the hot path just for metrics |
| `management.karst.netmap.push.duration.ms` | `Int64Histogram` | `trigger` (`peer_status`, `route_change`, `policy_change`, `bedrock_anchor` — whatever the update manager's own event already distinguishes; fall back to `unknown` rather than inventing a taxonomy the update manager doesn't have) | measured around the `karst.netmap.push` span's own boundaries (§3.4 item 1) |

Use `ObservableGauge` (a callback registered once, read by the exporter on
scrape) rather than a `Gauge` updated on a timer wherever the underlying value
is already held in a store or in-memory field the callback can read directly
— this avoids a periodic background goroutine purely to keep a gauge fresh,
matching the pattern `store_metrics.go`'s histograms already use for
push-style recording versus what a gauge needs for pull-style reads.

## 5. Implementation sequence

### W4 — server metrics plumbing (SRE)

1. Add `KarstMetrics` to `server/management/server/telemetry/`, one new file
   per the existing one-file-per-domain convention (e.g.
   `karst_bedrock_metrics.go`, `karst_relay_metrics.go`, or one
   `karst_metrics.go` grouping all four — match whichever the eleven existing
   files' own domain boundaries suggest is more consistent; `store_metrics.go`
   groups multiple related histograms in one file, so one file for all four
   is defensible and keeps the wiring in one place).
2. Wire `KarstMetrics` into `AppMetrics`/`defaultAppMetrics` the same way
   `StoreMetrics` etc. already are, and thread a reference into
   `internals/karst/bedrock`, `relayreg`, and `control` package
   constructors — these packages currently take no metrics dependency at all,
   so this is new plumbing, not a parameter rename.
3. Add the last-epoch-bump timestamp needed for
   `management.karst.psk.epoch.age.seconds` at the epoch's actual increment
   site (find it via `grep -rn "Epoch++\|Epoch = \|Epoch +=" internals/karst/`
   from the roster/account-management code — not yet identified above because
   it lives outside the files this plan already read; confirm before writing
   the metric, don't guess the call site).
4. Record `management.karst.bedrock.chain.depth` and
   `.anchor.age.seconds` at `CommitPending`/`Import`/`Scheduler.Tick`; record
   `.relay.registry.size` at `Store.Create`/`Delete`.
5. Table-driven tests per metric: a fake `metric.Meter` (the existing
   `telemetry` package's own test doubles, if any — check
   `telemetry/*_test.go` for the established mocking pattern before adding a
   new one) asserting the right value is recorded on the right event, not
   asserting against a live Prometheus registry.

### W5 — netmap-push span and histogram, Bedrock/handshake spans (SRE + Rust 3)

1. Construct a `TracerProvider` in `app_metrics.go` or its own
   `telemetry/tracing.go`, exported through whichever OTel trace exporter the
   deployment's `docker-compose.yml`/Caddy topology can actually receive
   (OTLP-over-gRPC to a collector is the standard default; confirm against
   what `deploy/compose/` already has room for before choosing an exporter
   that needs new infrastructure this phase does not otherwise add).
2. Instrument the three spans named in §3.4, with `management.karst.netmap
   .push.duration.ms` recorded from the same span's start/end rather than a
   second independent timer, so the histogram and the trace can never
   disagree about what "the push" means.
3. Begin the `tracing` crate migration on `karstd` per §3.2 — the prioritized
   call sites only, tracked against a checklist in this file's own status
   section (§7) rather than a separate document.

### W6 — `karstd` metrics surface and `bugreport` extension (Rust 3)

1. Implement `Command::Metrics` (§3.1) rendering `Engine::Stats` and
   route/gateway state as Prometheus text — reuse the exact field names
   `bug_report` already established (`tx_packets`, `unroutable`,
   `bedrock_equivocation`, etc.) translated to `karst_<field>` metric names,
   so a support engineer reading both a bugreport and a metrics dump
   recognizes the same numbers.
2. Add the opt-in loopback HTTP listener behind `[metrics] listen`, with the
   non-loopback-bind rejection from §3.1 covered by a test that asserts
   startup fails closed rather than silently binding wide.
3. Extend `bug_report` with the sections named in §2's gap column: control
   session health (time since last received push, transport — plaintext h2c
   per `04-pentest.md` §8 — TLS is not available to report as active because
   it isn't implemented), Bedrock chain depth and anchor age (mirroring the
   new server-side metrics so a node-side report and a server-side scrape
   describe the same state from two vantage points), and per-relay/TURN
   candidate reachability beyond the aggregate `relay_dropped` counter.
4. Confirm every new `bugreport` field against the existing redaction
   rule (`bug_report`'s own header comment: "Contains no key material") —
   add a test enumerating the report's field names against a denylist
   pattern (`psk`, `key`, `secret`, `token`) the way `leakscan.rs` already
   does for the existing report, extended to cover the new sections rather
   than assuming they're safe by construction.

### W7 — documentation and validation

1. Document every new metric's name, kind, labels, and meaning in the
   operations manual (workstream 11 owns the document itself; this workstream
   supplies the accurate content for its four server metrics and the
   `karstd` surface, since nobody else can write it correctly).
2. Publish one starter Grafana/PromQL query per metric — the netmap-push
   latency histogram in particular should show the query used to derive item
   0.1's number, so the ad hoc measurement done for that exit criterion has a
   durable, repeatable equivalent.
3. Run the exit demonstration (§7) from published artifacts.

## 6. Correctness and validation checks

- Each of the four server metrics changes on the event that should change it
  and does not change on unrelated events (e.g. `relay.registry.size`
  increments on `Store.Create`, not on an unrelated peer connect).
- `management.karst.netmap.push.duration.ms` is recorded exactly once per
  push, even under the eviction race §9.7/§10 of `04-pentest.md` fixed —
  confirm a superseded session's in-flight push does not double-record.
- The `karst.control.session_handshake` span fires for both a normal
  connection and the duplicate-identity eviction path
  (`TestSecondSessionForSameIdentityEvictsFirst`, already covers the
  eviction logic itself — add a span-presence assertion alongside it rather
  than a new end-to-end test).
- `karst metrics` (IPC) and the optional HTTP listener return byte-identical
  output for the same underlying state, proving the listener is a transport
  wrapper and not a second code path that can drift from the first.
- The non-loopback-bind rejection test from §5 W6 item 2.
- The `bugreport` redaction denylist test from §5 W6 item 4 passes against
  every existing section too, not only the new ones — regression coverage
  for the property the header comment already promises.
- `go vet`/`cargo clippy` clean on all touched packages; `go test
  ./management/server/telemetry/... ./management/internals/karst/...` and
  `cargo test -p karstd` both pass.

## 7. Exit demonstration

From a deployment installed from published packages/images (reuse
`deploy/compose/pentest/` or its non-pentest equivalent — this does not need
a fresh throwaway tag the way §1 of `04-pentest.md` did, since nothing here is
security-sensitive enough to require a from-scratch verified build, but it
must not be `:dev` images or `cargo run`):

1. Scrape `karst-control`'s `/metrics` before and after a Bedrock anchor
   cycle runs (force one via the scheduler's existing test hooks or by
   waiting out `MaxAge`); show `management.karst.bedrock.chain.depth`
   incrementing and `.anchor.age.seconds` resetting near zero.
2. Advance the PSK epoch (the existing epoch-rotation path used by workstream
   3's PSK grace-period tests) and show `management.karst.psk.epoch.age
   .seconds` reset, then climb.
3. Register and deregister a relay through the admin API; show
   `management.karst.relay.registry.size` move by exactly one each time.
4. Trigger a netmap push (enroll a node, or change a policy) and show
   `management.karst.netmap.push.duration.ms` record a sample, cross-checked
   against the `karst.netmap.push` trace span's own duration in whatever
   trace viewer the chosen exporter (§5 W5 item 1) feeds.
5. Run `karst metrics` on an enrolled `karstd` node and separately curl the
   opt-in HTTP listener (started for this demonstration only); show the two
   outputs match, then show the listener refuses to start when configured
   with a non-loopback address.
6. Run `karst bugreport` on the same node; show the new control-session,
   Bedrock, and relay-reachability sections populated, and confirm by
   inspection (or the automated denylist test from §6) that no key material
   appears anywhere in the output.

Evidence retained with the phase gate: the before/after `/metrics` scrapes,
the trace viewer screenshot or export for one push event, `karst metrics` and
`karst bugreport` output (redacted-by-construction, safe to attach as-is),
and the PromQL queries used for the demonstration so they double as the
documentation deliverable's starter queries.

## 8. Definition of done

- The four named server-side metrics (Bedrock chain depth, PSK epoch age,
  relay-registry size, netmap-push latency) are live on `/metrics`, follow
  the existing `management.<domain>.<name>.<unit>` naming idiom, and are
  covered by table-driven tests asserting they change on the right event.
- The three named trace spans exist, export through a real configured
  exporter (not a no-op provider), and cover the request paths named in §3.4.
- `karstd` exposes its own metrics over the IPC `Command::Metrics` verb by
  default and, when configured, over a loopback-only HTTP listener that is
  provably rejected for any non-loopback bind address.
- `karst bugreport` reports control-session health, Bedrock chain
  depth/anchor age, and per-relay/TURN reachability in addition to what it
  already reported before this workstream, with the redaction denylist test
  passing against the full report, old and new sections both.
- Item 0.1's netmap-push latency number has a durable, continuously exported
  metric behind it, not only the one-off measurement recorded in
  `00-overview.md` §0.1.
- The operations manual (workstream 11) has accurate content for every new
  metric and the `karstd` metrics surface, supplied by this workstream.
- Any discovered high/critical finding from the redaction check or the
  loopback-bind check is fixed and re-tested before the public beta gate.
