<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Observability

Operations reference for the feature `plans/phase-6/08-observability.md`
implements: Karst-object-aware Prometheus metrics and OTel traces on
`karst-control`, a metrics surface and an extended `bugreport` on `karstd`.
For how it fits together end to end and why each piece is shaped the way it
is, see that plan; this document is what an operator needs once it is
running — what to scrape, what to query, and what each new section of
`karst bugreport` means.

## 1. `karst-control`'s Prometheus metrics

`karst-control` exposes Prometheus text on `:9090/metrics` by default
(`--metrics-port`, `management/cmd/root.go`), alongside every metric
inherited from the fork. Four of them are Karst's own:

| Metric | Kind | Labels | Meaning |
|---|---|---|---|
| `management_karst_bedrock_chain_depth` | gauge | `account_id` | The head sequence number of an account's verified Bedrock audit chain — how many entries have been committed. Updated on every `bedrock.Log.Import` (an anchor, a `node-sign`/`node-revoke`, an authority-list change). |
| `management_karst_bedrock_anchor_age_seconds` | gauge | `account_id` | Seconds since an account's Bedrock chain was last anchored to the audit log (ADR-0016). Absent — not zero — until the first anchor exists, so a fresh deployment does not read as "just anchored." |
| `management_karst_psk_epoch_age_seconds` | gauge | *(none)* | Seconds since the PSK rotation epoch (spec/phreatic-v1.md §7.3) last advanced. One value for the whole process, not per account — `control.NetmapHandler.Epoch` is process-global. Rotates every 86400s in the steady state; a value climbing well past that means the rotation scheduler has stopped advancing it. |
| `management_karst_relay_registry_size` | gauge | `account_id` | Number of relays currently registered to an account. Moves by exactly one on `relayreg.Store.Create`/`Delete`, never on an unrelated peer connect or disconnect. |
| `management_karst_netmap_push_duration_ms_milliseconds` | histogram (`_bucket`/`_sum`/`_count`) | `trigger` | How long one server-initiated netmap push (GitHub issues #72/#73 — the deprovisioning-latency mechanism) took to seal and send to a connected node. `trigger` is currently always `"unknown"`: the update-manager channel a push arrives on carries no reason, only a wake-up signal, so there is no taxonomy to label it with yet. This is the durable, continuously-exported number behind the one-off 2.0s measurement `00-overview.md` §0.1 recorded by hand. |

The metric name's `_ms_milliseconds` double suffix (rather than a clean
`_ms`) comes from how `go.opentelemetry.io/otel/exporters/prometheus`
translates a name already ending in a unit abbreviation plus a spelled-out
`WithUnit(...)` — the same pattern every other duration histogram in
`management/server/telemetry/` already has (e.g.
`management_grpc_sync_request_duration_ms_milliseconds`). Verified against a
real scrape, not assumed; if you see a different suffix, trust the scrape
over this document.

### 1.1 Starter PromQL

```promql
# Bedrock chain depth per account, current value.
management_karst_bedrock_chain_depth

# Accounts whose Bedrock chain hasn't anchored in over a day — ADR-0016's
# automatic anchoring policy should keep this near zero once a key is
# enrolled in the anchor tier.
management_karst_bedrock_anchor_age_seconds > 86400

# PSK epoch age: alert if this exceeds ~2x the 86400s rotation period,
# which means the rotation scheduler (control/epoch.go) has stopped.
management_karst_psk_epoch_age_seconds > 172800

# Relay registry size, current value per account.
management_karst_relay_registry_size

# Netmap-push latency, p95 over 5 minutes — the repeatable equivalent of
# the ad hoc measurement 00-overview.md §0.1 recorded once by hand.
histogram_quantile(0.95,
  sum(rate(management_karst_netmap_push_duration_ms_milliseconds_bucket[5m])) by (le)
)

# Push volume by outcome, to see whether pushes are happening at all on a
# quiet deployment.
sum(rate(management_karst_netmap_push_duration_ms_milliseconds_count[5m]))
```

## 2. `karst-control`'s trace spans

Off by default. `karst-control` builds a real OTLP-over-gRPC exporter only
when an operator sets one of the OTel SDK's own standard endpoint
environment variables (`OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` or
`OTEL_EXPORTER_OTLP_ENDPOINT`) on the process; unset, every span created is
a genuine no-op, not a span retried forever against a collector that isn't
there. `deploy/compose/` does not run a collector today — pointing this at
one (Jaeger, Tempo, an OTel Collector, anything that accepts OTLP/gRPC) is
the operator's own infrastructure choice, made by setting the env var, not
a config file option.

Three spans, each covering exactly the request path named, not a blanket
instrumentation pass:

- **`karst.control.session_handshake`** — from a node's `Session` stream
  opening through the point its subscription to server-initiated pushes is
  registered. Ends there deliberately, not at stream close: the span
  covers the handshake, not the life of the connection. Fires on both an
  ordinary connection and the duplicate-identity eviction path (GitHub
  issue #87).
- **`karst.netmap.push`** — one server-initiated push, from the moment the
  session's goroutine wakes on the notification channel through the sealed
  envelope being sent. Shares its start time with the
  `netmap.push.duration.ms` histogram sample recorded from the same event,
  so the two can never disagree about what "the push" means.
- **`karst.bedrock.anchor_cycle`** — one `bedrock.Scheduler.Tick` call,
  with four child spans (`.anchor_due`, `.prepare_anchor`, `.sign`,
  `.import`) so a slow anchor cycle is diagnosable from the trace alone,
  without reading the scheduler's source to guess which step is slow.

## 3. `karstd`'s metrics surface

Two ways to reach the same numbers — deliberately: a new network-facing
listener is an opt-in capability, not a default, matching the same posture
`06-subnet-routers-and-exit-nodes.md` §3.2 requires for default routes.

### 3.1 `karst metrics` (always available)

```
$ karst metrics
```

Renders `Engine::Stats` and route/gateway state as Prometheus text over the
same local, root-owned control socket `karst status`/`karst bugreport`
already use — no new access boundary. Field names are `karst bugreport`'s
own `[stats]` section translated to `karst_<field>`, so a support engineer
reading both recognizes the same numbers:

| Metric | Kind | Meaning |
|---|---|---|
| `karst_tx_packets` | counter | Packets encrypted and sent |
| `karst_rx_packets` | counter | Packets decrypted and delivered to the host |
| `karst_unroutable` | counter | Packets from the host with no peer owning the destination |
| `karst_source_violations` | counter | Packets from a peer claiming a source address it does not own |
| `karst_mac_failures` | counter | Datagrams discarded by the fragment MAC before any state was touched |
| `karst_cookie_replies_issued` | counter | `CookieReply` datagrams sent under load (§9.1) |
| `karst_tx_dropped_no_session` | counter | Packets dropped because no session was established yet |
| `karst_decrypt_failures` | counter | Authenticated-decryption failures on inbound transport data |
| `karst_malformed` | counter | Inbound datagrams that could not even be parsed as a fragment |
| `karst_bedrock_head_agreed` | counter | Peer head claims that agreed with this node's verified Bedrock chain |
| `karst_bedrock_equivocation` | counter | Peer head claims that diverged from this node's chain — **any value above zero is an incident** |
| `karst_acl_denied_in` | counter | Authenticated packets from a peer the ACL refused |
| `karst_acl_denied_out` | counter | Packets from the host the ACL refused to send |
| `karst_acl_unclassifiable` | counter | Packets denied because their ports could not be established at all |
| `karst_relay_dropped` | counter | Packets dropped by the bounded queue to the relay worker |
| `karst_route_offers` | gauge | Route offers this node's netmap currently carries |
| `karst_gateway_active` | gauge | Whether this node is currently forwarding as a subnet/exit gateway |
| `karst_exit_route_active` | gauge | Whether an exit-route offer is currently selected and installed |

A node-exporter `textfile` collector or a cron job wrapping `karst metrics`
is enough for most deployments — see `06-subnet-routers-and-exit-nodes.md`'s
own `[routing]` block for the sibling pattern this follows.

### 3.2 The opt-in loopback HTTP listener

For an operator who wants a normal Prometheus scrape target instead of a
textfile collector:

```toml
[metrics]
listen = "127.0.0.1:9091"
```

Starts an HTTP server answering `GET /metrics` with exactly the same text
`karst metrics` returns — it dials the same control socket internally
rather than computing the numbers a second time, so the two can never
drift apart. **Loopback only, enforced at config load, not just
documented**: `karstd` refuses to start with a non-loopback `listen`
address rather than silently binding one. Front it with your own reverse
proxy or scrape it directly from `127.0.0.1` — it never listens on a
network-facing interface on its own.

## 4. `karst bugreport`'s new sections

Three sections added to the existing report, all under the same
redaction discipline the header comment has always promised — no PSKs, no
private keys, no setup key, checked by an automated denylist test against
every field name, old sections and new alike.

- **`[control]`** — control-session health: `transport` (always
  `"plaintext (h2c)"` today — `04-pentest.md` §8 found the control-channel
  client has no TLS support at all, stated here rather than left to be
  discovered) and `since_last_push_seconds` (time since this node last
  received an unprompted server push; `"never"` rather than a fabricated
  number if none has arrived yet).
- **`[bedrock]`** gains `chain_depth` and `anchor_age_seconds`, mirroring
  `management_karst_bedrock_chain_depth`/`.anchor_age_seconds` above so a
  node-side report and a server-side scrape describe the same chain from
  two vantage points.
- **`[[relay]]`/`[[turn]]`** — per-relay and per-TURN-server reachability
  beyond the aggregate `relay_dropped` counter: `address`/`uri`,
  `reachable`, and `since_seconds` (how long the connection has held its
  current state). Only relays and TURN servers this node has actually
  attempted to reach appear; one that was never dialled has no entry.

## 5. Redaction

Every field above is checked by `tests/leakscan.rs`'s
`no_bugreport_field_name_suggests_key_material` test, which scans every
`field = value` line's *name* against a `psk`/`key`/`secret`/`token`
denylist, and by the existing byte-content scan
(`no_psk_bytes_reach_any_diagnostic`), which drives a real netmap carrying
real PSKs through a datapath and confirms none of them appear in any
rendered diagnostic, `bugreport` included. Both run in CI on every change to
this surface.
