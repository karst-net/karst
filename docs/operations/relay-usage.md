<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Managed relay usage implementation status

ADR-0050 defines the intended meter: opaque `RecvPacket` payload bytes accepted
by the destination client's transport, after the entire encoded frame writes
successfully. This measures transport acceptance, not proven endpoint receipt.
Framing and transport overhead, control frames, failed/partial writes, queue
drops, and internal mesh hops do not contribute. A newly submitted duplicate
payload is a separate forwarding operation.

## Attribution and write boundary

The control-plane usage ledger stores immutable deployment/account/aquifer
mapping records. A domain-separated SHA-256 digest of length-prefixed fields
identifies each mapping. Repeated publication reuses the same record; account
reassignment produces another reference and preserves historical lookup.
Neither the aquifer prefix nor a relay-supplied account ID determines billing
ownership. A mapping reference is evidence, not producer authorization.

The optional Go roster integration persists mappings before advertising
`usage_deployment` and `usage_mapping` on client rows. It rejects transaction
handles that could publish before commit. On ledger failure it renews the
admission roster without attribution fields, removing old references. Network
admission must remain independent of billing availability.

The Rust relay parses these optional fields without making admission depend on
valid billing metadata. Destination queue entries capture a mapping reference
and opaque payload length from the same roster snapshot used for admission.
The reference is retained through queueing and is not looked up again at write
completion. A missing mapping remains unresolved; it must never become a zero
usage claim. Only destination deliveries carry usage metadata. The common
TCP/QUIC writer returns this metadata after a successful complete-frame write.

## Collection and local durability

Collection is explicitly enabled in the relay TOML with a `usage.spool_dir`
path. To also enable control-plane delivery, set `usage.upload_url` to the
HTTPS origin (scheme and authority only). Omitting `upload_url` retains batches
locally and makes no upload connection. Successful complete writes enter a bounded nonblocking queue and feed the
minute aggregator. Queue loss, unresolved mapping, overflow, clock changes,
unclean restart, or spool failure marks coverage incomplete. The consumer seals
empty windows as heartbeats. Each KRUM payload is wrapped as a KRUS v1 envelope:
its epoch, sequence, payload length, SHA-256 digest, and payload are signed with
the relay identity under a context reserved for usage accounting. The immutable
signed bytes are written once and replayed unchanged after restart. The Go
relayusage parser verifies envelope bounds and digest, and both implementations
check the shared signing-input vector. The Unix spool is bounded to
256 MiB and 1,024 batches; full storage rejects new windows and marks a gap.
No traffic is blocked when collection falls behind.

## Control-plane upload and authorization

The management API accepts signed batches at
`POST /api/karst/v1/usage/relay-batches` with
`Content-Type: application/octet-stream`. The `Authorization` header has the
canonical form `KarstUsage <relay-id>.<timestamp-micros>.<nonce-hex>.<signature-base64>`.
Each HTTP request has a fresh request signature and nonce, valid within five
minutes of management-server time; a retry reuses the immutable batch bytes
but signs a new request. The handler bounds the body before parsing. It returns
204 only after durable ingestion, including an identical batch retry, and
rejects replayed request nonces and conflicting batch identities.

The relay retries retained batches in order every five seconds. It treats only
HTTP 204 as acknowledgment; the spool removes a batch only after that response
and a local digest check. Every retry keeps the stored batch bytes but generates
a fresh request timestamp, nonce, and signature. An upload request has a
10-second timeout and never runs in a forwarding task.

Signature verification identifies a relay key but does not grant billing
authority. An operator must explicitly authorize its identity for one managed
deployment and allow each exact mapping version before a batch can be ingested.
The mapping version resolves to an account through the immutable control-plane
ledger; relay-supplied account identifiers are never trusted. The management
operator commands are `management admin usage relays authorize`, `allow-mapping`,
`revoke-mapping`, and `revoke`. Each mutation and its audit entry commit in one
database transaction. The `--actor` value is an audit label, not authentication;
access to the administrative command itself must remain restricted.

The control plane persists batch identities, per-account totals, and coverage
rows transactionally. This establishes durable, replay-safe ingestion, but it
does not yet expose relay totals or coverage through a customer or operator
report. The optional relay uploader and retry loop are wired to the local spool,
but customer-visible relay accounting is not complete. Charges and spending
enforcement are also not implemented. Unconfigured deployments create no relay
spool and retain existing forwarding behavior. The mapping ledger table is
additive, and no mappings are written unless the optional roster integration
is explicitly supplied. On non-Unix platforms, enabling the spool currently
fails at startup.

Next implementation work under [#275](https://github.com/karst-net/karst/issues/275):

- Expose account totals and coverage to customers and operators, including
  unresolved mappings, missing producers, disk failures, clock anomalies, and
  late data.
- Resolve pricing, alert thresholds, optional relay spending caps, and payment
  behavior from the remaining decisions tracked in #275 before implementing
  charges or enforcement.
- Document retention, recovery, and downgrade before managed rollout.

There is no atomic network-write/disk-write transaction. A crash between them
can lose observations. This must remain visible uncertainty, rather than an
estimated charge or a claim of exactly-once measurement.

## Verification

`cargo test -p karst-relay` covers relay behavior and the write boundary. The
write tests inject failures and zero writes at every partial-frame position.
Queue tests exclude mesh/control frames and preserve payload-only metadata.
Go race tests in `management/internals/karst/relayusage` cover bounded upload
parsing, fresh request authentication, operator producer/mapping authorization,
nonce replay rejection, exact batch deduplication, conflicting content, and
durable account totals/coverage. Tests in `management/internals/karst/usage`
and `management/internals/karst/roster` cover historical mappings, retries,
deployment isolation, rollback, and admission continuity on ledger failure.
The shared `spec/vectors/relay-usage-roster-v1.toml` fixture checks that Rust
reads references emitted by Go's durable publication path. These checks do
not establish complete end-to-end managed usage accounting.
