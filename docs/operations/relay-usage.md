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

## Not yet operational

Runtime collection remains unwired. No operator option enables managed relay
billing, and the successful-write evidence is currently discarded. There is no
durable spool, signed upload, producer authorization, coverage heartbeat,
aggregate relay report, charge, or spending enforcement in this slice.
Unconfigured deployments create no relay spool and retain existing forwarding
behavior. The device ledger migration adds the mapping table, but no mappings
are written unless the optional roster integration is explicitly supplied.

Next implementation work under [#275](https://github.com/karst-net/karst/issues/275):

- Bound the nonblocking aggregation path and persist immutable batches before
  upload; record lost observations as incomplete coverage.
- Persist producer epochs, sequence identities, clean termination, and coverage
  heartbeats; preserve sealed batches across restart and acknowledgment loss.
- Authenticate upload envelopes and authorize managed producer/mapping scope;
  accept identical retries without adding bytes twice and reject conflicts.
- Expose provisional account totals and coverage gaps, including unresolved
  mappings, missing producers, disk failures, clock anomalies, and late data.
- Wire explicit operator activation and document resource bounds, retention,
  recovery, and downgrade before managed rollout.

There is no atomic network-write/disk-write transaction. A crash between them
can lose observations. This must remain visible uncertainty, rather than an
estimated charge or a claim of exactly-once measurement.

## Verification

`cargo test -p karst-relay` covers relay behavior and the write boundary. The
write tests inject failures and zero writes at every partial-frame position.
Queue tests exclude mesh/control frames and preserve payload-only metadata.
Go race tests in `management/internals/karst/usage` and
`management/internals/karst/roster` cover historical mappings, retries,
deployment isolation, rollback, and admission continuity on ledger failure.
The shared `spec/vectors/relay-usage-roster-v1.toml` fixture checks that Rust
reads references emitted by Go's durable publication path. These checks do
not establish complete end-to-end managed usage accounting.
