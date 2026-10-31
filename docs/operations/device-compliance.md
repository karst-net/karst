<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Operating device compliance guardrails

Device compliance guardrails require fresh, self-reported evidence from a
client device before it may reach a protected resource. A guardrail can only
narrow access that identity policy already grants; it never grants additional
privileges, and it never changes domain membership. Compliance is an
independent, mandatory check composed with AND alongside the existing
union-of-accept ACL model and the independent SSH gate — see
[ADR-0055](../adr/0055-device-compliance-and-resource-access.md) and
[spec/device-compliance-v1.md](../../spec/device-compliance-v1.md) for the
full implementation contract.

## Supported checks

Only self-reported evidence is supported today — never verified MDM/EDR
attestation. Two check kinds exist:

- **Minimum Karst client version** — compares the connecting client's own
  reported version, any platform.
- **Minimum OS version** — Linux (distribution `ubuntu` with a two-component
  numeric release, or `debian` with one or two numeric components), macOS
  (`major.minor[.patch]`), or Windows (`major.minor.build[.revision]`,
  never a marketing name).

**Not yet supported, on any platform:** disk encryption, screen lock,
managed-device (MDM) status, and endpoint security (EDR) status. Do not
configure a guardrail that assumes one of these; there is no requirement kind
for it, and the write API rejects an unrecognized one.

A device with no accepted evidence, stale evidence (older than 180 seconds
past server receipt), or malformed/unsupported-platform evidence is treated
as nonpassing, never as a silent pass. A guardrail with an empty resolved
source list is a valid mandatory denial, not a configuration error.

## Configuring a guardrail

Use the console: **Groups & access → Compliance guardrails**. The flow is the
same reviewed-change pattern as Access grants:

1. **Add a requirement set** — name it, then add one or more checks (client
   version or OS version) to it. A guardrail references requirement sets by
   name; every referenced requirement in the set must pass.
2. **Add a guardrail** — a destination selector (a CIDR, a `group:` name, or
   a device handle), transport (`tcp`/`udp`/either) and port range, and which
   requirement set(s) every source device must satisfy to reach it.
3. **Add remediation resources**, if needed — destinations explicitly exempt
   from every guardrail (help/support endpoints a noncompliant device should
   still reach). A remediation resource must not overlap a guardrail's own
   destination; the review step rejects a draft where it does.
4. **Review guardrail changes** — this previews the actual compiled mandatory
   gates for every currently managed device, the same compilation the control
   plane uses to issue real permits, not a separate preview-only
   implementation. Confirm the devices and gates shown are what you intend
   before applying.
5. **Apply** — writes the new draft version. Already-connected devices pick
   it up on their next permit refresh (see "Revocation bound" below); the
   write also triggers an immediate account-wide netmap push so an
   already-connected session re-fetches promptly rather than waiting out
   that cycle.

Every write is optimistically versioned (`If-Match`/`ETag`, the same pattern
as the identity access policy): a conflicting concurrent edit is rejected
with "changed elsewhere," not silently overwritten. Version history is
available for review and restoration from the same view.

The underlying contract is `GET`/`PUT /karst/v1/compliance/draft`, plus
`/validate`, `/preview`, `/test`, `/versions`, and `/rollback/{version}` —
documented in `server/shared/management/http/api/karst-openapi.yml` for a
programmatic integration. It authenticates the same way as every other admin
console request; it is not a separate API key surface.

## Revocation and offline bound

Target online delivery is 30 seconds; the enforced bound is 120 seconds after
a device's last valid permit, even if notifications or control connectivity
fail. A real end-to-end test (two devices, one guardrail, a real Go control
server and a real packet-path `Engine`) measures this at ~30.09 seconds
across repeated runs, and separately proves that enforcement survives a
control-plane disconnect: the deciding factor is each device's own locally
tracked permit expiry, not an active connection to the server. Recovery after
a failure or expiry clears restores only grants the identity policy already
allows — never re-enrollment, never a domain move, and never more access than
the device already had.

## Audit visibility

Every `/karst/v1/compliance/draft*` write or test/preview/validate call is
recorded in the account's existing Karst audit log automatically (the same
cross-cutting mechanism that records every other administrative mutation
under `/karst/v1`, including identity policy writes): actor, action
(`karst.put`, `karst.post`, …), and target path. Review it the same way as
any other administrative change, from the console's **Audit log** view.

Per-device compliance status (self-reported evidence, no pass/fail verdict)
is visible from a machine's **Status → Compliance** dialog. It intentionally
shows the evidence the device reported, not a synthesized verdict: a verdict
assembled without knowing this account's actual configured guardrails would
read as a false "compliant" signal — the same reasoning the console applies
to cryptographic suite posture, which also shows raw observations rather
than inferring a status it cannot fully verify.

## Troubleshooting

- **A device I expect to pass shows no sources in a guardrail's compiled
  gate.** Check the device has recent accepted evidence (the Machines status
  dialog) and that its platform/OS/client version actually satisfies every
  requirement in every set the guardrail references — a guardrail denies by
  default, not by exception.
- **A `group:` selector never matches any device, or permits stop issuing
  entirely for the whole account.** Confirm the group is still defined in
  the account's current identity access policy. An undefined group is
  rejected when the guardrail is first written, but removing that group
  from identity policy *afterward* is not itself blocked — the next
  compilation (including real permit issuance) then fails validation again,
  for every device, until the guardrail is fixed or removed. Keep a
  guardrail's referenced groups in sync with identity policy changes.
- **A write is rejected with a version conflict.** Another administrator
  changed the draft concurrently. Reload the current draft before reapplying
  your edit; the view does this automatically after the conflict is
  reported.
- **A remediation resource is rejected at review time.** It overlaps a
  guardrail's own destination. Narrow one of the two, or remove the overlap
  — remediation access is exempt by design and must stay disjoint from
  anything a guardrail protects.
