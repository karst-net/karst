<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Documentation exit demonstration record

This is the evidence record for
[`11-documentation.md`](11-documentation.md) §§6–8. A maintainer must not mark
the workstream complete while any disposition below is pending. CI supplies
mechanical evidence; named people supply the independent-reader evidence the
plan deliberately requires.

## Candidate under review

- Branch: `phase-6/documentation`
- Threat-model correction: `99ba57f24cb4dc63755e19968f99168d12364215`
- Documentation candidate: `b4fe689` (full object ID recorded by the reviewer
  at sign-off)
- Released tag and artifact digests used by outsider/operator: pending

## 1. Mechanical checks

Run from the candidate checkout:

```sh
./scripts/documentation-check.sh
cd server && go test ./management/internals/karst/policy/...
```

CI must also pass all three destructive walkthrough jobs on fresh runners:
`Walkthrough path A (privileged)`, `Walkthrough path B (compose)`, and
`Walkthrough path C (systemd)`. The local static check is not a substitute.

- Result: static checks pass locally; fresh-runner jobs pending on this branch
- Reviewer/date: pending

## 2. Outsider reverse-proxy walkthrough

Runner eligibility: no prior Karst exposure and not on the engineering team.
Give the runner only the released tag's artifacts and
`docs/GETTING-STARTED.md`; do not give repository source, coaching, or the
pentest deployment. Timebox first connection at 30 minutes.

Ask the runner to use one TLS-terminating public origin for the console/API and
to configure node enrollment using §7.1–7.2. Record every departure from the
document as a numbered issue. In particular record whether the runner knew,
before encountering an error, that nodes cannot dial the TLS endpoint and need
a LAN-only unproxied h2c port.

- Runner/date: pending
- Release tag/digests: pending
- Time to first node: pending
- Numbered deviations: pending
- TLS/port-sharing-attributable deviations (required: zero): pending
- Disposition: pending

## 3. Operations restore demonstration

Give an operator only `docs/OPERATIONS.md` and credentials for a disposable,
running HA deployment. Do not provide source code or maintainer help. The
operator must create an off-host backup, introduce a reversible marker loss,
restore to a point before it, verify pre-target/post-target data, reconnect the
control replicas, and leave replication healthy. Never perform this drill on
the sole copy of production data.

- Operator/date: pending
- Release tag/digests and topology: pending
- Backup command/output path: pending
- Restore target and command: pending
- Data verification: pending
- Replication verification: pending
- Measured RTO/RPO (comparison with documented 45s/38.5s, not replacement): pending
- Deviations/issues: pending
- Disposition: pending

## 4. Whitepaper source review and sign-off

The crypto lead reads `docs/SECURITY-WHITEPAPER.md` line by line against
`docs/THREAT-MODEL.md`, `phreatic-review-findings.md`,
`spec/phreatic-v1.md`, `spec/karst-control-v1.md`, ADR-0016, and the named CI
jobs. Every factual claim must resolve to one of those sources. Corrections
land before sign-off.

After review, replace the pending fields in the whitepaper with the crypto
lead's name, date, exact threat-model commit, exact reviewed whitepaper commit,
and signed-off disposition. The reviewing commit must also state approval of
README's status wording.

- Crypto lead/date: pending
- Line-level corrections: pending
- Reviewed whitepaper commit: pending
- README wording disposition: pending
- Recorded sign-off commit: pending

## 5. Migration comprehension check

Give the migration guide to a WireGuard or Tailscale user who has never used
Karst. Without prompting, ask: “Can the old and new VPNs interoperate during
cutover, and what kind of cutover is required?” The passing answer states that
there is no interoperability bridge and production traffic moves in a clean
break. Do not quote those words in the question.

- Reader/date/background: pending
- Answer, verbatim: pending
- Disposition: pending

## 6. README claim review

A second reader checks each README status sentence against the tree and this
record. Until §2 and §4 pass, README must continue to say the outsider run and
crypto-lead sign-off are pending. After they pass, update the status only to
claims the recorded evidence supports.

- Reader/date: pending
- Corrections: pending
- Reviewed commit: pending
- Disposition: pending

## Final disposition

- All documentation defects found above fixed: pending
- All independent-reader checks complete: pending
- Workstream 11 exit criteria met: **no — pending external demonstrations and sign-off**
