<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Manual tests: Bedrock, audit, and operations

Perform Bedrock cases only in a disposable account with offline authority media.
Record fingerprints and request identifiers, never private key material.

| ID | Exercise | Steps | Expected result |
| --- | --- | --- | --- |
| OPS-01 | Bedrock bootstrap | Initialize root/authority material offline, configure quorum and advisory mode, and inspect console state. | Public fingerprints, mode, quorum, coverage and chain state agree; private keys remain offline. |
| OPS-02 | Reviewed membership | Export a pending membership request, inspect it offline with `karst-bedrock`, collect quorum signatures, import the bundle, and enroll/use the covered device. | The request describes the intended change; only a valid quorum advances the chain and clients accept covered membership. |
| OPS-03 | Invalid Bedrock inputs | Import a changed, stale, wrong-account, duplicate, or below-quorum bundle. | Import is rejected atomically; chain state and already valid membership remain unchanged. |
| OPS-04 | Enforcing floor | Switch to enforcing with the required acknowledgement; attempt an uncovered enrollment and attempt an online downgrade below a client's configured floor. | Enforcing blocks uncovered membership; a server cannot lower the local floor. Advisory/off do not create accidental lockout. |
| OPS-05 | Audit integrity | Perform user, policy, device, relay and Bedrock changes. Filter by actor/action, verify the chain, export to a test SIEM sink, then inspect a deliberately invalid-chain indication. | All relevant actions are append-only, filters/export work, verification result is explicit, and a bad chain is conspicuous. |
| OPS-06 | Crypto posture | Establish direct and relayed sessions with varied expected posture; inspect aggregate/per-session view and CSV export. | Values, counts and exported CSV agree without exposing key material. |
| OPS-07 | Metrics and traces | Scrape control metrics and `karst metrics`; exercise enrollment, netmap push, relay connection, and a failed operation; inspect configured traces. | Documented metrics/spans change with activity and carry safe labels only. |
| OPS-08 | Relay telemetry | Run a relay with telemetry enabled, create/remove clients, and make control temporarily unavailable. | Signed telemetry is accepted for the correct relay, health/counts update, and outage/retry does not interrupt forwarding or forge health. |
| OPS-09 | Diagnostics and redaction | Generate `karst bugreport`; search it for setup keys, PSKs, private keys and complete configuration content. | Bundle contains useful version/status/log facts but none of the forbidden secrets/configuration. |

