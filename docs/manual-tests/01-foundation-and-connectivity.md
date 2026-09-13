<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Manual tests: foundation and connectivity

Prerequisite: the shared fixture in [README.md](README.md).  Capture redacted
control/relay logs and `karst status` output for each result.

| ID | Exercise | Steps | Expected result |
| --- | --- | --- | --- |
| FND-01 | Control bootstrap | Start `karst-control` with persistent storage, OIDC, a valid policy, and both published control pins. Restart it. | The service is reachable, the pins remain stable across restart, and the empty policy is default-deny. |
| FND-02 | Invalid control trust | Attempt enrollment with a changed KEM pin and again with a changed signing pin. | Both attempts fail before a node is registered; neither failure silently falls back to unauthenticated TLS. |
| FND-03 | Relay configuration | Run `karst-relay check`, then `karst-relay pubkey`; register its numeric `IP:port`, TLS name, identity and region in control. | Validation and registry data agree. A newly enrolled node receives the relay entry. |
| FND-04 | Relay guard rails | Try a DNS hostname in the relay address field and an incorrect TLS name or relay identity. | The console/API rejects the hostname; clients reject the bad TLS/identity entry without accepting relay traffic. |
| FND-05 | Relay admission | Connect an enrolled node, then attempt with an unregistered node or stale/removed roster entry. | The enrolled node is admitted; the other connection is denied and no payload path is established. |
| FND-06 | Device enrollment | Create a short-lived, single-use credential. Enroll Alice's device with both pins, then inspect the portal/console. | A sealed local identity, stable opaque handle, owner, groups, encrypted netmap and enrollment audit event exist. |
| FND-07 | Enrollment replay and expiry | Reuse the credential, then use an expired or revoked credential. | All attempts fail; no additional node, identity substitution, or partial DNS/tunnel state remains. |
| FND-08 | Device lifecycle | Rename the enrolled device, revoke/deprovision it, and reconnect it. | Rename is reflected; revoked device loses its session and subsequent map access. Only the documented mutable fields are editable. |
| FND-09 | Direct path | With both clients reachable, permit one TCP port and exchange data. Inspect both statuses. | Encrypted traffic succeeds only on the allowed port and both sides report an established direct path. |
| FND-10 | Relay fallback | Block peer UDP/direct candidates while retaining relay reachability; exchange the same data. Restore UDP afterwards. | Traffic succeeds through an established relay path; after restoration it upgrades or remains relayed according to reachability, never falsely claiming direct. |
| FND-11 | ACL enforcement | Allow Alice-to-Bob TCP on one port; test that port, another port, reverse direction, and UDP. | Only the stated flow succeeds. Stateful return traffic works; all unmatched flows are denied. |
| FND-12 | Session continuity | While permitted traffic is active, restart control and then force a client reconnect. | Existing session behavior and reconnection match documented availability expectations; the client safely reauthenticates and receives current policy. |

Cleanup: restore UDP/firewall rules, remove throwaway nodes and keys, and retain only redacted logs.

