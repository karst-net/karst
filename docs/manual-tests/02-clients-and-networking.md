<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Manual tests: clients and networking

Run the common client rows on each supported beta platform: Linux x86-64 and
arm64, macOS Apple Silicon and Intel, and Windows x64.  Mark a platform row
`Not applicable` only where the product explicitly says the capability is not
available (for example host DNS in userspace mode).

| ID | Exercise | Steps | Expected result |
| --- | --- | --- | --- |
| CLI-01 | Install and boot service | Install the platform package/installer as a local administrator; reboot; uninstall afterwards in a disposable VM. | The service starts at the documented scope, leaves a functional host after uninstall, and no unprotected enrollment secret is displayed. |
| CLI-02 | Platform integration | Enroll once using the normal TUN path. Verify interface/address, routes, service logs, secure identity storage, and peer connectivity. | The correct platform mechanism is used: Linux service/TUN, macOS LaunchDaemon/utun, Windows service/TUN or documented userspace path. |
| CLI-03 | Userspace mode | Enroll/select userspace mode and send allowed traffic. Inspect DNS status. | Connectivity works without elevated TUN privileges; the client explicitly reports any host-DNS limitation rather than claiming integration. |
| CLI-04 | Setup recovery | Interrupt guided setup after identity creation, then run `karst setup --resume`. Also try malformed invitation input. | Resume uses the saved identity safely; malformed input fails clearly without replacing identity or enrolling a node. |
| CLI-05 | CLI status and shutdown | Run `karst status`, `version`, `metrics`, `down`, and status again. | Output identifies peer/session/MTU and version; metrics are Prometheus text; shutdown is clean and reports unavailable daemon afterwards. |
| NET-01 | Mesh DNS | Configure a mesh zone and resolve an enrolled peer, an unknown mesh name, and a public name. | Peer resolves from the netmap; unknown mesh name is authoritative NXDOMAIN and is not leaked upstream; public name follows normal resolver policy. |
| NET-02 | Split DNS | Add an authorized split domain and upstream. Query matching and nonmatching names; make the split upstream unavailable. | Matching queries go only to the split upstream; nonmatching names do not; split failure is SERVFAIL, never global fallback. |
| NET-03 | DNS lifecycle | Start the client, compare host resolver state with its backup, stop/crash it, run `karst dns revert`, and restart. | DNS changes are transactional and original resolver state is restored in every stop/failure path. |
| NET-04 | DNS diagnostics | Run `karst dns status` and `karst dns query` for mesh, split, and public names. | The displayed listener, host integration, routes and explanation agree with observed resolution. |
| NET-05 | Subnet router | Enable forwarding on the gateway, create a restricted CIDR route, authorize one recipient group, and test both an authorized and unauthorized client. | Only recipients receive/use the route; authorized traffic reaches the LAN with a return path; ACL still limits destination access. |
| NET-06 | Exit-node consent | Publish default-route prefixes, confirm they are not auto-applied, use `karst exit-node use ROUTE_ID`, test public egress, then disable it. | Selection is explicit and persistent; traffic uses the selected exit only after consent; disable removes consent and restores ordinary routes. |
| NET-07 | Route resilience | Disable/delete the gateway route during use and restore it. | Client removes or marks the route unavailable without retaining a black-hole default route; restoration is reflected on next map update. |

Platform-specific evidence: package/installer version, service state, interface/route view, secure-store confirmation without secret values, and before/after DNS state.

