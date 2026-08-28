# macOS client

**PLAN.md §9 · W2–W8 · Rust 2.**

## 0. Status — started 2026-08-28

**W2–W3 and W7 are done; W4–W6 and W8 are not.** What exists is a client that
builds, opens a real `utun`, carries packets, and ships as an installable
package — and does not yet resolve mesh names, recover from sleep, or carry an
Apple signature. Read that as "the port is done and the platform integration is
not", which is the honest split.

### Done

| Week | Work | Where |
|---|---|---|
| W2 | `utun` open, AF prefix, read/write, unit tests | `crates/karst-tun/src/macos.rs`, `sys_macos.rs`, `macos_wire.rs` |
| W3 | Addressing, routes, `local_addresses`, `default_gateway`; the name audit | as above, plus `TunConfig::name` redefined as a preference |
| W7 | `.pkg`, universal binary, install/uninstall scripts, LaunchDaemon | `packaging/macos/`, `scripts/build-macos-pkg.sh` |
| — | CI: build both arches, unit + privileged `utun` tests, package build | `.github/workflows/ci.yml` (`macos`), `deliverables.yml` (`macos-package`) |

Two things had to be fixed below `karst-tun` before any of it could compile,
and both are worth knowing about:

- **`karst-transport` had no batched path off Linux.** `sendmmsg`/`recvmmsg`
  are Linux-only and `karstd`'s receive loop uses them unconditionally.
  `src/portable.rs` implements the same two calls as a safe loop over
  `sendto`/`recvfrom`, so the daemon has one datapath rather than two. It is
  not an optimisation and does not pretend to be — see the module header.
- **PREF64 router solicitation is Linux-only** (`RouterSocket`, and
  `/proc/net/if_inet6`). It now returns "unavailable" on macOS rather than
  failing to compile, and RFC 7050 discovery through `ipv4only.arpa` still
  runs. A network that advertises PREF64 *and* does not serve `ipv4only.arpa`
  will leave a macOS node without a prefix, and it says so on startup.

### Not done

| Week | Work | Consequence today |
|---|---|---|
| W4 | Loopback pair test (`bins/karstd/tests/macos_pair.rs`) | Two daemons on one Mac are untested; the datapath is proven per-packet, not end to end |
| W5 | `/etc/resolver`, dynamic store, revert, cache flush | **Mesh names do not resolve system-wide.** `HostIntegration::Auto` selects nothing and announces it |
| W6 | Sleep/wake, network-change re-probe | A laptop that suspends recovers on the keepalive timeout rather than promptly |
| W8 | Signing, notarization, stapling, clean-machine verification | The `.pkg` is unsigned; Gatekeeper refuses it anywhere but the build machine |

W8 is **blocked on paperwork, not on code.** The pipeline is written and
conditional: `scripts/build-macos-pkg.sh` signs, notarizes and staples the
moment the credentials exist, and `--require-signing` makes their absence fatal
so a tag cannot quietly ship unsigned. §7 below is still the critical path —
somebody has to start the Apple Developer Program enrolment.

### On the App Store

`scripts/appstore-submit-macos.sh` and the `app-store` CI job are **stubs, and
will stay stubs until there is a `NEPacketTunnelProvider` variant.** The
package built here installs a root LaunchDaemon; the App Store accepts only
sandboxed applications, so it would be rejected on review whatever it is
signed with. The script checks every precondition, carries the real command
sequence, and refuses unless `KARST_APPSTORE_READY=1` — see §3 for why the
LaunchDaemon split is the right call anyway.


## 1. What porting actually means here

> **Re-baselined 2026-08-27.** No Karst macOS client implementation, package,
> key-storage integration, or host DNS integration exists. Linux-only code and
> userspace abstractions do not satisfy this use case. This workstream remains
> a Phase 5 exit dependency; its acceptance test must include enrolment,
> direct/relay connectivity, DNS apply/revert after abnormal exit, signed and
> notarized install/upgrade/uninstall, and portal download metadata.
>
> **Superseded in part by §0**, which records what has since been built. The
> acceptance criteria above stand unchanged; the statement that no
> implementation exists no longer does. The rest of this section describes the
> tree as it was before the port and is kept because the reasoning it sets out
> is what the port followed.

`karst-tun` was Linux by construction, and honestly so: `sys.rs` is 1 438 lines
of `ioctl` plumbing carrying the crate's single `#![allow(unsafe_code)]`, and
`lib.rs` gates `linux`, `sys`, and `Tun` behind `#[cfg(target_os = "linux")]`.
`local_addresses()` and `default_gateway()` are gated too.

What is **not** Linux: `ip.rs`, `userspace.rs`, `vnet.rs`, and every crate above
`karst-tun`. ADR-0012's userspace stack is platform-independent by
construction, the datapath is portable Rust, and the control client is
`tokio` + `tonic`. So the port is one module, three functions, and a great deal
of packaging.

**Estimate honestly: `utun` is a week and the installer is three.**

## 2. The `utun` device

Open an `AF_SYSTEM`/`SYSPROTO_CONTROL` socket, resolve the `com.apple.net.utun_control`
kernel control id with `CTLIOCGINFO`, and `connect` with a unit number; unit 0
asks the kernel to allocate. New file `crates/karst-tun/src/macos.rs`, plus the
`unsafe` syscall wrappers in a `sys_macos.rs` following `sys.rs`'s discipline
exactly — one thin total wrapper per syscall, each with its safety argument
written out, the crate-level `forbid` intact everywhere else.

Four differences from Linux that reach beyond the module:

**1. The four-byte address-family header.** Every packet read from or written
to a `utun` fd is prefixed with a 4-byte big-endian `AF_INET` or `AF_INET6`.
Linux's TUN has no such prefix (Karst does not use `IFF_NO_PI`'s counterpart
because it opens without `IFF_VNET_HDR` in the plain path). The datapath must
not learn about this — strip it on read and prepend it on write inside
`macos.rs`, and keep the `Tun` trait surface handing out bare IP packets.
Get this wrong in the direction of leaving the prefix on and the symptom is
every packet dropped by the filter as malformed; get it wrong in the other
direction and macOS silently discards writes.

**2. Interface names are not ours to choose.** macOS names `utun` devices
`utunN` and the number is assigned. `TunConfig::name` and `DEFAULT_NAME =
"karst0"` are Linux assumptions baked into config, logs, tests, and the
example TOML. Resolve it as: the config field becomes a *preference* that the
platform may decline, `Tun` exposes the name it actually got, and everything
downstream reads the actual name. Audit for places that assume the configured
name — `bins/karstd/src/routing.rs` and the example config are the first two.

**3. No offload.** `TUNSETOFFLOAD`, `TUNSETVNETHDRSZ`, GSO, and the batched
paths have no `utun` counterpart. The generic path already exists for the
userspace mode; make sure the macOS build selects it rather than compiling a
stub that pretends.

**4. Addressing and routing go through different plumbing.** `SIOCAIFADDR`
for the interface address and `PF_ROUTE` sockets for routes, both `unsafe`
and both fiddly. **Consider shelling out to `ifconfig` and `route` for
Phase 5**, and say so in a comment with a link to this note. It is not elegant,
those binaries are present on every macOS install, and the alternative is a
second 1 400-line `sys` module on the critical path of a packaging-heavy
phase. Revisit in Phase 7 when the mobile port needs the same code via
NetworkExtension anyway.

Also needed: `local_addresses()` via `getifaddrs(3)` and `default_gateway()`
via `sysctl(NET_RT_DUMP)` — both used by discovery and both currently
Linux-only.

## 3. The decision that saves the phase: LaunchDaemon, not NetworkExtension

§9 lists macOS as "`utun`, LaunchDaemon, signed+notarized pkg; App Store
NetworkExtension variant later".

Keep that split, firmly. A `NEPacketTunnelProvider` system extension requires
the `com.apple.developer.networking.networkextension` entitlement, which Apple
grants **by application, on a form, with a review turnaround measured in
weeks** and no committed SLA. Making that a Phase 5 dependency puts the exit
criterion behind someone else's queue.

A root LaunchDaemon opening `utun` needs no special entitlement — it needs
root, which a `.pkg` installer has. The trade is that the daemon is not
sandboxed and cannot ship on the App Store, and both of those are already the
plan (§9 says the App Store variant comes later; Phase 7 for mobile).

**Do the entitlement application in W1 anyway**, as paperwork alongside the
certificates. If it comes back during Phase 6 the NetworkExtension variant
starts unblocked; if it never comes back, nothing was lost.

## 4. LaunchDaemon

`/Library/LaunchDaemons/dev.karst.karstd.plist`, `RunAtLoad`,
`KeepAlive` with `SuccessfulExit=false`, logs to
`/var/log/karst/`, config at `/etc/karst/karstd.toml` (or
`/Library/Application Support/Karst/` — pick one, document it, and match what
the installer writes).

Two macOS-specific behaviours to build and test:

- **Sleep and wake.** A laptop suspends, the network changes, and every UDP
  socket's source address is now wrong. Subscribe to
  `NSWorkspaceDidWakeNotification`-equivalent via `IOKit` power notifications
  — or, much cheaper, poll for a link change and force endpoint rediscovery.
  Karst already re-probes on path change (AVEN, `disco.rs`); the requirement
  is that wake triggers it promptly rather than after a keepalive timeout.
  **Test by actually suspending a Mac**, which means this is a manual test in
  the W8 walkthrough, and say so rather than pretending CI covers it.
- **The revert file matters more here.** [01](01-karstdns.md) §7.1's stale-DNS
  failure mode is worse on a laptop that moves between networks than on a
  server that does not.

## 5. DNS integration

Two mechanisms, both needed:

| For | Mechanism |
|---|---|
| The mesh zone and split-DNS domains | A file per domain in `/etc/resolver/<domain>`, containing `nameserver 100.100.100.100`. The resolver picks these up automatically; no daemon restart, no `scutil` |
| Global nameservers and search domains | The SystemConfiguration dynamic store — `scutil` scripted, or the `SCDynamicStore` API |

`/etc/resolver/` files are the whole split-DNS story on macOS and they are
delightful: a file per domain, longest match wins, and the semantics are
exactly what [01](01-karstdns.md) §5.4 specifies. Prefer them for everything
they can express, and touch the dynamic store only for the global case.

Revert is `unlink` for the files and a store restore for the global config,
persisted to the revert file before the change is applied.

**One trap:** macOS caches negative resolver results aggressively and
`mDNSResponder` needs a nudge (`dscacheutil -flushcache; killall -HUP
mDNSResponder`) after a resolver change, or the first minute after connecting
looks broken. Do it on apply, and on revert.

## 6. Packaging

```
karst-<version>-macos.pkg
├── karstd, karst              → /usr/local/bin/
├── dev.karst.karstd.plist     → /Library/LaunchDaemons/
├── karstd.toml.example        → /etc/karst/
└── scripts/
    ├── preinstall             stop and unload an existing daemon
    └── postinstall            create /var/log/karst, load the daemon
```

Universal binary: build `aarch64-apple-darwin` and `x86_64-apple-darwin`, join
with `lipo`. Both, not just Apple Silicon — self-hosters run old Intel Macs as
always-on boxes, and that is exactly this project's audience.

`pkgbuild` for the component, `productbuild` for the distribution, and a
`Distribution.xml` with a minimum OS version. Pick **macOS 13** and state it;
supporting older costs testing time for a shrinking population.

## 7. Signing and notarization — start in W1

| Artefact | Certificate |
|---|---|
| `karstd`, `karst` binaries | Developer ID Application |
| The `.pkg` | Developer ID Installer |

Both come from an Apple Developer Program organisation membership: $99/yr, a
D-U-N-S number, and an enrolment that takes **one to four weeks** and can stall
on a legal-entity mismatch. ADR-0007 and ADR-0010 have the project's naming and
entity situation; whoever owns that needs to start the enrolment on the first
day of W1. PLAN.md §12 said to do this in Phase 3 and it did not happen.

The pipeline:

1. `codesign --force --options runtime --timestamp` each binary with hardened
   runtime.
2. `productsign` the `.pkg`.
3. `xcrun notarytool submit --wait` with an App Store Connect API key.
4. `xcrun stapler staple` the `.pkg`.
5. Verify with `spctl --assess --type install` **on a machine that has never
   seen the artefact**, because a locally-built package passes Gatekeeper for
   reasons that have nothing to do with whether a user's would.

Common notarization rejections to expect: a binary without the hardened
runtime, a missing secure timestamp, or a nested binary that was not signed.
The first submission will fail; budget for two rounds.

Secrets in CI: the Developer ID certificates as a base64 `.p12` plus password,
and the notarytool API key, all in GitHub Actions secrets. **`.gitignore`
already blocks `*.p12` and `*.pem`** — deliberately, per SECURITY.md — so
nobody can commit these by accident, and the SRE should verify that gate is
what they think it is before the first key exists.

## 8. Testing

There is no macOS equivalent of the netns suite, and pretending otherwise is
how a client ships broken.

| Level | What | Where |
|---|---|---|
| Unit | AF-prefix strip/prepend, name resolution, MTU validation | `crates/karst-tun/src/macos.rs`, runs on any macOS runner |
| Integration | Open a real `utun`, assign an address, write and read a packet | `macos-14` GitHub runner with `sudo`, gated on `target_os` |
| Loopback | Two `karstd` instances on one Mac over loopback, real `utun` each, TCP under an ACL | New `bins/karstd/tests/macos_pair.rs`. This is the closest thing to `two_nodes.rs` that macOS allows |
| Cross-platform | A Mac and a Linux host, real NAT, direct path | `scripts/two-host-test.sh` already exists for exactly this shape and takes two ssh destinations; extend it to cope with a non-Linux host |
| Manual | Sleep/wake, network change, Gatekeeper on a clean machine, the full install from a downloaded `.pkg` | The W8–W10 walkthrough, [09](09-exit-criteria.md) |

Add a `macos` job to `.github/workflows/ci.yml` building both architectures and
running the unit and integration tiers on every push. The signing job runs only
on tags — notarization is slow and rate-limited, and a per-push notarization
queue is a per-push wait.

## 9. Schedule

| Week | Work |
|---|---|
| W2 | `macos.rs`: `utun` open, AF prefix, read/write; unit tests |
| W3 | Addressing, routes, `local_addresses`, `default_gateway`; name-is-not-ours audit |
| W4 | `karstd` runs end to end on macOS; loopback pair test |
| W5 | DNS: `/etc/resolver`, dynamic store, revert, cache flush |
| W6 | LaunchDaemon, sleep/wake, log paths, config location |
| W7 | `.pkg`, universal binary, install/uninstall scripts |
| W8 | Signing, notarization, stapling, clean-machine verification |

## 10. Exit criteria

1. A downloaded, notarized `.pkg` installs on a clean macOS 13+ machine with
   no Gatekeeper warning and no terminal.
2. The node enrols from the console's auth key and reaches a peer directly
   across a NAT.
3. Mesh names resolve; `/etc/resolver` state is reverted on uninstall and
   after a `SIGKILL`.
4. Sleep, wake, and a network change recover the path without a restart —
   demonstrated manually, recorded in the walkthrough.
5. Uninstall removes the daemon, the binaries, and every DNS change, leaving
   the machine's resolvers as they were.
