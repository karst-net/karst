<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-0017: Windows TUN provider

- **Status:** Accepted
- **Date:** 2026-09-04 (proposed); accepted 2026-09-10
- **Deciders:** Adrian Anderson (project owner)
- **Related:** ADR-0003, ADR-0007, ADR-0012; [Windows plan](../../plans/phase-6/10-windows-client.md)

## Context

The Windows port needs a kernel TUN provider. The original handoff treated
Wintun's GPL source license as the license for its signed binary distribution.
Upstream distinguishes those artifacts: its [download page](https://www.wintun.net/)
says the prebuilt signed DLLs use a separate license supplied in the archive.

On 2026-09-04 we downloaded [Wintun 0.14.1](https://www.wintun.net/builds/wintun-0.14.1.zip),
verified SHA-256
`07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51`
against that page, and read `wintun/LICENSE.txt`. Section 1 limits the license
to the archive's precise DLL contents. Section 3(d) provides a redistribution
exception for accompanying software using only the permitted API. Sections
3(a–c) restrict modification and removal of notices; section 3(e) restricts
endorsement. This is evidence for review, not a recorded legal approval.

ADR-0015 is already the CNSA decision; this proposal uses the next free number.

### Distribution review

On 2026-09-10 the project owner (Adrian Anderson) reviewed this ADR's
evidence — the verified `wintun/LICENSE.txt` terms above and the proposed
layout below (unmodified DLL, loaded from the protected install directory,
kept separate from the MIT/Apache Rust tree) — and approved bundling the
unmodified Wintun 0.14.1 DLL in the Karst MSI on that basis: the binary
license's §3(d) redistribution exception covers accompanying software that
only calls the documented API, which is what this ADR proposes, and the DLL
is not a Cargo dependency so `deny.toml`'s MIT/Apache gate does not apply to
it. This is the project owner's distribution decision, not outside legal
counsel's; nothing here should be read as a formal legal opinion. Re-review
is required if the archive's terms or contents change.

## Decision

Use the official, unmodified AMD64 Wintun DLL through its documented API,
loaded at runtime from the protected installation directory by absolute path.
Do not search the working directory or PATH for the DLL. Keep the DLL and its
license separate from the MIT/Apache Rust code; do not add GPL source or a
Wintun Cargo wrapper. Use `windows-sys` for Win32 declarations, with unsafe
wrappers confined to the TUN crate per ADR-0003.

The written distribution review required by the Windows plan is recorded
above. Packaging must pin the archive digest, retain the license and notices,
and verify the upstream DLL signature on Windows. Karst signs its executables
and installer in Phase 8, leaving the upstream DLL unchanged. The project
owner deferred paid signing on 2026-09-05 due to cost; Phase 6 permits
unsigned Karst artifacts. This does not waive verification of the upstream
DLL signature.

The review having landed favorably, the W2 hard deadline for taking
ADR-0012's userspace stack as a licensing fallback does not apply. Userspace
mode remains available as a contingency — see Alternatives — should upstream
terms or availability change.

### Alternatives

- Building Wintun from GPL source changes the licensing and signing problem;
  it is outside this proposal.
- A custom driver requires a separate implementation and signing effort.
- Userspace mode avoids the driver but lacks host kernel routing. Retain it
  as the contingency, with that limitation documented in release criteria.

## Consequences

The binary license is a more specific basis for review than an aggregation
argument about the GPL source. Distribution still has obligations outside the
Cargo dependency license gate. A changed DLL release requires a fresh license,
hash, and signature check. Reconsider this proposal if review rejects the
layout or upstream changes the terms or availability.

`crates/karst-tun/src/windows.rs` and `sys_windows.rs` now implement the
adapter/session/ring I/O, the shutdown event, and IP Helper addressing and
routing this ADR proposed, checked (not yet run) against `windows-sys`
0.61.2 on `x86_64-pc-windows-gnu`. Signing-provider selection (Phase 8), SCM
lifecycle, protected state storage, NRPT recovery, MSI packaging (which is
also where `wintun.dll` acquisition and hash-pinning land), upgrades/
uninstall, and clean-machine testing remain open work. This ADR does not
satisfy those release gates.
