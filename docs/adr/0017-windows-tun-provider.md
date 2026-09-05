<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-0017: Windows TUN provider

- **Status:** Proposed
- **Date:** 2026-09-04
- **Deciders:** Pending maintainer and written distribution review
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

## Proposed decision

Use the official, unmodified AMD64 Wintun DLL through its documented API,
loaded at runtime from the protected installation directory by absolute path.
Do not search the working directory or PATH for the DLL. Keep the DLL and its
license separate from the MIT/Apache Rust code; do not add GPL source or a
Wintun Cargo wrapper. Use `windows-sys` for Win32 declarations, with unsafe
wrappers confined to the TUN crate per ADR-0003.

Before bundling a DLL, obtain the written distribution review required by the
Windows plan, covering the actual prebuilt license and proposed MSI layout.
Record its date, reviewer, scope, and result here before accepting this ADR.
Packaging must pin the archive digest, retain the license and notices, and
verify the upstream DLL signature on Windows. Karst signs its executables and
installer in Phase 8, leaving the upstream DLL unchanged. The project owner
deferred paid signing on 2026-09-05 due to cost; Phase 6 permits unsigned Karst
artifacts. This does not waive verification of the upstream DLL signature.

Until that review lands, proceed with portable networking CI and platform
boundary work. If it is still unresolved at the end of W2, use ADR-0012's
userspace stack as the engineering fallback. This does not imply that the
Windows daemon, service, or installer already works.

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

Signing-provider selection (Phase 8), SCM lifecycle, protected state storage, IP Helper
routing, NRPT recovery, MSI upgrades/uninstall, and clean-machine testing remain
open work. This ADR does not satisfy those release gates.
