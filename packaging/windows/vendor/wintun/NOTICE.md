<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Wintun, vendored

This directory carries the unmodified, amd64 `wintun.dll` from Wintun 0.14.1,
loaded by `karst-tun`'s Windows backend via `LoadLibraryExW` against the
documented API in `wintun.h` — never as a Cargo dependency, and never
searched for on `PATH` (ADR-0017). It is not part of the MIT/Apache Rust
tree and `deny.toml`'s license gate does not apply to it.

- **Source:** <https://www.wintun.net/builds/wintun-0.14.1.zip>
- **Archive SHA-256:**
  `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51` — matches
  the digest [ADR-0017](../../../docs/adr/0017-windows-tun-provider.md)
  recorded when the project owner reviewed and approved this distribution.
- **`wintun.dll` (amd64) SHA-256:** `e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce`
  — pinned in `wintun.dll.sha256`; `scripts/build-windows-msi.ps1` checks the
  vendored file against it before every build.
- **Authenticode signer:** `WireGuard LLC` (DigiCert EV Code Signing CA
  (SHA2), timestamped by DigiCert), verified at build time on Windows via
  `Get-AuthenticodeSignature`.
- **License:** `LICENSE.txt` in this directory, copied unmodified from the
  archive. It permits redistribution alongside software that uses only the
  documented API (§3(d)) — exactly `karst-tun`'s use — and requires the
  notices in this file and that license text to travel with the binary.

Only the amd64 build is vendored: Phase 6 is x64-only
(`packaging/windows/Product.wxs`'s own note on `-arch x64`). Re-review under
ADR-0017 is required before replacing this file with a newer Wintun release
or a different architecture.
