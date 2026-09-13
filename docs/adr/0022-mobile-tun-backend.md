<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-0022: Mobile TUN backend — adopting a platform-supplied descriptor

- **Status:** Accepted (the `karst-tun` backend below); the UniFFI crate
  boundary in Consequences/Reconsider is not yet implemented — see there.
- **Date:** 2026-09-13
- **Deciders:** Adrian Anderson (project owner)
- **Related:** ADR-0003 (greenfield Rust datapath, unsafe confined to `sys*`
  modules), ADR-0012 (userspace network stack — a different problem, see
  Alternatives), PLAN.md §9/§10 Phase 7, GitHub issue #117

---

## Context

PLAN.md §9 names the mobile mechanism as "`NetworkExtension`/`VpnService`,
Rust core via UniFFI" but had never been elaborated past that one line before
this ADR — no `plans/phase-7/` directory exists, and `crates/karst-tun` did
not compile for `target_os = "ios"` or `"android"` at all (no `Tun` binding
resolved for either). Phase 7 does not open until Nov 2026 on the plan's own
schedule; this ADR and the code alongside it are foundational work, not a
claim that the phase has started.

`karst-tun`'s existing three backends (`linux`, `macos`, `windows`) all
**create** the tunnel interface themselves and need a privilege to do it —
`CAP_NET_ADMIN`, root, or Administrator. Neither mobile OS permits that from
a native library: only the platform's own app-extension code
(`NEPacketTunnelProvider` on iOS, `VpnService` on Android) may create the
tunnel, and it is Swift or Kotlin code that does so, not anything this
workspace's Rust reaches. The most a native core can ever be handed is the
resulting file descriptor, after the fact.

Two further constraints came from reading each platform's actual contract,
not from assumption:

- **iOS's `packetFlow` fd is a `utun` socket under the hood** — the same
  kernel primitive `macos::Tun` already targets. Reaching it needs the
  private (undocumented, but stable and used in production by `WireGuard`'s
  and Tailscale's own iOS apps, since Apple has shipped no public
  alternative) `socket.fileDescriptor` key-value lookup on
  `NEPacketTunnelProvider.packetFlow`. It carries the same four-byte
  address-family prefix every `utun` frame does.
- **Android's fd, by contrast, is documented as a plain `IFF_TUN`-style
  descriptor** — bare IP packets, no header — the same contract
  `linux::Tun` already implements with `IFF_NO_PI` set.

So the two platforms need the same *shape* of backend (adopt an externally
created fd) but two different, already-implemented framings.

## Decision

`crates/karst-tun/src/mobile.rs`, compiled for `any(target_os = "ios",
target_os = "android")`, adds a fourth `Tun`:

- `Tun::from_fd(fd: RawFd, cfg: &TunConfig) -> Result<Self, TunError>` —
  `unsafe`, adopting a fd the caller already owns and is transferring.
  `RawFd` is a plain `i32` any safe caller can invent, so nothing about
  taking ownership of one can be checked from inside the function; this is
  the same reason `OwnedFd::from_raw_fd` is `unsafe` in `std` itself. It is
  the only new addition to the `unsafe` surface ADR-0003 already permits,
  confined the same way: one `unsafe` block, one stated safety argument.
- iOS's `recv`/`send` reuse [`crate::macos_wire`]'s `af_header`/
  `family_agrees` **verbatim** rather than re-deriving the same byte format
  a second time — that module already compiles and is tested on every
  platform for exactly this reason.
- Android's `recv`/`send` are the same bare read/write `linux::Tun` uses
  with `IFF_NO_PI` — no header to add or strip.
- **Ownership matches the other three backends: dropping `Tun` closes the
  descriptor.** Android's `ParcelFileDescriptor.detachFd()` and iOS's
  private lookup both transfer ownership to native code once called, and a
  stopped tunnel closing its fd is how the OS learns the session ended — the
  same signal `linux`/`macos`/`windows` send by tearing down their own
  interface. The mobile OS is the resource's origin, not its owner once
  handed off.
- No `ifindex`, no address/route assignment. Both remain the platform's own
  job (`NEPacketTunnelNetworkSettings` / `VpnService.Builder`), configured
  before the fd this module adopts ever exists — `Tun::name` is cosmetic,
  documented as such, and nothing above this crate should read it as an
  identity.

### Alternatives rejected

- **A single cross-platform "raw fd" backend with a runtime framing flag**
  instead of two `#[cfg]`-gated `impl` blocks. Rejected: the framing
  difference is a compile-time fact about the platform, not a runtime
  configuration choice, and a runtime branch would let a build for one
  platform silently carry dead code for the other's framing — exactly the
  class of mistake `#[cfg]` catches at compile time instead.
- **Re-deriving iOS's framing independently of `macos_wire`.** Rejected on
  sight: it is the same kernel primitive carrying the same bytes, and a
  second, separately-tested implementation of one wire format is a second
  place for it to drift from the first with no compiler in between.
- **ADR-0012's userspace/`smoltcp` stack as the mobile backend instead of a
  fd adoption.** Rejected: that stack solves "no privilege to create a TUN
  device," which is not mobile's problem — mobile's OS *does* create a real
  tunnel interface, and hands Karst the resulting fd. Routing Karst's own
  packets through a second, synthetic IP stack on top of an fd that already
  carries real ones would add a redundant layer for no capability gained.
- **Not closing the fd on `Tun`'s drop**, on the theory that a resource the
  mobile OS handed over should be the OS's to reclaim. Rejected: both
  platforms' own handoff APIs (`detachFd`, the private fd lookup) are
  documented/understood as a transfer, not a loan, and every other backend
  in this crate already signals "tunnel stopped" by closing its interface —
  matching that is less surprising than a fourth backend behaving
  differently for a reason a caller would have to already know.

---

## Consequences

### Positive

- `karst-tun` now compiles for `aarch64-linux-android` and
  `aarch64-apple-ios` (checked directly, both targets, this session) with
  zero duplicated framing logic — the two mobile `impl Tun` blocks are each
  under 40 lines because the hard part (the byte formats) was already
  written and tested for `macos`/`linux`.
- The `unsafe` surface this adds is exactly one function, matching ADR-0003's
  existing discipline rather than opening a second style of exception to it.

### Negative

- **Nothing here can be exercised by a test that actually runs.** This
  project has no iOS or Android CI runner (unlike Windows/macOS, which use
  real `windows-latest`/`macos-latest` GitHub-hosted runners) and no device
  or emulator in this environment. `ci.yml`'s new `mobile-tun` job checks
  compilation and lints only — a real fd-adoption test, the mobile
  equivalent of `karst-tun/tests/windows_adapter.rs`'s
  `creates_a_real_adapter_the_os_agrees_exists`, does not exist yet and
  should not be claimed as covered until a runner or device can actually run
  it. This is the same "do not invent a test with no way to run it even
  once" rule that test file's own history already follows.
- The UniFFI crate boundary PLAN.md §9 names — what mobile app code actually
  links against, and where `Tun::from_fd`'s `unsafe` contract gets enforced
  at the FFI edge rather than merely documented — **is not built yet.** This
  ADR decides the `karst-tun` piece underneath it; the binding crate, the
  Swift/Kotlin sides, `NEPacketTunnelProvider`/`VpnService` glue, enrollment,
  and app packaging are all still open. Do not read this ADR as "the mobile
  clients exist."
- iOS's fd-retrieval mechanism is undocumented by Apple. It has held stable
  across `WireGuard`'s and Tailscale's shipped apps for years, which is
  evidence of practical stability, not a guarantee — a future iOS release
  could change or remove it, and there is no fallback path designed here if
  it does.

### Reconsider if

- Apple ships a public, non-KVC way to obtain `packetFlow`'s underlying
  socket, or removes the private path this relies on.
- The UniFFI crate boundary, once designed, needs `Tun::from_fd`'s contract
  reshaped — e.g. if ownership should transfer back to the platform side on
  a graceful stop rather than always closing, which nothing in the two
  platforms' documented APIs currently asks for but a real app's lifecycle
  testing might surface.
