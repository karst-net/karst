<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-0027: `Karst.app` ↔ the macOS `PacketTunnelProvider` — which IPC channel

- **Status:** Proposed
- **Date:** 2026-09-16
- **Deciders:** Adrian Anderson (project owner)
- **Related:** ADR-0026 (macOS NetworkExtension backend — item 5, which named
  this gap without designing it), ADR-0022 (mobile TUN backend and the
  UniFFI boundary this assumes), `plans/phase-6/13-macos-status-indicators.md`
  (`Karst.app`/`KarstStatus`'s existing status-socket design, which this
  compares against)

---

## Context

ADR-0026 item 5 named the gap without deciding it: *"today's plain Unix
status socket pattern does not carry over unmodified into a sandboxed
extension."* This ADR is that decision — options, not yet chosen between,
with a recommendation.

**What changes and what doesn't.** Today, `karstd` and `Karst.app`
(`packaging/macos/KarstStatus`) are two independent OS processes: a root
LaunchDaemon and a per-user LaunchAgent, talking over a Unix domain socket at
`/var/run/karst-status/karstd.sock` (`ipc.rs`'s unprivileged listener,
`AppDelegate.swift`'s `StatusClient` polling it every two seconds). Under
NetworkExtension, the Karst protocol engine (PHREATIC/AVEN/Ponor — ADR-0022's
UniFFI boundary) moves **inside** the `PacketTunnelProvider` system
extension's own process, linked directly rather than spawned. That is not an
IPC question at all — the Swift provider code calling into the linked Rust
core is a plain FFI call, the same shape ADR-0022 already committed to for
iOS.

**The IPC question is specifically between two processes this project still
does not control the boundary of**: `Karst.app` (the menu-bar host,
`Karst.app`'s existing bundle) and the `PacketTunnelProvider` extension
process, which is sandboxed. `Karst.app` cannot open a Unix socket into the
extension's container the way it opens one into `karstd`'s `/var/run` today —
there is no `/var/run` equivalent reachable from inside App Sandbox, and
nothing in this project has ever needed to reach *into* a sandboxed process
before now.

Apple's documented, supported channel for exactly this pair — a container app
talking to its own `NEPacketTunnelProvider` extension — is
[`NETunnelProviderSession.sendProviderMessage(_:responseHandler:)`](https://developer.apple.com/documentation/networkextension/netunnelprovidersession/sendprovidermessage(_:responsehandler:))
on the app side, answered by
[`NETunnelProvider.handleAppMessage(_:completionHandler:)`](https://developer.apple.com/documentation/networkextension/netunnelprovider/1406545-handleappmessage)
overridden in the extension. Both are stable public API, unlike the private
`packetFlow.socket.fileDescriptor` lookup ADR-0022 already accepted the risk
of — this is not a second private-API dependency.

Two properties of that channel matter for this decision:

- **It is request/response, app-initiated only.** The extension cannot push a
  state change to `Karst.app` between polls. This is not a regression:
  `Karst.app` already polls `karstd` on a two-second timer rather than being
  pushed to, so the existing `AppDelegate.swift` polling-loop shape carries
  over unchanged — only the transport underneath `StatusClient` changes.
- **A message can launch the extension if it is not already running**, per
  Apple's own documentation. What that means for a two-second poll against a
  System Extension's tighter resource/lifecycle budget (ADR-0026's own
  "Negative" consequences already flag this class of constraint) has not been
  measured and should not be assumed benign — Apple Developer Forum threads
  report inconsistent behavior across OS versions when the tunnel is
  disconnected, which is exactly the "reads better than it behaves" gap a
  real Mac has to close, not this ADR.

## Decision

Use `sendProviderMessage`/`handleAppMessage` as the primary channel, carrying
the **same JSON body `Command::StatusJson` already produces**
(`bins/karstd/src/run.rs`'s `status_json()`) rather than a new schema:

1. **Wire format: reuse, not reinvent.** The extension's `handleAppMessage`
   handler calls the same status-assembly path the LaunchDaemon build's
   `Command::StatusJson` calls today — through the FFI boundary rather than a
   socket, since the Rust core is linked in-process — and returns the same
   `StatusJson` bytes verbatim. `Karst.app`'s `StatusParser`-equivalent then
   needs zero format changes between the LaunchDaemon build and the NE build,
   only a transport swap in `StatusClient`.
2. **`Karst.app`'s polling loop is unchanged in shape.** `AppDelegate.swift`'s
   `Timer.scheduledTimer` and `refresh()` stay as they are; only
   `StatusClient`'s connect-and-request internals change from a `Unix socket`
   to `NETunnelProviderManager.loadAllFromPreferences` (cached, not reloaded
   every tick) plus `sendProviderMessage` on the resulting session.
3. **No App Group / shared container for v1.** Nothing today needs state to
   survive independently of a live request/response — `karst status`'s text
   form has no push consumer either. Revisit only if a future feature
   (background notifications when a peer drops, say) needs the extension to
   originate a signal rather than answer one.
4. **Enrollment is the one piece this does not solve.** `sendProviderMessage`
   needs a loaded `NETunnelProviderManager` to call it on, which means a VPN
   configuration must already have been created and saved — today's
   `karst-setup` flow instead writes local keys/config files directly for a
   LaunchDaemon `karstd` to read on its next start. Whether `karst-setup`
   gains an `NETunnelProviderManager`-saving path, or enrollment becomes a
   distinct step from "create the VPN configuration," is genuinely open and
   is the next design question once this one is settled — not decided here.

### Alternatives rejected

- **XPC (`NSXPCConnection`) to a purpose-built service.** Rejected for v1:
  it is more machinery (a defined protocol, a listener, connection
  lifecycle) for the same request/response shape `sendProviderMessage`
  already gives for free as part of the NetworkExtension API Karst needs
  regardless. Worth reconsidering only if a future requirement needs
  something `sendProviderMessage` structurally cannot do — bidirectional
  streaming, say.
- **Darwin notify center (`CFNotificationCenterGetDarwinNotifyCenter`) as the
  primary channel.** It carries no payload — only "something changed,"
  requiring a second channel for the actual data — and Apple's own
  documentation search turned up no example pairing it with
  `NEPacketTunnelProvider` specifically, unlike `sendProviderMessage`, which
  is the API surface built for this exact pair. Noted as a possible future
  optimization (skip a poll tick's `sendProviderMessage` round trip when
  nothing changed), not a v1 requirement — `Karst.app` already tolerates a
  two-second-stale poll today.
- **Porting today's Unix-socket protocol as-is, tunneled through
  `sendProviderMessage`'s single `Data` payload.** Rejected as an unnecessary
  extra layer: `Command`/reply framing exists to multiplex several verbs
  (`status`, `dns-status`, `metrics`, …) over one long-lived socket
  connection. `sendProviderMessage` is already message-oriented and
  per-call, so the framing it exists to provide would be redundant — the
  message payload can just *be* the JSON body, with the verb (if more than
  status is ever needed here) as a field in it rather than a wire-level
  command line.

---

## Consequences

### Positive

- Zero new wire format: the LaunchDaemon build and the NE build's `Karst.app`
  render identically from the same JSON `status_json()` already produces and
  already has a test (`status_json_reports_the_same_facts_as_status_text`).
- No second private-API dependency alongside ADR-0022's `packetFlow` fd
  lookup — `sendProviderMessage`/`handleAppMessage` are public, stable,
  years-old API.
- `AppDelegate.swift`'s existing polling architecture needs no redesign, only
  a transport swap inside `StatusClient` — the smallest change that closes
  the gap ADR-0026 named.

### Negative

- **Unverified against a real System Extension's actual behavior.** Every
  claim above about `sendProviderMessage`'s behavior when the tunnel is
  disconnected, and about polling cadence against extension lifecycle, comes
  from Apple's documentation and third-party forum reports, not from running
  code — there is no Mac in this environment to build or exercise either
  side. Treat this ADR as the shape to build, not as proof it behaves this
  way in practice.
- Enrollment (this ADR's own decision item 4, above) is now the next named
  gap rather than a solved one — this ADR narrows ADR-0026 item 5 to the
  status-reporting slice of it and explicitly does not design the
  configuration-creation slice.
- `karst-dns`'s `HostRuntime::NetworkExtension` variant (ADR-0026 item 4, put
  on hold pending this ADR) is still not unblocked by this decision alone: it
  additionally needs the *outbound* direction — the extension pushing DNS
  settings into `NEDNSSettings` — which is a `setTunnelNetworkSettings` call
  inside the extension itself, not a message over this channel at all. This
  ADR only settles how `Karst.app` reads status back out.

### Reconsider if

- A real build shows `sendProviderMessage` behaving unreliably against a
  disconnected/idle extension in a way that makes two-second polling
  impractical — the forum reports found while researching this ADR disagree
  with each other across OS versions, which is reason enough to verify
  early rather than assume.
- A future requirement needs the extension to originate a signal (a
  notification on peer loss, say) rather than only answer polls — that is
  the point to add Darwin notify center as a "poll now" nudge rather than
  redesigning the primary channel.
