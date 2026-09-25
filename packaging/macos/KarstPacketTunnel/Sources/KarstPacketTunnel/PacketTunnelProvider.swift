// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

import Foundation
import KarstFFI
import NetworkExtension
import os.log

/// The macOS System Extension's `NEPacketTunnelProvider`.
///
/// docs/adr/0026-macos-network-extension-backend.md item 2's Rust `Tun`
/// backend (`crates/karst-tun`'s `network-extension` feature) is what
/// `startTunnel` drives `packetFlow` through, via `crates/karst-ffi`'s
/// `EngineHandle` (ADR-0030) — `KarstFFI`'s committed bindings were
/// regenerated on a real macOS host with `--features network-extension`
/// (see `Sources/KarstFFI/karst_ffi.swift`'s own header comment), so
/// `EngineHandle` now exists to call. `handleAppMessage`'s `"enroll"` verb
/// needed no such wait: `enrollInvitation` compiles the same on every
/// platform (ADR-0029).
///
/// **What is wired and what is still unverified.** `handleAppMessage`'s
/// `"enroll"`/`"re-enroll"`/`"identity"` verbs are verified end-to-end on
/// a signed, notarized, activated extension (#159, closed): activation,
/// entitlements (self-service, #156), and real enroll/re-enroll/identity
/// round trips all confirmed on real hardware. `startTunnel` itself is
/// real progress, not placeholder code, but still not a confirmed success
/// (#161, open): on the one real test rig available so far — itself an
/// Apple Virtual Machine, not real hardware — `packetFlow`'s private fd
/// never resolves even after a bounded retry, for reasons that may be
/// specific to running inside a VM rather than a bug in this file. Real
/// peer traffic, and therefore `networkSettings(fromStatusJSON:)`'s
/// AllowedIPs/exit-route-as-routes mapping (#160) actually taking effect,
/// remain unverified past compiling until #161's real-hardware test
/// happens. DNS is deliberately left unset —
/// `plans/phase-5/06-macos-client.md` §5's KarstDNS search-list gap is a
/// known, already-accepted limitation, not new scope for this file.
final class PacketTunnelProvider: NEPacketTunnelProvider {
    private static let log = OSLog(subsystem: "dev.karst.packettunnel", category: "provider")

    /// Where this extension keeps its own state — never `/etc/karst`, the
    /// now-removed `LaunchDaemon` build's namespace (ADR-0026 item 8,
    /// amended: NetworkExtension is the sole macOS backend now, but the
    /// distinct root-owned directory this chose while both builds still
    /// coexisted costs nothing to keep).
    ///
    /// **Why a plain root-owned path, not an App Group container.** A
    /// System Extension and its host app run as different users — root and
    /// the console user — so an App Group container is *not* the shared
    /// path it looks like: each side resolves it under its own home
    /// (`/private/var/root/Library/Group Containers/...` for the
    /// extension, `/Users/<user>/Library/Group Containers/...` for
    /// `Karst.app`), which is two separate directories, not one. This
    /// extension never needs to share these files with `Karst.app` at all
    /// — enrollment crosses via `sendProviderMessage`
    /// (docs/adr/0027-macos-system-extension-host-app-ipc.md), not a
    /// shared file — so there is nothing an App Group would actually buy
    /// here. `PacketTunnel.entitlements` carries no
    /// `com.apple.security.app-sandbox` entitlement, so this process is
    /// confined by what its own (root) UID can reach — not confined to a
    /// container the way a fully App-Sandboxed process would be. Checked
    /// against public developer-forum reports of this exact app/extension
    /// split (root vs. console user, App Groups not bridging them), and
    /// since confirmed correct end-to-end on real hardware (#159).
    private static let stateDir = "/Library/Application Support/dev.karst.packettunnel"

    /// The identity file a completed enrollment leaves behind —
    /// docs/adr/0028-macos-network-extension-enrollment.md item 3. Mirrors
    /// `karstd`'s own `identity_key_file` in shape and, now, in being a
    /// real root-owned directory rather than a LaunchDaemon-shaped
    /// placeholder — see `stateDir`'s own doc comment for why it is not
    /// `/etc/karst`.
    private static let identityPath = "\(stateDir)/identity.key"

    /// As `identityPath`. `enrollInvitation` (ADR-0029) writes a full
    /// `karstd`-shaped `config.toml` here, mirroring `karst-setup`'s own
    /// `config_path`/`state_dir` split
    /// (`bins/karstd/src/enrollment.rs::enroll_bundle`).
    private static let configPath = "\(stateDir)/config.toml"

    /// The socket `EngineHandle.start` binds its control-plane listener to
    /// — this process is both ends of it (see `EngineHandle.statusJson`'s
    /// own doc comment), so it lives in this extension's own state
    /// directory rather than `/var/run/karst`'s privileged, LaunchDaemon-
    /// build one.
    private static let socketPath = "\(stateDir)/control.sock"

    /// Held from a successful `startTunnel` until `stopTunnel` — the
    /// `"status"` app-message verb reads it, and `stopTunnel` calls
    /// `EngineHandle.stop()` on it. `NEPacketTunnelProvider` gets a fresh
    /// instance per activation, so this does not need to survive a
    /// stop/start cycle within one instance, only outlive the single
    /// `startTunnel` call that creates it.
    private var engine: EngineHandle?

    /// The utun descriptor this session's engine adopted, released from
    /// `ownedDescriptors` at stop.
    private var adoptedDescriptor: Int32?

    /// utun descriptors adopted by live engines in this process. A system
    /// extension's process outlives its sessions, and a new session can start
    /// while the previous one's socket is still open (found on the lab Mac
    /// switching between two configurations): scanning for "the" utun socket
    /// then found the old one first, and the new engine read a dead
    /// interface. The scan skips descriptors claimed here.
    private static var ownedDescriptors = Set<Int32>()
    private static let ownedDescriptorsLock = NSLock()

    private static func releaseDescriptor(_ fd: Int32) {
        ownedDescriptorsLock.lock()
        ownedDescriptors.remove(fd)
        ownedDescriptorsLock.unlock()
    }

    /// Polls `engine.statusJson()` on a fixed interval so routing reflects
    /// live state instead of the one-time snapshot `startTunnel` took —
    /// closes the mid-session gap `networkSettings(fromStatusJSON:)`'s own
    /// doc comment names (#158/docs/adr/0030-embedded-engine-lifecycle.md
    /// item 4) and, per
    /// docs/adr/0031-managed-device-mode-reconsiders-adr-0024.md, is what
    /// makes an MDM-set `includeAllNetworks` mean something in practice:
    /// this timer's unhealthy branch (`pollHealth()`) never tears the
    /// session down, so a fallback route outside the tunnel never reopens.
    /// `EngineHandleProtocol` (`Sources/KarstFFI/karst_ffi.swift`) exposes
    /// only `statusJson()`/`stop()` — confirmed by reading the generated
    /// FFI bindings, not assumed — so polling is the only mechanism
    /// available today; there is no callback to react to instead.
    private var healthTimer: DispatchSourceTimer?

    /// Where `healthTimer` fires. A dispatch timer on its own queue, not a
    /// `Timer`: see `startHealthTimer`.
    private let healthQueue = DispatchQueue(label: "dev.karst.packettunnel.health")

    /// The routing-relevant fingerprint (`routeSignature`) of whatever was
    /// last actually handed to `setTunnelNetworkSettings` — lets
    /// `pollHealth()` skip re-applying settings that have not changed,
    /// rather than touching the routing table every poll unconditionally.
    private var lastAppliedRouteSignature: String?

    private static let healthPollInterval: TimeInterval = 2.0

    override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        os_log("startTunnel", log: Self.log, type: .info)
        // Everything below runs on its own 8 MiB thread and calls
        // `completionHandler` from there, never on NetworkExtension's callout
        // thread. Found on the lab Mac: waiting for the utun descriptor with
        // that thread blocked sometimes starved NetworkExtension's own
        // creation of the interface, which then appeared just after the wait
        // gave up (a failed start right after a configuration switch). The
        // large stack also covers the Rust calls (`onLargeStack`'s reason).
        let worker = Thread { [self] in
            startTunnelOnWorker(completionHandler: completionHandler)
        }
        worker.stackSize = 8 << 20
        worker.start()
    }

    private func startTunnelOnWorker(completionHandler: @escaping (Error?) -> Void) {
        // Any failure after the descriptor was claimed releases the claim: the
        // engine (or its failed start) has closed it.
        let finish: (Error?) -> Void = { [weak self] error in
            if error != nil, let self, let fd = self.adoptedDescriptor {
                Self.releaseDescriptor(fd)
                self.adoptedDescriptor = nil
            }
            completionHandler(error)
        }
        if let error = Self.enrollFromPendingInvitation() {
            finish(error)
            return
        }

        guard FileManager.default.fileExists(atPath: Self.identityPath) else {
            // Mirrors `bins/karstd/src/setup.rs`'s `from_stdin`'s own
            // `resume` branch: never invent a tunnel out of a device that
            // was never enrolled.
            finish(PacketTunnelProviderError.notEnrolled)
            return
        }

        guard let fd = Self.adoptedFileDescriptorRetrying(from: packetFlow) else {
            finish(PacketTunnelProviderError.noPacketFlowDescriptor)
            return
        }
        adoptedDescriptor = fd

        let handle: EngineHandle
        do {
            // `fd`'s exclusive ownership transfers to `EngineHandle.start`
            // here — `karst_tun::Tun::from_fd`'s contract, carried across
            // this boundary rather than re-derived (`EngineHandle.start`'s
            // own `# Safety` doc comment).
            handle = try Self.startEngineOnLargeStack(fd: fd)
        } catch let error as FfiError {
            finish(PacketTunnelProviderError.engine(Self.message(from: error)))
            return
        } catch {
            finish(error)
            return
        }
        engine = handle

        // Captured once and reused for both the initial settings and the
        // health timer's baseline signature below, rather than calling
        // `statusJson()` twice for what is, at this instant, the same
        // status.
        let statusJSON: String
        do {
            statusJSON = try handle.statusJson()
        } catch let error as FfiError {
            handle.stop()
            engine = nil
            finish(PacketTunnelProviderError.engine(Self.message(from: error)))
            return
        } catch {
            handle.stop()
            engine = nil
            finish(error)
            return
        }

        let settings: NEPacketTunnelNetworkSettings
        do {
            settings = try Self.networkSettings(fromStatusJSON: statusJSON)
        } catch {
            handle.stop()
            engine = nil
            finish(error)
            return
        }

        setTunnelNetworkSettings(settings) { [weak self] error in
            guard let self else {
                finish(error)
                return
            }
            if error != nil {
                self.engine?.stop()
                self.engine = nil
            } else {
                self.lastAppliedRouteSignature = Self.routeSignature(fromStatusJSON: statusJSON)
                self.startHealthTimer()
            }
            finish(error)
        }
    }

    override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        os_log("stopTunnel: %{public}@", log: Self.log, type: .info, String(describing: reason))
        healthTimer?.cancel()
        healthTimer = nil
        // `EngineHandle.stop()` both requests shutdown and joins (that
        // method's own doc comment on why `Drop` alone does not) — exactly
        // what a caller waiting to report "fully stopped" needs.
        engine?.stop()
        engine = nil
        if let fd = adoptedDescriptor {
            Self.releaseDescriptor(fd)
            adoptedDescriptor = nil
        }
        completionHandler()
    }

    /// Starts `healthTimer` — split out of `startTunnel` only so its own
    /// doc comment has somewhere to live next to the `RunLoop` detail it's
    /// actually about.
    ///
    /// **Open risk, not yet verified on real hardware**: whether a
    /// `Timer` scheduled here actually fires reliably for the lifetime of
    /// a `NEPacketTunnelProvider` extension process, which has a tighter
    /// resource/lifecycle budget than an ordinary app — flagged in
    /// docs/adr/0031-managed-device-mode-reconsiders-adr-0024.md's
    /// Negative consequences rather than assumed benign.
    private func startHealthTimer() {
        // A dispatch timer, not `Timer.scheduledTimer` + `RunLoop.current`:
        // this runs inside `setTunnelNetworkSettings`' completion handler,
        // on a NetworkExtension dispatch-queue thread whose run loop nobody
        // runs, so a `Timer` added there was scheduled and never fired.
        // Found on real hardware: the poll never ran, so a subnet route
        // added mid-session reached the engine's netmap but never the
        // kernel, and nothing this poll exists for (route churn, exit
        // activation/withdrawal, reasserting) could happen.
        let timer = DispatchSource.makeTimerSource(queue: healthQueue)
        timer.schedule(deadline: .now() + Self.healthPollInterval, repeating: Self.healthPollInterval)
        timer.setEventHandler { [weak self] in
            self?.pollHealth()
        }
        timer.resume()
        healthTimer = timer
    }

    /// `healthTimer`'s tick. Two outcomes, both documented in
    /// `healthTimer`'s own doc comment as the point of this method
    /// existing at all:
    ///
    /// - `engine.statusJson()` throws (or `engine` is already `nil`): the
    ///   engine is unreachable. Sets `reasserting = true` and returns —
    ///   routing is left exactly as last applied. This method must never
    ///   call `stopTunnel`/`cancelTunnelWithError`/
    ///   `setTunnelNetworkSettings(nil)` from this branch: any of those
    ///   would end the session and let the OS fall back to a route outside
    ///   the tunnel, which is precisely the fail-open outcome
    ///   docs/adr/0031-managed-device-mode-reconsiders-adr-0024.md exists
    ///   to avoid.
    /// - It succeeds: `reasserting = false`, and if the routing-relevant
    ///   fields have actually changed since `lastAppliedRouteSignature`,
    ///   settings are recomputed and reapplied — the same mechanism also
    ///   closes the pre-existing mid-session route-churn gap this file's
    ///   `networkSettings(fromStatusJSON:)` already documented (#158).
    ///
    /// **What this does not do.** It does not itself discard in-flight
    /// packets — this method has no access to `packetFlow` once
    /// `EngineHandle.start` took exclusive ownership of its file
    /// descriptor (that method's own `# Safety` doc comment), so active
    /// packet-level black-holing is out of reach from here today. Whatever
    /// blocking actually happens when the engine is unhealthy is an
    /// emergent property of "no fallback route exists (an MDM profile's
    /// `includeAllNetworks`) plus a dead/degraded engine," not new
    /// packet-dropping code in this method — stated plainly rather than
    /// implying a stronger guarantee than this file provides.
    private func pollHealth() {
        guard let engine else { return }
        let json: String
        do {
            json = try engine.statusJson()
        } catch {
            os_log(
                "KARST-TRACE health poll: engine unreachable, reasserting: %{public}@",
                log: Self.log, type: .default, error.localizedDescription
            )
            reasserting = true
            return
        }
        reasserting = false

        let signature = Self.routeSignature(fromStatusJSON: json)
        guard signature != lastAppliedRouteSignature else { return }
        guard let settings = try? Self.networkSettings(fromStatusJSON: json) else { return }
        lastAppliedRouteSignature = signature
        setTunnelNetworkSettings(settings) { error in
            if let error {
                os_log(
                    "KARST-TRACE health poll: setTunnelNetworkSettings failed: %{public}@",
                    log: Self.log, type: .default, error.localizedDescription
                )
            }
        }
    }

    /// A cheap, order-independent fingerprint of the routing-relevant
    /// fields `networkSettings(fromStatusJSON:)` derives its output from —
    /// addresses and routes, not the full status body — so `pollHealth()`
    /// can tell "nothing routing-relevant changed" from "something did"
    /// without giving `NEPacketTunnelNetworkSettings` an `Equatable`
    /// conformance Apple's own type does not have.
    static func routeSignature(fromStatusJSON json: String) -> String? {
        guard let status = try? JSONDecoder().decode(EngineStatus.self, from: Data(json.utf8)) else {
            return nil
        }
        var routes = status.peers.flatMap(\.allowedIps).filter { !isDefaultRoute($0) }
        routes += (status.control?.routing.routes ?? [])
            .filter { $0.kind == "exit" && $0.role == "recipient" && $0.active }
            .map(\.prefix)
        return (status.addresses.sorted() + ["|"] + routes.sorted()).joined(separator: ",")
    }

    /// `EngineHandle.start` on an 8 MiB worker thread, waited for
    /// synchronously. Found on real hardware (#161): called directly on
    /// `startTunnel`'s NSXPC callout thread it overflows that thread's
    /// stack inside `Identity::from_seed`'s post-quantum key derivation
    /// (SIGBUS in the stack guard) — the same reason `handleAppMessage`'s
    /// enroll verbs already run on their own `stackSize = 8 << 20` thread.
    private static func startEngineOnLargeStack(fd: Int32) throws -> EngineHandle {
        try onLargeStack {
            try EngineHandle.start(configPath: Self.configPath, socketPath: Self.socketPath, fd: fd)
        }
    }

    /// Run `body` on an 8 MiB worker thread and wait for it — see
    /// `startEngineOnLargeStack` for why the Rust calls need one.
    private static func onLargeStack<T>(_ body: @escaping () throws -> T) throws -> T {
        var result: Result<T, Error>!
        let done = DispatchSemaphore(value: 0)
        let worker = Thread {
            result = Result { try body() }
            done.signal()
        }
        worker.stackSize = 8 << 20
        worker.start()
        done.wait()
        return try result.get()
    }

    /// Where a root-run provisioning step may leave one invitation for the
    /// next `startTunnel` to enroll from — see `enrollFromPendingInvitation`.
    private static let pendingInvitationPath = "\(stateDir)/pending-invitation"

    /// Enroll (or re-enroll) from `pendingInvitationPath` if a root-owned
    /// provisioning step left one there, deleting it before use.
    ///
    /// The unattended counterpart to Karst.app's Enroll…: the lab's CI job,
    /// or an administrator's script, has root but is not Karst.app, and
    /// macOS lets only a configuration's owning app reach the provider via
    /// `sendProviderMessage`. The trust boundary is the file itself — a
    /// regular, root-owned, mode-0600 file in this root-only directory, the
    /// same shape `enrollment.rs::load_bundle` demands of a bundle — so
    /// nothing below root can plant one. Single use: removed before
    /// enrolling, whatever the outcome.
    ///
    /// - Returns: `nil` when there is nothing to do or enrollment succeeded;
    ///   otherwise the error `startTunnel` should fail with.
    private static func enrollFromPendingInvitation() -> Error? {
        var info = stat()
        guard lstat(pendingInvitationPath, &info) == 0 else { return nil }
        defer { unlink(pendingInvitationPath) }
        guard (info.st_mode & S_IFMT) == S_IFREG, info.st_uid == 0, info.st_mode & 0o077 == 0,
              (1...65_536).contains(info.st_size)
        else {
            return PacketTunnelProviderError.engine(
                "pending invitation refused: it must be a regular, root-owned, mode-0600 file of at most 64 KiB"
            )
        }
        guard let invitation = try? String(contentsOfFile: pendingInvitationPath, encoding: .utf8)
            .trimmingCharacters(in: .whitespacesAndNewlines), !invitation.isEmpty
        else {
            return PacketTunnelProviderError.engine("pending invitation could not be read")
        }
        unlink(pendingInvitationPath)
        os_log("startTunnel: enrolling from a pending invitation", log: Self.log, type: .default)
        do {
            try onLargeStack {
                try reEnrollInvitation(invitation: invitation, configPath: Self.configPath, stateDir: Self.stateDir)
            }
            return nil
        } catch let error as FfiError {
            return PacketTunnelProviderError.engine(Self.message(from: error))
        } catch {
            return error
        }
    }

    /// `packetFlow`'s underlying `utun` socket descriptor — the private,
    /// undocumented-but-stable `socket.fileDescriptor` KVC lookup
    /// ADR-0022 (`docs/adr/0022-mobile-tun-backend.md`) already documents
    /// for iOS's identical situation (WireGuard's and Tailscale's own iOS
    /// apps rely on the same lookup), applied here for macOS's own
    /// packet-tunnel path. Verified working end to end on real hardware
    /// (#161) — but not on the very first call: see
    /// `adoptedFileDescriptorRetrying(from:)`, the caller this exists for.
    private static func adoptedFileDescriptor(from packetFlow: NEPacketTunnelFlow) -> Int32? {
        if let fd = utunControlSocketDescriptor() {
            return fd
        }
        guard let number = packetFlow.value(forKeyPath: "socket.fileDescriptor") as? NSNumber else {
            return nil
        }
        let fd = number.int32Value
        return fd >= 0 ? fd : nil
    }

    /// The `utun` kernel-control socket NetworkExtension opened in this
    /// process for `packetFlow`, found by scanning this process's own
    /// descriptors — WireGuard-apple's `tunnelFileDescriptor`, which does
    /// not depend on any private property. Found on real hardware (#161,
    /// macOS 26.6, Intel): the `socket.fileDescriptor` KVC lookup below
    /// never resolved there, not only in the VM first suspected.
    ///
    /// A system extension's process outlives its sessions, and a starting
    /// session can overlap the previous one's socket, so this returns the
    /// first utun control socket *not already claimed* by a live engine
    /// (`ownedDescriptors`), and claims it.
    private static func utunControlSocketDescriptor() -> Int32? {
        ownedDescriptorsLock.lock()
        defer { ownedDescriptorsLock.unlock() }
        var info = ctl_info()
        withUnsafeMutablePointer(to: &info.ctl_name) {
            $0.withMemoryRebound(to: CChar.self, capacity: MemoryLayout.size(ofValue: $0.pointee)) {
                _ = strcpy($0, "com.apple.net.utun_control")
            }
        }
        // _IOWR('N', 3, struct ctl_info): the macro does not import into Swift.
        let ctliocginfo: UInt = 0xc064_4e03
        for fd: Int32 in 0...1024 {
            var address = sockaddr_ctl()
            var length = socklen_t(MemoryLayout.size(ofValue: address))
            let peer = withUnsafeMutablePointer(to: &address) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getpeername(fd, $0, &length) }
            }
            guard peer == 0, address.sc_family == AF_SYSTEM else { continue }
            if info.ctl_id == 0, ioctl(fd, ctliocginfo, &info) != 0 { continue }
            if address.sc_id == info.ctl_id, !ownedDescriptors.contains(fd) {
                ownedDescriptors.insert(fd)
                return fd
            }
        }
        return nil
    }

    /// **Found on real hardware (#161), not anticipated**: `packetFlow`'s
    /// `socket.fileDescriptor` reliably returns `nil` on the very first
    /// access inside `startTunnel`, then resolves to a real descriptor a
    /// few hundred milliseconds later — confirmed on real hardware by
    /// `com.apple.networkextension`'s own log: it goes on to create the
    /// backing `NEVirtualInterface` shortly after `startTunnel` had
    /// already reported failure and returned, with nothing left listening
    /// for it. This is not this app's own race (the [`EngineHandle::start`]
    /// readiness fix next to this one is that); it is `packetFlow` itself
    /// not being fully live the instant `startTunnel` is called, the same
    /// class of "give the platform a moment" issue this private API is
    /// already known for in other tunnel providers. Retried, not fixed
    /// with a single longer wait: the property becomes valid at some
    /// point during that window, not predictably at its start or end, so
    /// polling is the correct shape here, not a fixed delay.
    private static func adoptedFileDescriptorRetrying(
        from packetFlow: NEPacketTunnelFlow,
        attempts: Int = 100,
        interval: TimeInterval = 0.1
    ) -> Int32? {
        for attempt in 1...attempts {
            if let fd = adoptedFileDescriptor(from: packetFlow) {
                return fd
            }
            if attempt < attempts {
                Thread.sleep(forTimeInterval: interval)
            }
        }
        return nil
    }

    /// Whether `cidr` is a whole address family (`0.0.0.0/0`, `::/0`).
    ///
    /// A peer's `allowed_ips` carries an exit offer's default prefix as soon
    /// as the offer exists — karstd keeps a cryptokey next hop for it before
    /// any local consent — so mapping every allowed IP into an included
    /// route steered this device's default route into a tunnel whose engine
    /// refuses to forward it: an unconsented exit offer black-holed the
    /// Mac's internet (found on the lab hardware). A default route enters
    /// these settings only through the active recipient exit route below.
    static func isDefaultRoute(_ cidr: String) -> Bool {
        splitCIDR(cidr)?.prefixLength == 0
    }

    /// Builds the settings `setTunnelNetworkSettings` needs from
    /// `EngineHandle.statusJson()`'s body — the same JSON `karst status
    /// --json` reports on the `LaunchDaemon` build
    /// (`bins/karstd/src/run.rs`'s `StatusJson`). Assigns this device's own
    /// `addresses`, then routes every peer's `allowed_ips` through the
    /// tunnel — the standard AllowedIPs-as-routes mapping every
    /// WireGuard-shaped client uses, not a scheme invented for this file —
    /// plus, if this device currently has a live exit route (#160,
    /// `RoutingJson.exit_route_active`/`.routes`, only present under
    /// `StatusJson.control`, which `EngineHandle.status_json()` always has:
    /// it is both ends of its own admin socket), the same full-default-route
    /// prefix (`0.0.0.0/0`/`::/0`) an exit offer already carries literally,
    /// not a scheme this file invents from `exit_route_active` alone.
    ///
    /// **What this does, beyond the single call `startTunnel` makes.**
    /// This function itself only ever builds settings from whichever JSON
    /// it is handed — it does not re-poll anything on its own. The
    /// mid-session route-churn gap this comment used to describe as
    /// entirely open (the exit peer drops, a different one takes over, or
    /// the route is explicitly released, none of it reflected until the
    /// next full tunnel restart) is now mostly closed one call site up, by
    /// `healthTimer`/`pollHealth()`: that timer re-derives this same
    /// output on each poll and reapplies it when it changes, which is what
    /// `docs/adr/0030-embedded-engine-lifecycle.md`'s
    /// `NetworkDevice::add_route`/`remove_route`-are-no-ops gap (#158)
    /// actually needed. What remains genuinely unresolved — see
    /// `pollHealth()`'s own doc comment — is that neither this function
    /// nor its caller can discard in-flight packets while the engine is
    /// unhealthy; not falling open to a route outside the tunnel is the
    /// guarantee that exists today, not active blocking. DNS is left
    /// unset — `plans/phase-5/06-macos-client.md` §5's KarstDNS
    /// search-list gap is an already-accepted limitation.
    static func networkSettings(fromStatusJSON json: String) throws -> NEPacketTunnelNetworkSettings {
        let status = try JSONDecoder().decode(EngineStatus.self, from: Data(json.utf8))

        var ipv4Addresses: [String] = []
        var ipv4Masks: [String] = []
        var ipv6Addresses: [String] = []
        var ipv6PrefixLengths: [NSNumber] = []
        for cidr in status.addresses {
            guard let parsed = splitCIDR(cidr) else { continue }
            if parsed.address.contains(":") {
                ipv6Addresses.append(parsed.address)
                ipv6PrefixLengths.append(NSNumber(value: parsed.prefixLength))
            } else {
                ipv4Addresses.append(parsed.address)
                ipv4Masks.append(ipv4SubnetMask(prefixLength: parsed.prefixLength))
            }
        }

        var ipv4Routes: [NEIPv4Route] = []
        var ipv6Routes: [NEIPv6Route] = []
        for peer in status.peers {
            for allowed in peer.allowedIps where !isDefaultRoute(allowed) {
                addRoute(allowed, toIPv4: &ipv4Routes, ipv6: &ipv6Routes)
            }
        }
        // An exit offer's own `prefix` is already the literal
        // `0.0.0.0/0`/`::/0` this route needs — `route_offer.rs` requires
        // a zero-length prefix to construct `Kind::Exit` at all, so there
        // is nothing to derive here beyond reading it and checking `active`.
        // `role == "recipient"` is not redundant with that: `active` is
        // also `true` for a `role == "gateway"` entry (`routing_json`,
        // `run.rs`) when *this* node is itself relaying exit traffic for
        // others, which must never fold into this node's own default
        // route — that is the inbound side of the exact opposite
        // relationship.
        for route in status.control?.routing.routes ?? []
        where route.kind == "exit" && route.role == "recipient" && route.active {
            addRoute(route.prefix, toIPv4: &ipv4Routes, ipv6: &ipv6Routes)
        }

        // A non-empty string is required even though a full mesh has no
        // single "server" — every other NetworkExtension client facing the
        // same shape (no central gateway) uses one of its own tunnel
        // addresses here for the same reason.
        let tunnelRemoteAddress = ipv4Addresses.first ?? ipv6Addresses.first ?? "127.0.0.1"
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: tunnelRemoteAddress)
        settings.mtu = NSNumber(value: status.mtu)

        if !ipv4Addresses.isEmpty {
            let ipv4Settings = NEIPv4Settings(addresses: ipv4Addresses, subnetMasks: ipv4Masks)
            ipv4Settings.includedRoutes = ipv4Routes
            settings.ipv4Settings = ipv4Settings
        }
        if !ipv6Addresses.isEmpty {
            let ipv6Settings = NEIPv6Settings(addresses: ipv6Addresses, networkPrefixLengths: ipv6PrefixLengths)
            ipv6Settings.includedRoutes = ipv6Routes
            settings.ipv6Settings = ipv6Settings
        }
        return settings
    }

    /// Parses one CIDR route and appends it to whichever of `ipv4Routes`/
    /// `ipv6Routes` matches its family — the one construction path every
    /// route source (`allowed_ips`, an active exit offer's `prefix`) goes
    /// through, so a `0.0.0.0/0` from either place is handled identically
    /// rather than by two copies of the same six lines.
    private static func addRoute(
        _ cidr: String,
        toIPv4 ipv4Routes: inout [NEIPv4Route],
        ipv6 ipv6Routes: inout [NEIPv6Route]
    ) {
        guard let parsed = splitCIDR(cidr) else { return }
        if parsed.address.contains(":") {
            ipv6Routes.append(NEIPv6Route(
                destinationAddress: parsed.address,
                networkPrefixLength: NSNumber(value: parsed.prefixLength)
            ))
        } else {
            ipv4Routes.append(NEIPv4Route(
                destinationAddress: parsed.address,
                subnetMask: ipv4SubnetMask(prefixLength: parsed.prefixLength)
            ))
        }
    }

    /// Splits `"100.64.0.1/16"` into its address and prefix length.
    /// `karstd`'s `addresses`/`allowed_ips` fields are always
    /// `IpNet::to_string()` output (`bins/karstd/src/run.rs`) — always
    /// address-slash-prefix — so a `nil` here means genuinely malformed
    /// input, not a valid shape this just doesn't handle yet.
    static func splitCIDR(_ cidr: String) -> (address: String, prefixLength: Int)? {
        let parts = cidr.split(separator: "/", maxSplits: 1)
        guard parts.count == 2, let prefixLength = Int(parts[1]) else { return nil }
        let address = String(parts[0])
        let maximumPrefixLength = address.contains(":") ? 128 : 32
        guard (0...maximumPrefixLength).contains(prefixLength) else { return nil }
        return (address, prefixLength)
    }

    /// `NEIPv4Settings.subnetMasks` wants dotted-decimal, not a prefix
    /// length — the conversion Apple's API has needed since before CIDR
    /// notation was how anything else here expresses a range.
    static func ipv4SubnetMask(prefixLength: Int) -> String {
        let mask: UInt32 = prefixLength == 0 ? 0 : ~UInt32(0) << (32 - prefixLength)
        return [24, 16, 8, 0].map { String((mask >> $0) & 0xFF) }.joined(separator: ".")
    }

    /// Every `FfiError` case carries its message the same way — one
    /// extraction point rather than repeating this `switch` at every call
    /// site that catches one.
    private static func message(from error: FfiError) -> String {
        switch error {
        case .Enrollment(let message), .Engine(let message), .Identity(let message):
            return message
        }
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        guard let completionHandler else { return }

        // The message payload *is* the JSON body — no wire-level command
        // line the way `karstd::ipc::Command`'s socket protocol has one.
        // docs/adr/0027-macos-system-extension-host-app-ipc.md's
        // "Alternatives rejected" is why: that framing exists to multiplex
        // several verbs over one long-lived connection, which
        // `sendProviderMessage`'s one-message-per-call shape does not need.
        guard
            let object = try? JSONSerialization.jsonObject(with: messageData) as? [String: Any],
            let verb = object["verb"] as? String
        else {
            completionHandler(Self.errorResponse(
                "malformed app message: expected a JSON object with a \"verb\" field"
            ))
            return
        }

        switch verb {
        case "status":
            guard let engine else {
                completionHandler(Self.errorResponse("tunnel is not running"))
                return
            }
            // `EngineHandle.status_json()` (ADR-0030) — the same body
            // `karst status --json` reads on the `LaunchDaemon` build,
            // fetched over the control socket `startTunnel` bound `engine`
            // to.
            do {
                completionHandler(Data(try engine.statusJson().utf8))
            } catch let error as FfiError {
                completionHandler(Self.errorResponse(Self.message(from: error)))
            } catch {
                completionHandler(Self.errorResponse("status failed: \(error.localizedDescription)"))
            }
        case "enroll":
            guard let invitation = object["invitation"] as? String, !invitation.isEmpty else {
                completionHandler(Self.errorResponse("enroll message carried no invitation"))
                return
            }
            // `enrollInvitation` (ADR-0029) calls
            // `enrollment::enroll_invitation`'s existing Rust logic
            // verbatim — bundle parsing, the control-plane handshake, and
            // config publishing, all reused, not reimplemented
            // (docs/adr/0028-macos-network-extension-enrollment.md item 3).
            //
            // Run on an explicit `Thread` with a generous stack, not
            // `DispatchQueue.global` — found on real hardware via an actual
            // crash report, not inferred from timing (#159): GCD's global
            // queues hand out worker threads with a small, fixed default
            // stack (documented around 512KB), and the post-quantum
            // identity key generation this call reaches
            // (`karstd::control::Identity::from_seed`, deep under
            // `enroll_bundle`) needs more than that — it overflowed the
            // guard page and crashed the whole extension process with
            // `EXC_BAD_ACCESS`/`SIGBUS`, confirmed from the real crash
            // report's backtrace. That crash, not a slow response, is what
            // `sendProviderMessage` was actually seeing as "not valid UTF-8
            // JSON" on the host side: the process died mid-call, so no
            // response — valid or otherwise — was ever coming. A plain
            // `Thread` lets stack size be set explicitly, which GCD's
            // queues do not expose.
            os_log("KARST-TRACE enroll: received, spawning worker thread", log: Self.log, type: .default)
            let worker = Thread {
                os_log("KARST-TRACE enroll: calling enrollInvitation", log: Self.log, type: .default)
                let start = Date()
                do {
                    try enrollInvitation(
                        invitation: invitation,
                        configPath: Self.configPath,
                        stateDir: Self.stateDir
                    )
                    os_log(
                        "KARST-TRACE enroll: enrollInvitation succeeded after %{public}.2fs, calling completionHandler",
                        log: Self.log, type: .default, Date().timeIntervalSince(start)
                    )
                    completionHandler(Self.okResponse())
                } catch let error as FfiError {
                    os_log(
                        "KARST-TRACE enroll: enrollInvitation threw FfiError after %{public}.2fs: %{public}@",
                        log: Self.log, type: .default, Date().timeIntervalSince(start), Self.message(from: error)
                    )
                    completionHandler(Self.errorResponse(Self.message(from: error)))
                } catch {
                    os_log(
                        "KARST-TRACE enroll: enrollInvitation threw after %{public}.2fs: %{public}@",
                        log: Self.log, type: .default, Date().timeIntervalSince(start), error.localizedDescription
                    )
                    completionHandler(Self.errorResponse("enrollment failed: \(error.localizedDescription)"))
                }
            }
            // 8MB — the same default `pthread`/the main thread already gets
            // on Darwin, comfortably above whatever `Identity::from_seed`
            // actually needs; GCD's worker default (~512KB) is the reason
            // this crashed at all.
            worker.stackSize = 8 << 20
            worker.start()
        case "re-enroll":
            guard let invitation = object["invitation"] as? String, !invitation.isEmpty else {
                completionHandler(Self.errorResponse("re-enroll message carried no invitation"))
                return
            }
            // As `"enroll"` above — same `enrollInvitation`/`from_seed`
            // path once `reEnrollInvitation` gets past its own
            // config-replacement step, so it needs the same big-stack
            // `Thread`, not just the same Rust call.
            os_log("KARST-TRACE re-enroll: received, spawning worker thread", log: Self.log, type: .default)
            let worker = Thread {
                do {
                    try reEnrollInvitation(
                        invitation: invitation,
                        configPath: Self.configPath,
                        stateDir: Self.stateDir
                    )
                    completionHandler(Self.okResponse())
                } catch let error as FfiError {
                    completionHandler(Self.errorResponse(Self.message(from: error)))
                } catch {
                    completionHandler(Self.errorResponse("re-enrollment failed: \(error.localizedDescription)"))
                }
            }
            worker.stackSize = 8 << 20
            worker.start()
        case "identity":
            // `identityHandle` calls `Identity::load`, which — when
            // `identityPath` exists — runs the same `Identity::from_seed`
            // ML-DSA-87 key expansion `"enroll"`'s own comment names as
            // needing an explicit big-stack `Thread`, not GCD's default.
            // Only the "never enrolled" fast path skips it, and this
            // branch cannot tell which case it is in without running the
            // call — so it always pays for the safe thread.
            let worker = Thread {
                do {
                    // `JSONSerialization` does not reliably turn a bare
                    // `Optional<String>.none` into JSON `null` when boxed
                    // as `Any` in a dictionary — handled explicitly rather
                    // than relying on that bridging, for both fields below.
                    guard let handle = try identityHandle(identityKeyPath: Self.identityPath) else {
                        completionHandler(Data("{\"handle\":null,\"name\":null}".utf8))
                        return
                    }
                    // `deviceName` (#163) is a plain file read, not a
                    // `from_seed`-derived value like `handle` — cheap
                    // regardless of the big-stack `Thread` this already
                    // pays for, and folded into the same round trip
                    // rather than a second `"device-name"` verb, since a
                    // caller showing one always wants both.
                    let name = deviceName(identityKeyPath: Self.identityPath)
                    let object: [String: Any] = ["handle": handle, "name": name ?? NSNull()]
                    let data = (try? JSONSerialization.data(withJSONObject: object))
                        ?? Data("{\"handle\":null,\"name\":null}".utf8)
                    completionHandler(data)
                } catch let error as FfiError {
                    completionHandler(Self.errorResponse(Self.message(from: error)))
                } catch {
                    completionHandler(Self.errorResponse("identity lookup failed: \(error.localizedDescription)"))
                }
            }
            worker.stackSize = 8 << 20
            worker.start()
        case "exit-use", "exit-disable":
            // Karst.app's Exit node menu (ADR-0036 §3). The token is checked
            // here, as root, before anything reaches the engine: see
            // `ExitConsent`'s doc comment for why the app's own check is not
            // enough.
            guard
                let token = object["authorization"] as? String,
                ExitConsent.isAuthorized(externalForm: token)
            else {
                completionHandler(Self.errorResponse("an administrator must approve exit-node changes"))
                return
            }
            let line: String
            if verb == "exit-use" {
                guard let routeID = object["route_id"] as? String, ExitConsent.isPlausibleRouteID(routeID) else {
                    completionHandler(Self.errorResponse("exit-use needs a valid route_id"))
                    return
                }
                line = "exit-use \(routeID)"
            } else {
                line = "exit-disable"
            }
            guard engine != nil, let reply = ExitConsent.engineCommand(line, socketPath: Self.socketPath) else {
                completionHandler(Self.errorResponse("tunnel is not running"))
                return
            }
            if let failure = reply.split(separator: "\n").first(where: { $0.hasPrefix("error = ") }) {
                let message = failure.dropFirst("error = ".count).trimmingCharacters(in: CharacterSet(charactersIn: "\""))
                completionHandler(Self.errorResponse(message))
                return
            }
            completionHandler(Self.okResponse())
        default:
            completionHandler(Self.errorResponse("unknown app message verb \(verb)"))
        }
    }

    /// The same `{"error": "..."}` shape `run.rs`'s `status_json` itself
    /// falls back to on a `Serialize` failure — one error shape for
    /// `StatusParser.parseJSON` and `NetworkExtensionEnrollment.enroll` to
    /// check on either side of this channel, not a second one invented here.
    private static func errorResponse(_ message: String) -> Data {
        let object = ["error": message]
        return (try? JSONSerialization.data(withJSONObject: object))
            ?? Data("{\"error\":\"internal: could not encode error response\"}".utf8)
    }

    /// A bare `{}` — `NetworkExtensionEnrollment.enroll`'s own success
    /// condition is simply the absence of an `"error"` key, so this is the
    /// whole contract, not a shape this file invented on its own.
    private static func okResponse() -> Data {
        Data("{}".utf8)
    }
}

/// Failures `startTunnel` can report today.
enum PacketTunnelProviderError: LocalizedError {
    case notEnrolled
    case noPacketFlowDescriptor
    case engine(String)

    var errorDescription: String? {
        switch self {
        case .notEnrolled:
            return "This device has not completed Karst enrollment yet."
        case .noPacketFlowDescriptor:
            return "Could not obtain packetFlow's underlying file descriptor."
        case .engine(let message):
            return message
        }
    }
}

/// The subset of `bins/karstd/src/run.rs`'s `StatusJson` that
/// `PacketTunnelProvider.networkSettings(fromStatusJSON:)` needs — decoded
/// directly rather than via `JSONSerialization`'s untyped dictionaries,
/// since every field here is load-bearing for a real tunnel's routing, not
/// read-and-discard.
private struct EngineStatus: Decodable {
    struct Peer: Decodable {
        let allowedIps: [String]

        enum CodingKeys: String, CodingKey {
            case allowedIps = "allowed_ips"
        }
    }

    /// Mirrors `ControlJson` (`run.rs`) — `nil` only on the unprivileged
    /// status socket, which `EngineHandle.status_json()` never uses (it is
    /// both ends of its own admin socket, per that method's own doc
    /// comment), so this is `Optional` to match the Rust type honestly
    /// rather than because this file ever expects to see it absent.
    struct Control: Decodable {
        let routing: Routing
    }

    /// Mirrors `RoutingJson`. Only `routes` is read here — `offers`,
    /// `selected_exit`, `gateway_active`/`gateway_error` describe *why*
    /// routing is in its current state, which belongs in a status display,
    /// not in what `setTunnelNetworkSettings` needs to act on.
    struct Routing: Decodable {
        let routes: [Route]
    }

    /// Mirrors `RouteJson`. `prefix` for a `kind == "exit"` route is
    /// already a literal `0.0.0.0/0`/`::/0` (`route_offer.rs` requires a
    /// zero-length prefix to construct `Kind::Exit` at all — not a
    /// placeholder this file needs to special-case into one), so an active
    /// exit route folds into the same `splitCIDR`/`NEIPv4Route`/
    /// `NEIPv6Route` construction every peer's `allowed_ips` already goes
    /// through, not a second route-building path.
    struct Route: Decodable {
        let prefix: String
        let kind: String
        let role: String
        let active: Bool
    }

    let addresses: [String]
    let mtu: Int
    let peers: [Peer]
    let control: Control?
}
