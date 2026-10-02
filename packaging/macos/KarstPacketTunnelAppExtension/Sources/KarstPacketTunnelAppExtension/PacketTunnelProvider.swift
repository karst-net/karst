// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

import Foundation
import KarstFFI
import NetworkExtension
import os.log

/// The sandboxed macOS App Extension's `NEPacketTunnelProvider` — the Mac App
/// Store counterpart to `KarstPacketTunnel`'s Developer-ID System Extension.
/// docs/adr/0040-mac-app-store-needs-a-sandboxed-app-extension.md,
/// docs/adr/0043-mac-app-store-sandboxed-app-extension-target.md.
///
/// This is a deliberately narrower copy of `KarstPacketTunnel`'s own
/// `PacketTunnelProvider.swift`, not a generalization of it: `startTunnel`/
/// `stopTunnel`, the large-stack worker threads the Rust calls need, the
/// `packetFlow` fd-adoption retry, `networkSettings(fromStatusJSON:)`, and the
/// `pollHealth()` reassert loop are all copied verbatim in shape (see that
/// file's own doc comments for what each one guards against — they apply
/// identically here, since `karst-ffi`'s `EngineHandle` is NE-packaging-
/// agnostic, confirmed by ADR-0040). Three things are deliberately different:
///
/// 1. **State lives in an App Group container, not a root-owned path.** A
///    System Extension runs as root and its host app as the console user, so
///    (per the other file's own `stateDir` doc comment) an App Group would
///    not actually bridge the two. A sandboxed App Extension and its host app
///    run as the *same* console user, so an App Group container is the right
///    mechanism here, not a repeat of that earlier mistake.
/// 2. **`handleAppMessage` only answers `status`/`enroll`/`re-enroll`/
///    `identity`.** `exit-use`/`exit-disable` and `ExitNodeAutoConsent`
///    reconciliation are out of scope for this first pass (ADR-0040 item 4:
///    the App Store build doesn't need managed-device/exit-node parity with
///    the Developer-ID build) — a deliberate, named gap, not an oversight.
/// 3. **No root-owned-file unattended-enrollment path.** `KarstPacketTunnel`'s
///    `enrollFromPendingInvitation` exists for the lab's root-provisioning
///    automation, which has no sandboxed equivalent and nothing here needs.
///
/// **What is wired and what is still unverified.** Written and reviewed
/// against Apple's App Extension/App Sandbox documentation, and compiled and
/// tested by `.github/workflows/macos-appextension-swift-build.yml` on a real
/// macos-14 runner — but, unlike `KarstPacketTunnel`, **nothing here has run
/// as a real, installed, sandboxed extension on real hardware**: no Apple
/// Developer Program Mac App Store certificates, App ID, or provisioning
/// profile exist in this environment to activate one. Sandbox activation,
/// App Group container resolution, enrollment, and real packet flow are all
/// genuinely open, stated here rather than assumed — the same "written and
/// reviewed, not run" posture ADR-0029/ADR-0030 already hold themselves to.
final class PacketTunnelProvider: NEPacketTunnelProvider {
    private static let log = OSLog(subsystem: "dev.karst.appstore.packettunnel", category: "provider")

    /// The App Group shared with the host app (`KarstAppStore`) —
    /// `com.apple.security.application-groups` in both
    /// `PacketTunnelAppExtension.entitlements` and the host app's own
    /// entitlements file. Both processes run as the console user under this
    /// sandboxed packaging (unlike the System Extension/host-app split,
    /// which runs as root vs. the console user), so both resolve the same
    /// container directory — see this file's own header comment, item 1.
    private static let appGroupIdentifier = "group.dev.karst.appstore"

    /// Where this extension keeps its own state, inside the App Group
    /// container — `identity.key`/`config.toml`/`control.sock`, the same
    /// file names `KarstPacketTunnel`'s own `stateDir` uses, just a
    /// different, sandbox-writable root. `nil` only if the App Group
    /// entitlement is missing or misconfigured, which `startTunnel` below
    /// treats as a hard failure rather than falling back to a path this
    /// sandboxed process cannot write to anyway.
    private static var stateDir: String? {
        FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: appGroupIdentifier)?
            .appendingPathComponent("Library/Application Support/dev.karst.packettunnel", isDirectory: true)
            .path
    }

    private static func identityPath(stateDir: String) -> String { "\(stateDir)/identity.key" }
    private static func configPath(stateDir: String) -> String { "\(stateDir)/config.toml" }
    private static func socketPath(stateDir: String) -> String { "\(stateDir)/control.sock" }

    /// Held from a successful `startTunnel` until `stopTunnel` — see
    /// `KarstPacketTunnel`'s own `engine` doc comment; identical reasoning.
    private var engine: EngineHandle?

    private var adoptedDescriptor: Int32?
    private static var ownedDescriptors = Set<Int32>()
    private static let ownedDescriptorsLock = NSLock()

    private static func releaseDescriptor(_ fd: Int32) {
        ownedDescriptorsLock.lock()
        ownedDescriptors.remove(fd)
        ownedDescriptorsLock.unlock()
    }

    /// As `KarstPacketTunnel`'s `healthTimer` — see that file's own doc
    /// comment on why a dispatch timer, not `Timer`/`RunLoop`, and why its
    /// unhealthy branch never tears the session down.
    private var healthTimer: DispatchSourceTimer?
    private let healthQueue = DispatchQueue(label: "dev.karst.appstore.packettunnel.health")
    private var lastAppliedRouteSignature: String?
    private static let healthPollInterval: TimeInterval = 2.0

    override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        os_log("startTunnel", log: Self.log, type: .info)
        // Large stack: see KarstPacketTunnel's identical comment on
        // `startTunnel` — the post-quantum key derivation this reaches needs
        // more than NetworkExtension's own callout-thread stack provides.
        let worker = Thread { [self] in
            startTunnelOnWorker(completionHandler: completionHandler)
        }
        worker.stackSize = 8 << 20
        worker.start()
    }

    private func startTunnelOnWorker(completionHandler: @escaping (Error?) -> Void) {
        let finish: (Error?) -> Void = { [weak self] error in
            if error != nil, let self, let fd = self.adoptedDescriptor {
                Self.releaseDescriptor(fd)
                self.adoptedDescriptor = nil
            }
            completionHandler(error)
        }

        guard let stateDir = Self.stateDir else {
            finish(PacketTunnelProviderError.appGroupContainerUnavailable)
            return
        }
        let identityPath = Self.identityPath(stateDir: stateDir)
        let configPath = Self.configPath(stateDir: stateDir)
        let socketPath = Self.socketPath(stateDir: stateDir)

        guard FileManager.default.fileExists(atPath: identityPath) else {
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
            handle = try Self.startEngineOnLargeStack(configPath: configPath, socketPath: socketPath, fd: fd)
        } catch let error as FfiError {
            finish(PacketTunnelProviderError.engine(Self.message(from: error)))
            return
        } catch {
            finish(error)
            return
        }
        engine = handle

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
        engine?.stop()
        engine = nil
        if let fd = adoptedDescriptor {
            Self.releaseDescriptor(fd)
            adoptedDescriptor = nil
        }
        completionHandler()
    }

    private func startHealthTimer() {
        let timer = DispatchSource.makeTimerSource(queue: healthQueue)
        timer.schedule(deadline: .now() + Self.healthPollInterval, repeating: Self.healthPollInterval)
        timer.setEventHandler { [weak self] in
            self?.pollHealth()
        }
        timer.resume()
        healthTimer = timer
    }

    /// As `KarstPacketTunnel.pollHealth()` — same two outcomes, same
    /// never-tear-down-on-fault rule. `ExitNodeAutoConsent` reconciliation is
    /// not ported (see this file's own header comment, item 2).
    private func pollHealth() {
        guard let engine else { return }
        let json: String
        do {
            json = try engine.statusJson()
        } catch {
            os_log(
                "health poll: engine unreachable, reasserting: %{public}@",
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
                    "health poll: setTunnelNetworkSettings failed: %{public}@",
                    log: Self.log, type: .default, error.localizedDescription
                )
            }
        }
    }

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

    private static func startEngineOnLargeStack(configPath: String, socketPath: String, fd: Int32) throws -> EngineHandle {
        try onLargeStack {
            try EngineHandle.start(configPath: configPath, socketPath: socketPath, fd: fd)
        }
    }

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

    private static func utunControlSocketDescriptor() -> Int32? {
        ownedDescriptorsLock.lock()
        defer { ownedDescriptorsLock.unlock() }
        var info = ctl_info()
        withUnsafeMutablePointer(to: &info.ctl_name) {
            $0.withMemoryRebound(to: CChar.self, capacity: MemoryLayout.size(ofValue: $0.pointee)) {
                _ = strcpy($0, "com.apple.net.utun_control")
            }
        }
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

    static func isDefaultRoute(_ cidr: String) -> Bool {
        splitCIDR(cidr)?.prefixLength == 0
    }

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
        for route in status.control?.routing.routes ?? []
        where route.kind == "exit" && route.role == "recipient" && route.active {
            addRoute(route.prefix, toIPv4: &ipv4Routes, ipv6: &ipv6Routes)
        }

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

    static func splitCIDR(_ cidr: String) -> (address: String, prefixLength: Int)? {
        let parts = cidr.split(separator: "/", maxSplits: 1)
        guard parts.count == 2, let prefixLength = Int(parts[1]) else { return nil }
        let address = String(parts[0])
        let maximumPrefixLength = address.contains(":") ? 128 : 32
        guard (0...maximumPrefixLength).contains(prefixLength) else { return nil }
        return (address, prefixLength)
    }

    static func ipv4SubnetMask(prefixLength: Int) -> String {
        let mask: UInt32 = prefixLength == 0 ? 0 : ~UInt32(0) << (32 - prefixLength)
        return [24, 16, 8, 0].map { String((mask >> $0) & 0xFF) }.joined(separator: ".")
    }

    private static func message(from error: FfiError) -> String {
        switch error {
        case .Enrollment(let message), .Engine(let message), .Identity(let message):
            return message
        }
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        guard let completionHandler else { return }

        guard
            let object = try? JSONSerialization.jsonObject(with: messageData) as? [String: Any],
            let verb = object["verb"] as? String
        else {
            completionHandler(Self.errorResponse(
                "malformed app message: expected a JSON object with a \"verb\" field"
            ))
            return
        }

        guard let stateDir = Self.stateDir else {
            completionHandler(Self.errorResponse("the App Group container is not available"))
            return
        }
        let identityPath = Self.identityPath(stateDir: stateDir)
        let configPath = Self.configPath(stateDir: stateDir)
        let socketPath = Self.socketPath(stateDir: stateDir)

        switch verb {
        case "status":
            guard let engine else {
                completionHandler(Self.errorResponse("tunnel is not running"))
                return
            }
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
            let worker = Thread {
                do {
                    try enrollInvitation(invitation: invitation, configPath: configPath, stateDir: stateDir)
                    completionHandler(Self.okResponse())
                } catch let error as FfiError {
                    completionHandler(Self.errorResponse(Self.message(from: error)))
                } catch {
                    completionHandler(Self.errorResponse("enrollment failed: \(error.localizedDescription)"))
                }
            }
            worker.stackSize = 8 << 20
            worker.start()
        case "re-enroll":
            guard let invitation = object["invitation"] as? String, !invitation.isEmpty else {
                completionHandler(Self.errorResponse("re-enroll message carried no invitation"))
                return
            }
            let worker = Thread {
                do {
                    try reEnrollInvitation(invitation: invitation, configPath: configPath, stateDir: stateDir)
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
            let worker = Thread {
                do {
                    guard let handle = try identityHandle(identityKeyPath: identityPath) else {
                        completionHandler(Data("{\"handle\":null,\"name\":null}".utf8))
                        return
                    }
                    let name = deviceName(identityKeyPath: identityPath)
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
        default:
            completionHandler(Self.errorResponse("unknown app message verb \(verb)"))
        }
    }

    private static func errorResponse(_ message: String) -> Data {
        let object = ["error": message]
        return (try? JSONSerialization.data(withJSONObject: object))
            ?? Data("{\"error\":\"internal: could not encode error response\"}".utf8)
    }

    private static func okResponse() -> Data {
        Data("{}".utf8)
    }
}

enum PacketTunnelProviderError: LocalizedError {
    case notEnrolled
    case noPacketFlowDescriptor
    case engine(String)
    /// Distinct from `KarstPacketTunnel`'s error set — a sandboxed process
    /// has no fallback if its App Group entitlement/container is missing or
    /// misconfigured, unlike the System Extension's literal root-owned path.
    case appGroupContainerUnavailable

    var errorDescription: String? {
        switch self {
        case .notEnrolled:
            return "This device has not completed Karst enrollment yet."
        case .noPacketFlowDescriptor:
            return "Could not obtain packetFlow's underlying file descriptor."
        case .engine(let message):
            return message
        case .appGroupContainerUnavailable:
            return "Could not resolve the App Group container for group.dev.karst.appstore."
        }
    }
}

private struct EngineStatus: Decodable {
    struct Peer: Decodable {
        let allowedIps: [String]

        enum CodingKeys: String, CodingKey {
            case allowedIps = "allowed_ips"
        }
    }

    struct Control: Decodable {
        let routing: Routing
    }

    struct Routing: Decodable {
        let routes: [Route]
        let selectedExit: String?

        enum CodingKeys: String, CodingKey {
            case routes
            case selectedExit = "selected_exit"
        }
    }

    struct Route: Decodable {
        let prefix: String
        let kind: String
        let role: String
        let active: Bool
        let routeId: String?

        enum CodingKeys: String, CodingKey {
            case prefix, kind, role, active
            case routeId = "route_id"
        }
    }

    let addresses: [String]
    let mtu: Int
    let peers: [Peer]
    let control: Control?
}
