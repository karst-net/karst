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
/// **What is wired and what is still unverified.** Every call below
/// compiles against the real `EngineHandle`/`enrollInvitation` bindings and
/// is not a placeholder, but none of it has been exercised against a
/// signed, notarized, activated extension yet — that needs #156's still-
/// pending entitlement and real code signing, not just a compiling build.
/// `networkSettings(fromStatusJSON:)`'s AllowedIPs-as-routes mapping is the
/// same one every WireGuard-shaped client uses, not an invented scheme, but
/// it has not carried real peer traffic. DNS is deliberately left unset —
/// `plans/phase-5/06-macos-client.md` §5's KarstDNS search-list gap is a
/// known, already-accepted limitation, not new scope for this file.
final class PacketTunnelProvider: NEPacketTunnelProvider {
    private static let log = OSLog(subsystem: "dev.karst.packettunnel", category: "provider")

    /// Where this extension keeps its own state — never `/etc/karst`,
    /// which is the `LaunchDaemon` build's namespace, running as a
    /// different process this extension shares a machine with, not a
    /// predecessor it replaces (ADR-0026 item 8 ships both "indefinitely,
    /// not just during a transition"). Reusing `/etc/karst` would mean
    /// enrolling one build silently corrupts the other's config the moment
    /// both are ever present on the same machine — a distinct root-owned
    /// directory costs nothing and removes the collision entirely.
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
    /// confined by what its own (root) UID can reach, the same as the
    /// `LaunchDaemon` build already is for `/etc/karst` — not confined to
    /// a container the way a fully App-Sandboxed process would be.
    /// Checked against public developer-forum reports of this exact
    /// app/extension split (root vs. console user, App Groups not
    /// bridging them) during this session, not verified end-to-end on a
    /// real machine — flag if a real activation finds this wrong.
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

    override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        os_log("startTunnel", log: Self.log, type: .info)

        guard FileManager.default.fileExists(atPath: Self.identityPath) else {
            // Mirrors `bins/karstd/src/setup.rs`'s `from_stdin`'s own
            // `resume` branch: never invent a tunnel out of a device that
            // was never enrolled.
            completionHandler(PacketTunnelProviderError.notEnrolled)
            return
        }

        guard let fd = Self.adoptedFileDescriptor(from: packetFlow) else {
            completionHandler(PacketTunnelProviderError.noPacketFlowDescriptor)
            return
        }

        let handle: EngineHandle
        do {
            // `fd`'s exclusive ownership transfers to `EngineHandle.start`
            // here — `karst_tun::Tun::from_fd`'s contract, carried across
            // this boundary rather than re-derived (`EngineHandle.start`'s
            // own `# Safety` doc comment).
            handle = try EngineHandle.start(
                configPath: Self.configPath,
                socketPath: Self.socketPath,
                fd: fd
            )
        } catch let error as FfiError {
            completionHandler(PacketTunnelProviderError.engine(Self.message(from: error)))
            return
        } catch {
            completionHandler(error)
            return
        }
        engine = handle

        let settings: NEPacketTunnelNetworkSettings
        do {
            settings = try Self.networkSettings(fromStatusJSON: handle.statusJson())
        } catch {
            handle.stop()
            engine = nil
            completionHandler(error)
            return
        }

        setTunnelNetworkSettings(settings) { [weak self] error in
            if error != nil {
                self?.engine?.stop()
                self?.engine = nil
            }
            completionHandler(error)
        }
    }

    override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        os_log("stopTunnel: %{public}@", log: Self.log, type: .info, String(describing: reason))
        // `EngineHandle.stop()` both requests shutdown and joins (that
        // method's own doc comment on why `Drop` alone does not) — exactly
        // what a caller waiting to report "fully stopped" needs.
        engine?.stop()
        engine = nil
        completionHandler()
    }

    /// `packetFlow`'s underlying `utun` socket descriptor — the private,
    /// undocumented-but-stable `socket.fileDescriptor` KVC lookup
    /// ADR-0022 (`docs/adr/0022-mobile-tun-backend.md`) already documents
    /// for iOS's identical situation (WireGuard's and Tailscale's own iOS
    /// apps rely on the same lookup), applied here for macOS's own
    /// packet-tunnel path for the first time. Not verified against a real
    /// activated extension yet — see this file's own header comment.
    private static func adoptedFileDescriptor(from packetFlow: NEPacketTunnelFlow) -> Int32? {
        guard let number = packetFlow.value(forKeyPath: "socket.fileDescriptor") as? NSNumber else {
            return nil
        }
        let fd = number.int32Value
        return fd >= 0 ? fd : nil
    }

    /// Builds the settings `setTunnelNetworkSettings` needs from
    /// `EngineHandle.statusJson()`'s body — the same JSON `karst status
    /// --json` reports on the `LaunchDaemon` build
    /// (`bins/karstd/src/run.rs`'s `StatusJson`). Assigns this device's own
    /// `addresses`, then routes every peer's `allowed_ips` through the
    /// tunnel — the standard AllowedIPs-as-routes mapping every
    /// WireGuard-shaped client uses, not a scheme invented for this file.
    /// Exit-node full-default-route handling (`RoutingJson.exit_route_active`,
    /// only present under `StatusJson.control`) is out of scope here: that
    /// needs its own verification once a real exit peer exists to route
    /// through, not a guess bundled into this pass. DNS is left unset —
    /// `plans/phase-5/06-macos-client.md` §5's KarstDNS search-list gap is
    /// an already-accepted limitation.
    private static func networkSettings(fromStatusJSON json: String) throws -> NEPacketTunnelNetworkSettings {
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
            for allowed in peer.allowedIps {
                guard let parsed = splitCIDR(allowed) else { continue }
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

    /// Splits `"100.64.0.1/16"` into its address and prefix length.
    /// `karstd`'s `addresses`/`allowed_ips` fields are always
    /// `IpNet::to_string()` output (`bins/karstd/src/run.rs`) — always
    /// address-slash-prefix — so a `nil` here means genuinely malformed
    /// input, not a valid shape this just doesn't handle yet.
    private static func splitCIDR(_ cidr: String) -> (address: String, prefixLength: Int)? {
        let parts = cidr.split(separator: "/", maxSplits: 1)
        guard parts.count == 2, let prefixLength = Int(parts[1]) else { return nil }
        return (String(parts[0]), prefixLength)
    }

    /// `NEIPv4Settings.subnetMasks` wants dotted-decimal, not a prefix
    /// length — the conversion Apple's API has needed since before CIDR
    /// notation was how anything else here expresses a range.
    private static func ipv4SubnetMask(prefixLength: Int) -> String {
        let mask: UInt32 = prefixLength == 0 ? 0 : ~UInt32(0) << (32 - prefixLength)
        return [24, 16, 8, 0].map { String((mask >> $0) & 0xFF) }.joined(separator: ".")
    }

    /// Both `FfiError` cases carry their message the same way — one
    /// extraction point rather than repeating this `switch` at every call
    /// site that catches one.
    private static func message(from error: FfiError) -> String {
        switch error {
        case .Enrollment(let message), .Engine(let message):
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
            // Dispatched to a background queue rather than called directly
            // on `handleAppMessage`'s own thread — found on real hardware
            // (#159), not anticipated: this call blocks on a real
            // control-plane network round trip (several seconds, not
            // milliseconds), and running it synchronously here left that
            // thread unresponsive long enough that `nesessionmanager`'s own
            // watchdog gave up and reported failure to the host app before
            // this method's `completionHandler` was ever invoked — even
            // though enrollment itself went on to succeed moments later
            // (`identity.key`/`enrollment.toml` were written correctly,
            // confirmed on disk, while the host app had already been told
            // the response was invalid). Freeing this thread immediately
            // is the fix, not making the network call itself faster.
            os_log("KARST-TRACE enroll: received, dispatching to background queue", log: Self.log, type: .default)
            DispatchQueue.global(qos: .userInitiated).async {
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
                    os_log("KARST-TRACE enroll: completionHandler(okResponse) returned", log: Self.log, type: .default)
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

    let addresses: [String]
    let mtu: Int
    let peers: [Peer]
}
