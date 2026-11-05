// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

import Darwin
import Foundation

/// The extension's side of `KarstAppStore`'s Exit node menu (ADR-0036 §3,
/// #499). A trimmed copy of
/// packaging/macos/KarstPacketTunnel/Sources/KarstPacketTunnel/
/// ExitConsent.swift: `ManagedDecision`/`managedDecision` are dropped, since
/// ADR-0040 item 4 keeps `ExitNodeAutoConsent`/managed-device coexistence out
/// of scope for this self-service-only distribution channel — there is no
/// managed refusal for this extension to make. `isPlausibleRouteID`/
/// `engineCommand` are unchanged: exit-route consent on this build, as on
/// the Developer-ID one, comes from whoever is logged in locally, with no
/// Authorization Services round trip and no password — `KarstAppStore` runs
/// as whoever is logged in, and any console user can already send this
/// extension a provider message, so this is simply not gated.
enum ExitConsent {
    /// Route IDs are server-generated tokens; anything else is refused before
    /// it can reach the engine's line-oriented control protocol.
    static func isPlausibleRouteID(_ routeID: String) -> Bool {
        !routeID.isEmpty && routeID.count <= 128
            && routeID.unicodeScalars.allSatisfy {
                CharacterSet.alphanumerics.contains($0) || $0 == "-" || $0 == "_"
            }
    }

    /// Send one command line to the embedded engine's control socket (inside
    /// the App Group container, unlike the Developer-ID build's root-owned
    /// path — see `PacketTunnelProvider.stateDir`) and return its reply —
    /// the same channel `karst exit-node` uses.
    static func engineCommand(_ line: String, socketPath: String) -> String? {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let capacity = MemoryLayout.size(ofValue: address.sun_path)
        guard socketPath.utf8.count < capacity else { return nil }
        withUnsafeMutablePointer(to: &address.sun_path) {
            $0.withMemoryRebound(to: CChar.self, capacity: capacity) { _ = strcpy($0, socketPath) }
        }
        let connected = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard connected == 0 else { return nil }
        let request = Array((line + "\n").utf8)
        guard write(fd, request, request.count) == request.count else { return nil }
        shutdown(fd, SHUT_WR)
        var reply = Data()
        var buffer = [UInt8](repeating: 0, count: 16_384)
        while true {
            let n = read(fd, &buffer, buffer.count)
            if n <= 0 { break }
            reply.append(contentsOf: buffer[0..<n])
        }
        return String(data: reply, encoding: .utf8)
    }
}
