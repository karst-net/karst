// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

import Darwin
import Foundation

/// The extension's side of Karst.app's Exit node menu (ADR-0036 §3).
///
/// Exit-route consent on a self-service (non-MDM) Mac now comes from
/// whoever is logged in locally: no Authorization Services round trip, no
/// administrator password. `Karst.app` runs as whoever is logged in, and
/// any console user can already send this extension a provider message, so
/// this is simply not gated for that case. The one consent decision that
/// still cannot come from the local console is a managed install's: see
/// `PacketTunnelProvider.managedExitAutoConsent`, which this type's
/// `managedDecision` serves, and which refuses `exit-use`/`exit-disable`
/// from the app entirely rather than checking a per-request token.
enum ExitConsent {
    /// What `ExitNodeAutoConsent` (ADR-0036 §4) does with the current offers.
    enum ManagedDecision: Equatable {
        /// Nothing to change: no offer, or an offered one is already chosen.
        case none
        /// Consent to this route.
        case use(String)
        /// Several exits are offered and none is chosen: the profile cannot
        /// say which, so choose none and report it.
        case conflict
    }

    /// Consent to the single offered exit route; with several offered, keep
    /// an existing choice among them but make no new one. With none offered,
    /// any selection stays dormant, as it does on a self-service Mac.
    static func managedDecision(offers: [String], selected: String?) -> ManagedDecision {
        if let selected, offers.contains(selected) {
            return .none
        }
        switch offers.count {
        case 0: return .none
        case 1: return .use(offers[0])
        default: return .conflict
        }
    }

    /// Route IDs are server-generated tokens; anything else is refused before
    /// it can reach the engine's line-oriented control protocol.
    static func isPlausibleRouteID(_ routeID: String) -> Bool {
        !routeID.isEmpty && routeID.count <= 128
            && routeID.unicodeScalars.allSatisfy {
                CharacterSet.alphanumerics.contains($0) || $0 == "-" || $0 == "_"
            }
    }

    /// Send one command line to the embedded engine's root-only control
    /// socket and return its reply — the same channel `karst exit-node` uses.
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
