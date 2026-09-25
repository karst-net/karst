// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

import Darwin
import Foundation
import Security

/// The extension's side of Karst.app's Exit node menu (ADR-0036 §3).
///
/// Exit-route consent belongs to the device's local administrator
/// (ADR-0024), but `Karst.app` runs as whoever is logged in, and any console
/// user can send this extension a provider message. So the app sends an
/// Authorization Services external form with each `exit-use`/`exit-disable`
/// request, and this side — running as root — reconstructs it and checks the
/// consent right itself, without interaction, before relaying anything to
/// the engine. A request that is missing a token, carries a malformed one, or
/// whose token does not hold the right is refused; nothing the app claims
/// about its own checks is trusted.
enum ExitConsent {
    /// Defined by the package's postinstall (administrator authentication,
    /// credentials not shared, a short timeout so the app's pre-authorization
    /// is still valid when this side checks). Without the definition, the
    /// authorization database falls back to its default rule, which also
    /// requires an administrator.
    static let rightName = "dev.karst.exit-node.consent"

    /// Whether `externalForm` (base64 of an `AuthorizationExternalForm`)
    /// currently holds `rightName`.
    static func isAuthorized(externalForm: String) -> Bool {
        guard
            let data = Data(base64Encoded: externalForm),
            data.count == MemoryLayout<AuthorizationExternalForm>.size
        else { return false }
        var form = AuthorizationExternalForm()
        withUnsafeMutableBytes(of: &form) { _ = data.copyBytes(to: $0) }

        var reference: AuthorizationRef?
        guard
            AuthorizationCreateFromExternalForm(&form, &reference) == errAuthorizationSuccess,
            let reference
        else { return false }
        defer { AuthorizationFree(reference, []) }

        return rightName.withCString { name -> Bool in
            var item = AuthorizationItem(name: name, valueLength: 0, value: nil, flags: 0)
            return withUnsafeMutablePointer(to: &item) { itemPointer -> Bool in
                var rights = AuthorizationRights(count: 1, items: itemPointer)
                // No .interactionAllowed: this side never prompts. The app
                // pre-authorized in the user's session; the check here only
                // confirms the token actually holds the right.
                return AuthorizationCopyRights(reference, &rights, nil, [.extendRights], nil)
                    == errAuthorizationSuccess
            }
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
