// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

import Foundation
import NetworkExtension
import os.log

/// The macOS System Extension's `NEPacketTunnelProvider`.
///
/// docs/adr/0026-macos-network-extension-backend.md item 2's Rust `Tun`
/// backend (`crates/karst-tun`'s `network-extension` feature) is what this
/// class will eventually drive `packetFlow` through; nothing here does yet,
/// because the Rust core has no linkable form to call into —
/// ADR-0022's UniFFI boundary "is not built yet," its own words. Every
/// `TODO(karst-ffi)` below marks exactly where that call belongs once it
/// exists. This class is honest about that gap rather than returning
/// invented values that would look like a working tunnel and are not one —
/// the same posture `plans/phase-5/06-macos-client.md` §5 already insists on
/// for KarstDNS's search-list gap, applied here to a larger one.
final class PacketTunnelProvider: NEPacketTunnelProvider {
    private static let log = OSLog(subsystem: "dev.karst.packettunnel", category: "provider")

    /// The identity file a completed enrollment leaves behind —
    /// docs/adr/0028-macos-network-extension-enrollment.md item 3. Mirrors
    /// `karstd`'s own `identity_key_file` in shape, not necessarily in exact
    /// path: the NE build's real directory layout is still open pending
    /// ADR-0026 item 7's packaging work, so this is a placeholder location,
    /// not a decision this file makes.
    private static let identityPath = "/etc/karst/identity.key"

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

        // TODO(karst-ffi): load the identity, run the Karst protocol engine
        // against `packetFlow`, and call `setTunnelNetworkSettings` with the
        // addresses/routes/DNS the control plane's netmap actually assigns.
        // All of that lives behind ADR-0022's UniFFI boundary, which does
        // not exist as a linkable artifact yet. Answering `.notImplemented`
        // here is the honest current behavior, not a bug to silence.
        completionHandler(PacketTunnelProviderError.notImplemented)
    }

    override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        os_log("stopTunnel: %{public}@", log: Self.log, type: .info, String(describing: reason))
        // TODO(karst-ffi): tear down the linked Rust core's engine, once
        // `startTunnel` actually creates one.
        completionHandler()
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
            // TODO(karst-ffi): call the linked Rust core's `status_json()`
            // equivalent directly — an in-process function call, not IPC,
            // once it is linkable. See ADR-0026's Context section for why
            // this differs from every other `HostRuntime`-shaped mechanism,
            // which all mutate host state from a separate `karstd` process.
            completionHandler(Self.errorResponse(
                "karst NetworkExtension core is not yet linked into this extension — see docs/adr/0022-mobile-tun-backend.md"
            ))
        case "enroll":
            guard let invitation = object["invitation"] as? String, !invitation.isEmpty else {
                completionHandler(Self.errorResponse("enroll message carried no invitation"))
                return
            }
            // TODO(karst-ffi): call `crates/karst-ffi`'s `enroll_invitation`
            // (ADR-0029), write the resulting identity to `Self.identityPath`,
            // and report success. That crate exists now and wraps
            // `enrollment::enroll_invitation`'s existing Rust logic verbatim
            // (docs/adr/0028-macos-network-extension-enrollment.md item 3) —
            // what is still missing is the packaging half (ADR-0026 item 7):
            // this target has no Swift Package/xcframework dependency on the
            // compiled `karst_ffi` library yet, so there is nothing to import
            // and call. `invitation` is intentionally unused past this guard
            // — see the type's own doc comment on not inventing what this
            // build cannot yet do.
            _ = invitation
            completionHandler(Self.errorResponse(
                "karst NetworkExtension enrollment is not yet linked into this extension — see crates/karst-ffi and docs/adr/0029-ffi-boundary-uniffi.md"
            ))
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
}

/// Failures `startTunnel` can report today. Both cases are honest about what
/// this build actually does, not a placeholder success.
enum PacketTunnelProviderError: LocalizedError {
    case notEnrolled
    case notImplemented

    var errorDescription: String? {
        switch self {
        case .notEnrolled:
            return "This device has not completed Karst enrollment yet."
        case .notImplemented:
            return "The Karst NetworkExtension core is not yet linked into this build — see docs/adr/0022-mobile-tun-backend.md."
        }
    }
}
