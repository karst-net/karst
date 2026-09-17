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
/// `startTunnel` will eventually drive `packetFlow` through, via
/// `crates/karst-ffi`'s `EngineHandle` (ADR-0030) once `KarstFFI`'s
/// committed bindings include it — see that call site's own
/// `TODO(karst-ffi)` for exactly what is still missing and why.
/// `handleAppMessage`'s `"enroll"` verb
/// needs no such wait: `enrollInvitation` compiles the same on every
/// platform (ADR-0029), so it is wired for real below, not a placeholder.
/// Every remaining `TODO(karst-ffi)` marks exactly where a call belongs
/// once it can be made — this class stays honest about what it cannot yet
/// do rather than returning invented values that would look like a working
/// tunnel and are not one, the same posture `plans/phase-5/06-macos-client.md`
/// §5 already insists on for KarstDNS's search-list gap, applied here to a
/// larger one.
final class PacketTunnelProvider: NEPacketTunnelProvider {
    private static let log = OSLog(subsystem: "dev.karst.packettunnel", category: "provider")

    /// The identity file a completed enrollment leaves behind —
    /// docs/adr/0028-macos-network-extension-enrollment.md item 3. Mirrors
    /// `karstd`'s own `identity_key_file` in shape, not necessarily in exact
    /// path: ADR-0026 item 7's packaging work now builds and signs a real
    /// bundle, but *where inside the sandbox this extension may actually
    /// read and write* — its own container, or an App Group shared with
    /// `Karst.app` — is a separate question that work did not answer. This
    /// stays a placeholder until it does, not a decision this file makes.
    private static let identityPath = "/etc/karst/identity.key"

    /// As `identityPath` — placeholder, not a decision. `enrollInvitation`
    /// (ADR-0029) writes a full `karstd`-shaped `config.toml` here, mirroring
    /// `karst-setup`'s own `config_path`/`state_dir` split
    /// (`bins/karstd/src/enrollment.rs::enroll_bundle`).
    private static let configPath = "/etc/karst/config.toml"

    /// As `configPath` — where `enrollInvitation` writes `node.key` and,
    /// once enrollment finishes, `identityPath` above.
    private static let stateDir = "/etc/karst"

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

        // TODO(karst-ffi): `EngineHandle` (ADR-0030) is what this call
        // belongs to — `EngineHandle.start(configPath:socketPath:fd:)`,
        // adopting `packetFlow`'s fd via the private KVC lookup ADR-0022
        // already documents for iOS, then `setTunnelNetworkSettings` once
        // `status_json()` (over the socket `start` bound) reports the
        // addresses/routes/DNS the control plane's netmap actually
        // assigned. Not yet possible: `KarstFFI`'s committed bindings
        // (Sources/KarstFFI/karst_ffi.swift) were generated from a Linux
        // build of `karst-ffi` without `--features network-extension` —
        // the only feature combination `EngineHandle` compiles under — so
        // the type does not exist in this build yet. See that file's own
        // header comment for the regeneration command. Answering
        // `.notImplemented` here is the honest current behavior, not a bug
        // to silence.
        completionHandler(PacketTunnelProviderError.notImplemented)
    }

    override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        os_log("stopTunnel: %{public}@", log: Self.log, type: .info, String(describing: reason))
        // TODO(karst-ffi): `EngineHandle.stop()` (ADR-0030) already both
        // requests shutdown and joins (that method's own doc comment on why
        // `Drop` alone does not) — once `startTunnel` above can construct a
        // handle to hold and call this on, this needs nothing more than the
        // call itself. Blocked on the same missing binding as `startTunnel`.
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
            // TODO(karst-ffi): `EngineHandle.status_json()` (ADR-0030) is
            // what this call belongs to, over the same handle `startTunnel`
            // holds once it can construct one — same missing binding as
            // `startTunnel`'s own `TODO(karst-ffi)`, not a second gap.
            completionHandler(Self.errorResponse(
                "karst NetworkExtension core is not yet linked into this extension — see docs/adr/0030-embedded-engine-lifecycle.md"
            ))
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
            // Unlike `startTunnel`'s `EngineHandle` call, this compiles the
            // same on every platform (ADR-0029's own reasoning for
            // shipping it first), so `KarstFFI`'s Linux-generated bindings
            // already carry it — nothing here is waiting on a Mac.
            do {
                try enrollInvitation(
                    invitation: invitation,
                    configPath: Self.configPath,
                    stateDir: Self.stateDir
                )
                completionHandler(Self.okResponse())
            } catch let error as FfiError {
                switch error {
                case .Enrollment(let message), .Engine(let message):
                    completionHandler(Self.errorResponse(message))
                }
            } catch {
                completionHandler(Self.errorResponse("enrollment failed: \(error.localizedDescription)"))
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
            return "The Karst NetworkExtension core is not yet linked into this build — see docs/adr/0030-embedded-engine-lifecycle.md."
        }
    }
}
