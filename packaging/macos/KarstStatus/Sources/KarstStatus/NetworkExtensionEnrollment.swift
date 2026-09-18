// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

import Foundation
import NetworkExtension

/// Everything that can go wrong turning an invitation into a saved
/// NetworkExtension configuration and a reply from the extension.
enum NetworkExtensionEnrollmentError: Error {
    case saveFailed(Error)
    case sessionUnavailable
    case sendFailed(Error)
    case invalidResponseEncoding
    /// The extension answered with its own `{"error": "..."}` — carries the
    /// message verbatim, the same "never re-derive, never paraphrase a
    /// credential-adjacent error" posture `enrollment.rs`'s
    /// `parse_invitation` already applies on the Rust side.
    case providerRefused(String)
}

/// Without this, `AppDelegate.showAlert`'s message comes from Swift's
/// default `Error`-to-`NSError` bridging — the generic, useless "The
/// operation couldn't be completed. (KarstStatus.NetworkExtensionEnrollmentError
/// error 0.)" this project's own real-device testing (#159) actually hit,
/// which hid the real underlying `NEVPNErrorDomain`/`NEConfigurationErrorDomain`
/// text behind a case index. Surfacing the wrapped error's own description
/// costs nothing and is exactly the diagnostic this file's cases exist to
/// carry.
extension NetworkExtensionEnrollmentError: LocalizedError {
    var errorDescription: String? {
        switch self {
        case .saveFailed(let error):
            return "Could not save the VPN configuration: \(error.localizedDescription)"
        case .sessionUnavailable:
            return "No VPN session is available for the network extension."
        case .sendFailed(let error):
            return "Could not reach the network extension: \(error.localizedDescription)"
        case .invalidResponseEncoding:
            return "The network extension's response was not valid UTF-8 JSON."
        case .providerRefused(let message):
            return message
        }
    }
}

/// Creates and saves the `NETunnelProviderManager` `NetworkExtensionStatusClient`
/// polls, and carries one enrollment invitation to the extension over the
/// same `sendProviderMessage` channel —
/// docs/adr/0028-macos-network-extension-enrollment.md items 1-2.
///
/// Wired into `AppDelegate`'s "Setup (Network Extension)…" item
/// (`runNetworkExtensionSetup`/`ensureConfigurationAndEnroll`) now that
/// ADR-0026 item 7's packaging work gives `dev.karst.packettunnel` a real
/// signed bundle to be a `providerBundleIdentifier` for. Written and
/// reviewed against Apple's published API, not run — see
/// `NetworkExtensionClient.swift`'s header for the standard this package
/// holds itself to either way, and `SystemExtensionActivator.swift`'s for
/// what "run" would even mean here (nothing has activated a real signed
/// extension and driven this call for real).
enum NetworkExtensionEnrollment {
    /// Create the `NETunnelProviderManager` if none exists yet for
    /// `providerBundleIdentifier`, or return the existing one.
    ///
    /// Idempotent: safe to call on every `Karst.app` launch, not only on
    /// first enrollment — mirrors `bins/karstd/src/setup.rs`'s `from_stdin`'s
    /// own `resume` branch, which likewise never demands a fresh invitation
    /// merely to restart.
    ///
    /// - Parameter controlURL: the control-plane address — the one
    ///   non-secret field ADR-0028's Context says belongs in
    ///   `providerConfiguration` before any identity exists at all.
    static func ensureConfiguration(
        providerBundleIdentifier: String,
        controlURL: String,
        completion: @escaping (Result<NETunnelProviderManager, Error>) -> Void
    ) {
        NETunnelProviderManager.loadAllFromPreferences { managers, error in
            if let error {
                completion(.failure(error))
                return
            }
            if let existing = managers?.first(where: {
                ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier
                    == providerBundleIdentifier
            }) {
                completion(.success(existing))
                return
            }

            let proto = NETunnelProviderProtocol()
            proto.providerBundleIdentifier = providerBundleIdentifier
            // `serverAddress` is `NEVPNProtocol`'s own field, shown in
            // System Settings' VPN list — the control-plane host is the only
            // address this app can name before enrollment has ever run, so
            // it stands in here rather than leaving Apple's own UI blank.
            proto.serverAddress = controlURL
            // Non-secret only — see ADR-0028's Context on why nothing else
            // belongs here: a System Extension runs as root while this app
            // runs as the console user, so Keychain Access Groups and App
            // Group containers cannot bridge the two, and Apple's own
            // guidance says not to put secrets in `providerConfiguration`
            // regardless.
            proto.providerConfiguration = ["controlURL": controlURL]

            let manager = NETunnelProviderManager()
            manager.protocolConfiguration = proto
            manager.localizedDescription = "Karst"
            manager.isEnabled = true
            manager.saveToPreferences { error in
                if let error {
                    completion(.failure(NetworkExtensionEnrollmentError.saveFailed(error)))
                    return
                }
                completion(.success(manager))
            }
        }
    }

    /// Carry one enrollment invitation to the extension, unparsed —
    /// `karst-invite-v1:…`, exactly as pasted, exactly as `read_invitation`
    /// in `bins/karstd/src/setup.rs` already refuses to look inside it
    /// beyond a size check. This app is a courier for bytes it cannot use,
    /// the same posture it already has for the LaunchDaemon build's
    /// `karst-setup` flow.
    ///
    /// Every failure arrives through `completion` rather than being thrown,
    /// since both `saveToPreferences` and `sendProviderMessage` are
    /// themselves completion-driven, not synchronous.
    static func enroll(
        invitation: String,
        manager: NETunnelProviderManager,
        completion: @escaping (Result<Void, Error>) -> Void
    ) {
        guard let session = manager.connection as? NETunnelProviderSession else {
            completion(.failure(NetworkExtensionEnrollmentError.sessionUnavailable))
            return
        }

        let payload: [String: Any] = ["verb": "enroll", "invitation": invitation]
        guard let requestData = try? JSONSerialization.data(withJSONObject: payload) else {
            completion(.failure(NetworkExtensionEnrollmentError.invalidResponseEncoding))
            return
        }

        do {
            try session.sendProviderMessage(requestData) { responseData in
                guard let responseData, let text = String(data: responseData, encoding: .utf8) else {
                    completion(.failure(NetworkExtensionEnrollmentError.invalidResponseEncoding))
                    return
                }
                // The provider answers a refusal in the same shape
                // `status-json`'s own fallback uses — `{"error": "..."}` —
                // rather than a distinct enrollment-specific error format.
                // See `StatusParser.parseJSON`'s doc comment for why that
                // one shape was chosen once and reused everywhere on this
                // channel.
                if
                    let data = text.data(using: .utf8),
                    let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                    let errorMessage = object["error"] as? String
                {
                    completion(.failure(NetworkExtensionEnrollmentError.providerRefused(errorMessage)))
                    return
                }
                completion(.success(()))
            }
        } catch {
            completion(.failure(NetworkExtensionEnrollmentError.sendFailed(error)))
        }
    }
}
