// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

import Foundation
import NetworkExtension

/// Everything that can go wrong asking a `PacketTunnelProvider` extension
/// for its status over `NETunnelProviderSession.sendProviderMessage`.
enum NetworkExtensionStatusError: Error {
    /// No `NETunnelProviderManager` is saved for `providerBundleIdentifier`
    /// yet — see `NetworkExtensionEnrollment`, which is what creates one.
    case noManagerConfigured
    /// `manager.connection` was not an `NETunnelProviderSession` — should be
    /// unreachable for a `NETunnelProviderManager`, kept as a named case
    /// rather than a forced cast so a future API change fails with a clear
    /// error instead of a crash.
    case sessionUnavailable
    case sendFailed(Error)
    case emptyResponse
    case invalidResponseEncoding
}

/// Talks to the NetworkExtension build's `PacketTunnelProvider` over
/// `NETunnelProviderSession.sendProviderMessage` —
/// docs/adr/0027-macos-system-extension-host-app-ipc.md's decision.
///
/// Wired into `AppDelegate` as the sole status source (#159, once
/// NetworkExtension became the only macOS backend — the `LaunchDaemon`
/// status socket this used to sit beside no longer exists). Verified end
/// to end on real hardware, not just reviewed against Apple's published
/// `NETunnelProviderSession`/`NETunnelProviderManager` API.
struct NetworkExtensionStatusClient {
    /// The `providerBundleIdentifier` the extension's `NETunnelProviderProtocol`
    /// was saved under — see `NetworkExtensionEnrollment.ensureConfiguration`.
    /// A stored value rather than a shared constant: whoever wires this in
    /// decides the real identifier once the extension target exists, is
    /// signed, and has a bundle identifier that is not this file's guess.
    let providerBundleIdentifier: String

    /// Ask the running extension for `status-json`'s body — the same shape
    /// `bins/karstd/src/run.rs`'s `status_json` produces, now served by
    /// `PacketTunnelProvider.handleAppMessage`'s `"status"` verb — over the
    /// one `NETunnelProviderManager` saved for `providerBundleIdentifier`.
    ///
    /// Feeds `StatusParser.parseJSON(_:)` on success.
    func fetchStatusJSON(completion: @escaping (Result<String, Error>) -> Void) {
        sendVerb("{\"verb\":\"status\"}", completion: completion)
    }

    /// Ask the running extension for this device's own identity handle —
    /// `PacketTunnelProvider.handleAppMessage`'s `"identity"` verb — as the
    /// raw `{"handle": "..." | null}` JSON text. `AppDelegate` parses the
    /// `"handle"` field itself rather than this client returning
    /// `String?` directly: a malformed/empty response and "not enrolled"
    /// (`null`) are different failure shapes, and collapsing them here
    /// would hide which one a caller actually got.
    func fetchIdentityHandle(completion: @escaping (Result<String, Error>) -> Void) {
        sendVerb("{\"verb\":\"identity\"}", completion: completion)
    }

    /// Common plumbing every verb over this channel needs: find the saved
    /// manager, get its session, send the (already-JSON) payload, decode
    /// the reply as UTF-8 text. What differs per verb is only the request
    /// body and what the caller does with the response text — extracted
    /// here once `fetchIdentityHandle` needed to repeat everything
    /// `fetchStatusJSON` already did except the literal verb string.
    private func sendVerb(_ requestJSON: String, completion: @escaping (Result<String, Error>) -> Void) {
        NETunnelProviderManager.loadAllFromPreferences { managers, error in
            if let error {
                completion(.failure(error))
                return
            }
            guard
                let manager = managers?.first(where: {
                    ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier
                        == providerBundleIdentifier
                })
            else {
                completion(.failure(NetworkExtensionStatusError.noManagerConfigured))
                return
            }
            guard let session = manager.connection as? NETunnelProviderSession else {
                completion(.failure(NetworkExtensionStatusError.sessionUnavailable))
                return
            }

            // The message payload *is* the JSON body — no wire-level command
            // line the way the Unix-socket protocol has one. See
            // `PacketTunnelProvider.handleAppMessage`'s matching doc comment
            // on the other side of this channel.
            guard let request = requestJSON.data(using: .utf8) else {
                completion(.failure(NetworkExtensionStatusError.invalidResponseEncoding))
                return
            }
            do {
                try session.sendProviderMessage(request) { responseData in
                    guard let responseData else {
                        completion(.failure(NetworkExtensionStatusError.emptyResponse))
                        return
                    }
                    guard let text = String(data: responseData, encoding: .utf8) else {
                        completion(.failure(NetworkExtensionStatusError.invalidResponseEncoding))
                        return
                    }
                    completion(.success(text))
                }
            } catch {
                completion(.failure(NetworkExtensionStatusError.sendFailed(error)))
            }
        }
    }
}
