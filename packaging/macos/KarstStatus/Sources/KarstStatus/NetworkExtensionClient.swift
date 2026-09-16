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
/// docs/adr/0027-macos-system-extension-host-app-ipc.md's decision — the way
/// `StatusClient` talks to the LaunchDaemon build's status socket.
///
/// **Not wired into `AppDelegate` yet.** Nothing packages or signs the
/// NetworkExtension build today — docs/adr/0026-macos-network-extension-backend.md
/// items 5-7 are still open — so there is nothing live for this to poll, and
/// no decided `providerBundleIdentifier` to hard-code here. Written now, at
/// the same confidence this package's Swift originally shipped at
/// (plans/phase-6/13-macos-status-indicators.md): reviewed line by line
/// against Apple's published `NETunnelProviderSession`/`NETunnelProviderManager`
/// API, not compiled or run against a real System Extension.
struct NetworkExtensionStatusClient {
    /// The `providerBundleIdentifier` the extension's `NETunnelProviderProtocol`
    /// was saved under — see `NetworkExtensionEnrollment.ensureConfiguration`.
    /// A stored value rather than a shared constant: whoever wires this in
    /// decides the real identifier once the extension target exists, is
    /// signed, and has a bundle identifier that is not this file's guess.
    let providerBundleIdentifier: String

    /// Ask the running extension for `status-json`'s body — the same JSON
    /// `Command::StatusJson` produces on the LaunchDaemon build
    /// (`bins/karstd/src/run.rs`'s `status_json`) — over the one
    /// `NETunnelProviderManager` saved for `providerBundleIdentifier`.
    ///
    /// Feeds `StatusParser.parseJSON(_:)` on success, exactly as
    /// `StatusClient.fetchStatus()`'s text feeds `StatusParser.parse(_:)` —
    /// the two clients differ in transport, not in what `AppDelegate` does
    /// with the result.
    func fetchStatusJSON(completion: @escaping (Result<String, Error>) -> Void) {
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
            guard let request = "{\"verb\":\"status\"}".data(using: .utf8) else {
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
