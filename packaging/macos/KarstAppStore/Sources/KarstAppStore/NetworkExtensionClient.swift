// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.
//
// A trimmed copy of packaging/macos/KarstStatus/Sources/KarstStatus/
// NetworkExtensionClient.swift: `sendExitCommand`/`fetchExitManaged` are
// dropped (minimal-viable scope has no exit-node menu — see
// AppDelegate.swift's own header comment); `fetchStatusJSON`/
// `fetchIdentityHandle` and the shared `sendVerb` plumbing are unchanged,
// since `sendProviderMessage`'s wire shape does not depend on which
// NetworkExtension packaging is on the other end.

import Foundation
import NetworkExtension

enum NetworkExtensionStatusError: Error {
    case noManagerConfigured
    case sessionUnavailable
    case sendFailed(Error)
    case emptyResponse
    case invalidResponseEncoding
}

/// Talks to the App Extension's `PacketTunnelProvider` over
/// `NETunnelProviderSession.sendProviderMessage`.
struct NetworkExtensionStatusClient {
    let providerBundleIdentifier: String

    func fetchStatusJSON(completion: @escaping (Result<String, Error>) -> Void) {
        sendVerb("{\"verb\":\"status\"}", completion: completion)
    }

    func fetchIdentityHandle(completion: @escaping (Result<String, Error>) -> Void) {
        sendVerb("{\"verb\":\"identity\"}", completion: completion)
    }

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
