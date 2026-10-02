// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.
//
// A trimmed copy of packaging/macos/KarstStatus/Sources/KarstStatus/
// NetworkExtensionEnrollment.swift. `ManagerOwnership`/`currentOwnership`
// (#162/ADR-0031's managed-device UI heuristic) are dropped — out of scope
// for this minimal-viable pass (ADR-0040 item 4: the App Store build does
// not need managed-device/MDM coexistence at all) — everything else
// (`ensureConfiguration`, `enroll`/`reEnroll`, the on-demand-after-enrollment
// gate, the restart-on-reenroll dance) is unchanged: none of it is
// System-Extension-specific, and the self-created marker this file still
// writes is needed for `enableOnDemandAfterEnrollment` on its own, not only
// for the dropped ownership heuristic.

import Foundation
import NetworkExtension
import os.log

enum NetworkExtensionEnrollmentError: Error {
    case saveFailed(Error)
    case sessionUnavailable
    case sendFailed(Error)
    case startFailed(Error)
    case invalidResponseEncoding
    case providerRefused(String)
}

extension NetworkExtensionEnrollmentError: LocalizedError {
    var errorDescription: String? {
        switch self {
        case .saveFailed(let error):
            return "Could not save the VPN configuration: \(error.localizedDescription)"
        case .sessionUnavailable:
            return "No VPN session is available for the network extension."
        case .sendFailed(let error):
            return "Could not reach the network extension: \(error.localizedDescription)"
        case .startFailed(let error):
            return "Could not start the VPN tunnel: \(error.localizedDescription)"
        case .invalidResponseEncoding:
            return "The network extension's response was not valid UTF-8 JSON."
        case .providerRefused(let message):
            return message
        }
    }
}

/// Creates and saves the `NETunnelProviderManager`, and carries one
/// enrollment invitation to the App Extension over
/// `sendProviderMessage` — the same shape
/// docs/adr/0028-macos-network-extension-enrollment.md's items 1-2 describe
/// for the Developer-ID build, unchanged by which NetworkExtension packaging
/// is on the other end.
enum NetworkExtensionEnrollment {
    private static let log = OSLog(subsystem: "dev.karst.appstore", category: "enrollment")

    /// Written once, right after a successful `ensureConfiguration` create —
    /// gates `enableOnDemandAfterEnrollment` below. Kept even though the
    /// Developer-ID build's `ManagerOwnership`/`currentOwnership` UI this
    /// marker also feeds there is not ported here (see this file's own
    /// header comment).
    private static func selfCreatedMarkerKey(_ providerBundleIdentifier: String) -> String {
        "dev.karst.appstore.selfCreatedManager.\(providerBundleIdentifier)"
    }

    /// Create the `NETunnelProviderManager` if none exists yet for
    /// `providerBundleIdentifier`, or return the existing one. Idempotent,
    /// safe on every launch. Identical logic to the Developer-ID build's own
    /// `ensureConfiguration` — see that file's doc comment for the full
    /// reasoning on never mutating a manager this app did not create, the
    /// ambiguous-multiple-managers tiebreak, and why on-demand starts off
    /// until enrollment confirms an identity exists.
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
            let matching = (managers ?? []).filter {
                ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier
                    == providerBundleIdentifier
            }
            if let existing = matching.first {
                if matching.count > 1 {
                    let chosen = matching.first(where: \.isEnabled) ?? existing
                    os_log(
                        "ensureConfiguration: %{public}d configurations found for %{public}@, choosing the %{public}@ one",
                        log: Self.log, type: .default, matching.count, providerBundleIdentifier,
                        chosen.isEnabled ? "enabled" : "first"
                    )
                    completion(.success(chosen))
                    return
                }
                completion(.success(existing))
                return
            }

            let proto = NETunnelProviderProtocol()
            proto.providerBundleIdentifier = providerBundleIdentifier
            proto.serverAddress = controlURL
            proto.providerConfiguration = ["controlURL": controlURL]

            let manager = NETunnelProviderManager()
            manager.protocolConfiguration = proto
            manager.localizedDescription = "Karst"
            manager.isEnabled = true
            manager.isOnDemandEnabled = false
            manager.onDemandRules = [NEOnDemandRuleConnect()]
            manager.saveToPreferences { error in
                if let error {
                    completion(.failure(NetworkExtensionEnrollmentError.saveFailed(error)))
                    return
                }
                UserDefaults.standard.set(true, forKey: selfCreatedMarkerKey(providerBundleIdentifier))
                manager.loadFromPreferences { error in
                    if let error {
                        completion(.failure(NetworkExtensionEnrollmentError.saveFailed(error)))
                        return
                    }
                    completion(.success(manager))
                }
            }
        }
    }

    static func enroll(
        invitation: String,
        manager: NETunnelProviderManager,
        completion: @escaping (Result<Void, Error>) -> Void
    ) {
        sendInvitation(verb: "enroll", invitation: invitation, manager: manager, restartRunning: false, completion: completion)
    }

    static func reEnroll(
        invitation: String,
        manager: NETunnelProviderManager,
        completion: @escaping (Result<Void, Error>) -> Void
    ) {
        sendInvitation(verb: "re-enroll", invitation: invitation, manager: manager, restartRunning: true, completion: completion)
    }

    private static func enableOnDemandAfterEnrollment(_ manager: NETunnelProviderManager) {
        guard
            !manager.isOnDemandEnabled,
            let identifier = (manager.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier,
            UserDefaults.standard.bool(forKey: selfCreatedMarkerKey(identifier))
        else { return }
        manager.isOnDemandEnabled = true
        if manager.onDemandRules?.isEmpty ?? true {
            manager.onDemandRules = [NEOnDemandRuleConnect()]
        }
        manager.saveToPreferences { error in
            if let error {
                os_log(
                    "enableOnDemandAfterEnrollment: save failed: %{public}@",
                    log: Self.log, type: .default, error.localizedDescription
                )
            }
        }
    }

    private static func sendInvitation(
        verb: String,
        invitation: String,
        manager: NETunnelProviderManager,
        restartRunning: Bool,
        completion: @escaping (Result<Void, Error>) -> Void
    ) {
        guard let session = manager.connection as? NETunnelProviderSession else {
            completion(.failure(NetworkExtensionEnrollmentError.sessionUnavailable))
            return
        }

        let payload: [String: Any] = ["verb": verb, "invitation": invitation]
        guard let requestData = try? JSONSerialization.data(withJSONObject: payload) else {
            completion(.failure(NetworkExtensionEnrollmentError.invalidResponseEncoding))
            return
        }

        do {
            try session.sendProviderMessage(requestData) { responseData in
                guard let responseData else {
                    completion(.failure(NetworkExtensionEnrollmentError.invalidResponseEncoding))
                    return
                }
                guard let text = String(data: responseData, encoding: .utf8) else {
                    completion(.failure(NetworkExtensionEnrollmentError.invalidResponseEncoding))
                    return
                }
                if
                    let data = text.data(using: .utf8),
                    let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                    let errorMessage = object["error"] as? String
                {
                    completion(.failure(NetworkExtensionEnrollmentError.providerRefused(errorMessage)))
                    return
                }
                switch session.status {
                case .connected, .connecting, .reasserting:
                    guard restartRunning else { break }
                    restart(session) { error in
                        if let error {
                            completion(.failure(NetworkExtensionEnrollmentError.startFailed(error)))
                            return
                        }
                        enableOnDemandAfterEnrollment(manager)
                        completion(.success(()))
                    }
                    return
                default:
                    do {
                        try session.startVPNTunnel()
                    } catch {
                        completion(.failure(NetworkExtensionEnrollmentError.startFailed(error)))
                        return
                    }
                }
                enableOnDemandAfterEnrollment(manager)
                completion(.success(()))
            }
        } catch {
            completion(.failure(NetworkExtensionEnrollmentError.sendFailed(error)))
        }
    }

    private static let restartTimeout: TimeInterval = 20

    static func restart(_ session: NETunnelProviderSession, completion: @escaping (Error?) -> Void) {
        var observer: NSObjectProtocol?
        var finished = false
        let finish: (Error?) -> Void = { error in
            guard !finished else { return }
            finished = true
            if let observer { NotificationCenter.default.removeObserver(observer) }
            completion(error)
        }
        let startIfDown = {
            guard session.status == .disconnected || session.status == .invalid else { return }
            do {
                try session.startVPNTunnel()
                finish(nil)
            } catch {
                finish(error)
            }
        }
        observer = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange, object: session, queue: .main
        ) { _ in startIfDown() }
        session.stopVPNTunnel()
        DispatchQueue.main.async(execute: startIfDown)
        DispatchQueue.main.asyncAfter(deadline: .now() + restartTimeout) {
            guard !finished else { return }
            do {
                try session.startVPNTunnel()
                finish(nil)
            } catch {
                finish(error)
            }
        }
    }
}
