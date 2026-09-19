// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

import Foundation
import NetworkExtension
import os.log

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
    private static let log = OSLog(subsystem: "dev.karst.karststatus", category: "enrollment")

    /// A UI-only heuristic for whether *this* app created the current
    /// `NETunnelProviderManager` — never wired into `ensureConfiguration`'s
    /// own mutation boundary below, which stays ownership-agnostic on
    /// purpose (#162). See `currentOwnership(providerBundleIdentifier:completion:)`.
    enum ManagerOwnership: Equatable {
        case createdByThisApp
        case unknownOrForeign
    }

    /// Written only inside `ensureConfiguration`'s create-new-manager
    /// branch, once, right after a successful save — the one moment this
    /// app actually knows it just created the configuration in question.
    private static func selfCreatedMarkerKey(_ providerBundleIdentifier: String) -> String {
        "dev.karst.karststatus.selfCreatedManager.\(providerBundleIdentifier)"
    }

    /// #162's own research concluded there is no reliable, documented way
    /// to ask the OS "did this app create this configuration?" — the
    /// closest available signal ("a manager already existed at launch,
    /// with no `ensureConfiguration` call from this app yet") was tried
    /// and rejected there as too risky to gate real functionality on: a
    /// stale/ambiguous read would incorrectly treat a normal self-service
    /// user's own configuration as foreign.
    ///
    /// This persists a marker across launches instead of relying on
    /// in-memory call history, which resolves the specific ambiguity #162
    /// hit — but a marker can still go missing (app data reset, a
    /// migration) while the `NETunnelProviderManager` itself persists at
    /// the OS level, so absence is still treated as "don't know," not as
    /// "foreign." That is why this is UI-only: `AppDelegate` uses it only
    /// to add an informational line, never to hide or disable Enroll/
    /// Re-enroll, which is the stronger move #162 already judged too
    /// risky on a weaker version of this same heuristic.
    static func currentOwnership(
        providerBundleIdentifier: String,
        completion: @escaping (ManagerOwnership) -> Void
    ) {
        NETunnelProviderManager.loadAllFromPreferences { managers, error in
            guard error == nil else {
                completion(.unknownOrForeign)
                return
            }
            let matching = (managers ?? []).filter {
                ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier
                    == providerBundleIdentifier
            }
            // Ambiguous the same way `ensureConfiguration` already treats
            // it below (#162): more than one candidate means this cannot
            // say which one is "the" configuration, so this defaults to
            // the safe answer rather than guessing.
            guard matching.count == 1 else {
                completion(.unknownOrForeign)
                return
            }
            let marked = UserDefaults.standard.bool(forKey: selfCreatedMarkerKey(providerBundleIdentifier))
            completion(marked ? .createdByThisApp : .unknownOrForeign)
        }
    }

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
            let matching = (managers ?? []).filter {
                ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier
                    == providerBundleIdentifier
            }
            // Never save, remove, or otherwise mutate a manager this app
            // did not just create in the branch below — deliberately, not
            // an oversight. There is no supported API to tell "this app
            // created it" apart from "an MDM profile pushed it" (#162,
            // researched, not assumed: no documented property, no
            // documented error from a management call against one, and
            // even Tailscale's own macOS client has an open, unresolved
            // issue over exactly this). Whatever is already here — ours
            // from an earlier launch, or someone else's entirely — is
            // used as-is; only its absence is this app's cue to create
            // one of its own.
            if let existing = matching.first {
                if matching.count > 1 {
                    // Two configurations for the same provider bundle
                    // identifier is a real, reachable state this app
                    // cannot resolve on its own (self-created earlier,
                    // then MDM-pushed later, or the reverse) — the order
                    // `loadAllFromPreferences` returns them in is not
                    // documented as stable or meaningful, so picking
                    // deterministic over arbitrary is the most this can
                    // do: prefer one already enabled, so a disabled
                    // leftover never silently wins over a live one.
                    let chosen = matching.first(where: \.isEnabled) ?? existing
                    os_log(
                        "KARST-TRACE ensureConfiguration: %{public}d configurations found for %{public}@, choosing the %{public}@ one",
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
            // Personal/self-service configs only — a managed config's
            // on-demand behavior comes entirely from its MDM profile
            // (docs/adr/0031-managed-device-mode-reconsiders-adr-0024.md),
            // and this branch never runs against one anyway (it only
            // executes when no configuration exists yet). A bare
            // `NEOnDemandRuleConnect()` (default `interfaceTypeMatch =
            // .any`) is reconnect-for-convenience only: no
            // `includeAllNetworks`, so it changes nothing about who can
            // disable this device's tunnel, only how quickly it comes back
            // after sleep/network changes.
            manager.isOnDemandEnabled = true
            manager.onDemandRules = [NEOnDemandRuleConnect()]
            manager.saveToPreferences { error in
                if let error {
                    completion(.failure(NetworkExtensionEnrollmentError.saveFailed(error)))
                    return
                }
                // The one moment this app knows for certain it just
                // created this configuration — see `currentOwnership`'s
                // own doc comment for why this is recorded at all.
                UserDefaults.standard.set(true, forKey: selfCreatedMarkerKey(providerBundleIdentifier))
                // Found on real hardware (#159), not anticipated: calling
                // `sendProviderMessage` on this same in-memory `manager`
                // immediately after `saveToPreferences` failed with
                // `NEVPNErrorDomain` error 1 (`configurationInvalid`) — a
                // known NetworkExtension gotcha, not unique to this app.
                // `manager`'s own `connection` was built before the
                // configuration existed in the system's store; saving does
                // not retroactively fix it up. `loadFromPreferences`
                // re-fetches the manager from that store, with a
                // `connection` actually tied to the persisted
                // configuration, which is what a caller needs before using
                // it at all.
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
        sendInvitation(verb: "enroll", invitation: invitation, manager: manager, completion: completion)
    }

    /// As [`enroll`], but for a device that is already enrolled — sends the
    /// `"re-enroll"` verb `PacketTunnelProvider.handleAppMessage` maps to
    /// `reEnrollInvitation`, which explicitly replaces the existing saved
    /// config instead of refusing. `AppDelegate`'s "Re-enroll…" item is the
    /// only caller; ordinary first-time setup still goes through [`enroll`].
    static func reEnroll(
        invitation: String,
        manager: NETunnelProviderManager,
        completion: @escaping (Result<Void, Error>) -> Void
    ) {
        sendInvitation(verb: "re-enroll", invitation: invitation, manager: manager, completion: completion)
    }

    /// Shared body for [`enroll`] and [`reEnroll`] — they differ only in
    /// which verb string the extension dispatches on
    /// (`PacketTunnelProvider.handleAppMessage`'s `"enroll"` vs.
    /// `"re-enroll"` cases), not in how the round trip itself is sent,
    /// logged, or its response interpreted.
    private static func sendInvitation(
        verb: String,
        invitation: String,
        manager: NETunnelProviderManager,
        completion: @escaping (Result<Void, Error>) -> Void
    ) {
        guard let session = manager.connection as? NETunnelProviderSession else {
            os_log("KARST-TRACE host %{public}@: manager.connection is not a NETunnelProviderSession", log: Self.log, type: .default, verb)
            completion(.failure(NetworkExtensionEnrollmentError.sessionUnavailable))
            return
        }
        os_log(
            "KARST-TRACE host %{public}@: session.status=%{public}@ before sendProviderMessage",
            log: Self.log, type: .default, verb, String(describing: session.status)
        )

        let payload: [String: Any] = ["verb": verb, "invitation": invitation]
        guard let requestData = try? JSONSerialization.data(withJSONObject: payload) else {
            completion(.failure(NetworkExtensionEnrollmentError.invalidResponseEncoding))
            return
        }

        let sentAt = Date()
        do {
            try session.sendProviderMessage(requestData) { responseData in
                let elapsed = Date().timeIntervalSince(sentAt)
                guard let responseData else {
                    os_log(
                        "KARST-TRACE host %{public}@: response after %{public}.2fs was nil",
                        log: Self.log, type: .default, verb, elapsed
                    )
                    completion(.failure(NetworkExtensionEnrollmentError.invalidResponseEncoding))
                    return
                }
                guard let text = String(data: responseData, encoding: .utf8) else {
                    os_log(
                        "KARST-TRACE host %{public}@: response after %{public}.2fs was %{public}d bytes, not valid UTF-8: %{public}@",
                        log: Self.log, type: .default, verb, elapsed, responseData.count, responseData as NSData
                    )
                    completion(.failure(NetworkExtensionEnrollmentError.invalidResponseEncoding))
                    return
                }
                os_log(
                    "KARST-TRACE host %{public}@: response after %{public}.2fs: %{public}@",
                    log: Self.log, type: .default, verb, elapsed, text
                )
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
            os_log(
                "KARST-TRACE host %{public}@: sendProviderMessage threw synchronously: %{public}@",
                log: Self.log, type: .default, verb, error.localizedDescription
            )
            completion(.failure(NetworkExtensionEnrollmentError.sendFailed(error)))
        }
    }
}
