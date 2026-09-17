// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

import Foundation
import SystemExtensions

/// Submits and tracks one `OSSystemExtensionRequest` — the "activation/approval"
/// half of docs/adr/0026-macos-network-extension-backend.md item 7. A system
/// extension does not start just because its bundle exists inside
/// `Karst.app/Contents/Library/SystemExtensions/`
/// (scripts/build-macos-pkg.sh stages it there): macOS refuses to run it
/// until this app asks, once, and either an MDM profile pre-approves the
/// request or the user clicks through the resulting System
/// Settings ("System Settings > Privacy & Security > *Allow*") prompt
/// themselves.
///
/// **Not wired into `AppDelegate`'s menu yet**, for the same reason
/// `NetworkExtensionClient.swift`/`NetworkExtensionEnrollment.swift` still
/// aren't: activation is only the first of three steps a real "turn on the
/// NetworkExtension build" flow needs (activate this, then
/// `NetworkExtensionEnrollment.ensureConfiguration`, then
/// `NetworkExtensionEnrollment.enroll`), and deciding how that flow is
/// surfaced — a menu item, automatic on first launch, gated behind a
/// preference — is a product decision this file does not make on its own.
/// Written and reviewed against Apple's published
/// `SystemExtensions`/`OSSystemExtensionRequest` API, not run: nothing has
/// submitted a real request against a signed, notarized extension bundle,
/// which is the only way any of this is actually exercised — ADR-0026 items
/// 1 and 7's remaining packaging/signing work.
final class SystemExtensionActivator: NSObject, OSSystemExtensionRequestDelegate {
    /// Held for the request's lifetime — `OSSystemExtensionManager` does
    /// not retain its delegate, and this class's only owner today would
    /// otherwise be a local variable that could be deallocated before the
    /// asynchronous result ever arrives.
    private static var current: SystemExtensionActivator?

    private let completion: (Result<OSSystemExtensionRequest.Result, Error>) -> Void

    private init(completion: @escaping (Result<OSSystemExtensionRequest.Result, Error>) -> Void) {
        self.completion = completion
    }

    /// Ask macOS to activate `extensionIdentifier` — `dev.karst.packettunnel`
    /// (`KarstPacketTunnel/Info.plist`'s `CFBundleIdentifier`) once a real
    /// signed build exists to pass here. Takes the identifier as a
    /// parameter rather than hardcoding it, the same posture
    /// `NetworkExtensionEnrollment.ensureConfiguration` already holds:
    /// whoever wires this in decides the real value once the extension
    /// target is signed and packaged, not this file.
    ///
    /// `completion` fires on the queue given to
    /// `OSSystemExtensionRequest.activationRequest` — main, here — exactly
    /// once, whether the request finished, failed, or (see
    /// `requestNeedsUserApproval`) is merely still pending a user's click.
    static func activate(
        extensionIdentifier: String,
        completion: @escaping (Result<OSSystemExtensionRequest.Result, Error>) -> Void
    ) {
        let activator = SystemExtensionActivator(completion: completion)
        current = activator
        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: extensionIdentifier,
            queue: .main
        )
        request.delegate = activator
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    /// As `activate`, in reverse — `karst-setup`'s "Start Over" recovery
    /// path (`AppDelegate.swift`'s `addSetupItem` doc comment) will need
    /// this once the NetworkExtension build has its own equivalent, so it
    /// exists now rather than being bolted on asymmetrically later.
    static func deactivate(
        extensionIdentifier: String,
        completion: @escaping (Result<OSSystemExtensionRequest.Result, Error>) -> Void
    ) {
        let activator = SystemExtensionActivator(completion: completion)
        current = activator
        let request = OSSystemExtensionRequest.deactivationRequest(
            forExtensionWithIdentifier: extensionIdentifier,
            queue: .main
        )
        request.delegate = activator
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    func request(
        _ request: OSSystemExtensionRequest,
        didFinishWithResult result: OSSystemExtensionRequest.Result
    ) {
        completion(.success(result))
        Self.current = nil
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        completion(.failure(error))
        Self.current = nil
    }

    /// Fires once macOS has queued the request and is waiting on the user
    /// (or an MDM profile) to approve it in System Settings — this call
    /// does not itself resolve the request. Nothing to do here beyond what
    /// the type's own doc comment already says: whoever wires this in
    /// decides how to reflect "pending approval" in the UI, since today
    /// nothing calls `activate` at all for there to be a UI state for yet.
    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {}

    /// Only ever asked when a *different* version of this same extension is
    /// already installed — `.replace` is correct unconditionally here: a
    /// build that ships a new bundle wants that bundle running, not the one
    /// it replaced, and there is no in-place upgrade case where Karst would
    /// want to keep the old version active instead.
    func request(
        _ request: OSSystemExtensionRequest,
        actionForReplacingExtension existing: OSSystemExtensionProperties,
        withExtension ext: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction {
        .replace
    }
}
