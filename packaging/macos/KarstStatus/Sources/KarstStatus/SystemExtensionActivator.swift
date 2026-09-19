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
/// Wired into `AppDelegate.ensureNetworkExtensionReady` as the first of
/// the two calls that need to succeed before "Enroll…" can do anything —
/// this, then `NetworkExtensionEnrollment.ensureConfiguration`. Runs
/// silently at every launch (not only from the menu) — see
/// `AppDelegate.applicationDidFinishLaunching`'s own reasoning for why.
/// Verified end to end on real hardware (#159): a signed, notarized
/// extension bundle activating for real, not just reviewed against
/// Apple's published `SystemExtensions`/`OSSystemExtensionRequest` API.
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

    /// As `activate`, in reverse. Nothing calls this yet — `uninstall.sh`
    /// already documents that full deactivation isn't reliably scriptable
    /// from a root shell (needs SIP disabled), and no in-app "start over"
    /// action has needed to deactivate the extension itself rather than
    /// just re-enrolling — kept so a future one does not have to add this
    /// asymmetrically.
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
    /// (or an MDM profile — this is the actual, documented MDM mechanism
    /// for system extension approval, `com.apple.system-extension-policy`,
    /// distinct from and unrelated to #162's VPN-configuration question)
    /// to approve it in System Settings — this call does not itself
    /// resolve the request. No UI action needed here either way: the
    /// pending state resolves into `didFinishWithResult`/`didFailWithError`
    /// on its own once approved or declined, and the one OS-level prompt
    /// this triggers is not something this app's own UI needs to echo.
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
