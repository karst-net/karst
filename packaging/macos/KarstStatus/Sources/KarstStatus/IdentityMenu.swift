// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

import AppKit
import Foundation

/// This device's enrollment identity, as last established over
/// `sendProviderMessage`'s `"identity"` verb.
///
/// Four states, not the plain `String?` this used to be (#481): "never
/// enrolled" and "could not check" must drive different menu text and
/// different handling of a later failed check — collapsing them is
/// exactly what let an already-enrolled device with a temporarily
/// unreachable extension show "Enroll…" with no way to tell it apart from
/// a genuinely fresh install.
enum IdentityStatus: Equatable {
    /// Never checked yet, or the most recent check failed before any
    /// identity was ever confirmed.
    case unknown
    /// Confirmed as of the last successful check: `identity_handle`
    /// returned `Ok(None)` — no identity key on disk.
    case notEnrolled
    /// Confirmed as of the last successful check.
    case enrolled(handle: String, name: String?)
    /// `.enrolled` once, but the most recent check failed (extension
    /// unreachable, or the identity file could not be read) — kept rather
    /// than reverting to `.unknown`, so a transient failure never tells an
    /// already-enrolled device to re-enroll. See `AppDelegate.refreshIdentity`.
    case stale(handle: String, name: String?)

    /// What a failed check becomes: `.stale` if an identity was already
    /// confirmed, `.unknown` otherwise — never `.notEnrolled`, which only
    /// a confirmed `Ok(None)` earns.
    var afterFailedCheck: IdentityStatus {
        switch self {
        case .enrolled(let handle, let name), .stale(let handle, let name):
            return .stale(handle: handle, name: name)
        case .unknown, .notEnrolled:
            return .unknown
        }
    }
}

/// The identity/enroll section of the menu (#481) — factored out of
/// `AppDelegate` so its text can be exercised without an `NSApplication`,
/// the same shape `SoftwareVersionMenu` already uses.
enum IdentityMenu {
    static func addItems(
        to menu: NSMenu,
        identity: IdentityStatus,
        managerOwnership: NetworkExtensionEnrollment.ManagerOwnership?,
        target: AnyObject?,
        enrollAction: Selector,
        reEnrollAction: Selector
    ) {
        // Informational only — Enroll/Re-enroll below stay fully
        // functional either way. #162 considered hiding them outright for
        // a detected-managed configuration and rejected it as too risky on
        // a weaker heuristic than `managerOwnership`'s own: a false
        // "foreign" reading must never cost a real self-service user their
        // only way to (re-)enroll.
        if managerOwnership == .unknownOrForeign {
            menu.addItem(
                withTitle: "VPN configuration managed by your organization",
                action: nil,
                keyEquivalent: ""
            )
        }
        switch identity {
        case .unknown:
            menu.addItem(
                withTitle: "Enrollment status could not be checked yet",
                action: nil,
                keyEquivalent: ""
            )
            addEnrollItem(to: menu, target: target, enrollAction: enrollAction)
        case .notEnrolled:
            addEnrollItem(to: menu, target: target, enrollAction: enrollAction)
        case .enrolled(let handle, let name):
            addEnrolledItems(to: menu, handle: handle, name: name, target: target, reEnrollAction: reEnrollAction)
        case .stale(let handle, let name):
            menu.addItem(
                withTitle: "Enrollment status could not be rechecked — showing the last known identity",
                action: nil,
                keyEquivalent: ""
            )
            addEnrolledItems(to: menu, handle: handle, name: name, target: target, reEnrollAction: reEnrollAction)
        }
    }

    private static func addEnrollItem(to menu: NSMenu, target: AnyObject?, enrollAction: Selector) {
        let item = NSMenuItem(title: "Enroll…", action: enrollAction, keyEquivalent: "")
        item.target = target
        menu.addItem(item)
    }

    /// The friendly `name` when there is one (#163); the truncated handle
    /// alone otherwise — a device enrolled before #163 shipped, or one
    /// whose login never persisted a name, still gets a real menu item,
    /// not a blank or an error.
    private static func addEnrolledItems(
        to menu: NSMenu,
        handle: String,
        name: String?,
        target: AnyObject?,
        reEnrollAction: Selector
    ) {
        let identityItem = NSMenuItem(
            title: name.map { "Enrolled as \($0)" } ?? "Enrolled as \(truncatedHandle(handle))",
            action: nil,
            keyEquivalent: ""
        )
        identityItem.toolTip = name.map { "\($0)\n\(handle)" } ?? handle
        menu.addItem(identityItem)
        let reEnrollItem = NSMenuItem(title: "Re-enroll…", action: reEnrollAction, keyEquivalent: "")
        reEnrollItem.target = target
        menu.addItem(reEnrollItem)
    }

    /// The full 44-character handle is exact but not glanceable in a menu
    /// item; the full value stays reachable via `toolTip` above rather than
    /// dropped, since an operator comparing it against the admin console's
    /// own device list needs the whole thing at least once.
    private static func truncatedHandle(_ handle: String) -> String {
        guard handle.count > 16 else { return handle }
        let start = handle.prefix(8)
        let end = handle.suffix(8)
        return "\(start)…\(end)"
    }
}
