// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

import AppKit
import Foundation

/// Keep installed app identity independent of the responding agent, including
/// when the tunnel is stopped or an older agent omits its build fields.
enum SoftwareVersionMenu {
    static func addItems(to menu: NSMenu, status: DaemonStatus?, bundle: Bundle = .main) {
        let appVersion = bundle.object(forInfoDictionaryKey: "KarstReleaseVersion") as? String
            ?? bundle.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "Unknown"
        let appBuild = bundle.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "Unknown"
        menu.addItem(withTitle: "App: \(appVersion) (build \(appBuild))", action: nil, keyEquivalent: "")
        menu.addItem(withTitle: "Running agent: \(status?.version ?? "Unknown")", action: nil, keyEquivalent: "")
        let revisionItem = menu.addItem(withTitle: "Agent revision: \(status?.revision ?? "Unknown")", action: nil, keyEquivalent: "")
        revisionItem.toolTip = "Source commit reported by the running agent; not an artifact digest."
        menu.addItem(NSMenuItem.separator())
    }
}
