// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

import AppKit
import Foundation

// Compile against each shipped app's production parser and menu renderer.
// No NetworkExtension is started, no status is fetched, and no bundle from
// the test machine is used as a substitute for a running agent's identity.
func fixtureBundle(release: String?, shortVersion: String?, build: String?) throws -> Bundle {
    let identifier = UUID().uuidString
    let url = FileManager.default.temporaryDirectory.appendingPathComponent("karst-menu-\(identifier).app")
    let contents = url.appendingPathComponent("Contents")
    try FileManager.default.createDirectory(at: contents, withIntermediateDirectories: true)
    var info: [String: Any] = ["CFBundleIdentifier": "dev.karst.menu-test.\(identifier)", "CFBundlePackageType": "APPL"]
    if let release { info["KarstReleaseVersion"] = release }
    if let shortVersion { info["CFBundleShortVersionString"] = shortVersion }
    if let build { info["CFBundleVersion"] = build }
    let data = try PropertyListSerialization.data(fromPropertyList: info, format: .xml, options: 0)
    try data.write(to: contents.appendingPathComponent("Info.plist"))
    guard let bundle = Bundle(url: url) else { fatalError("test bundle could not be opened") }
    return bundle
}

try MainActor.assumeIsolated {
    let installed = try fixtureBundle(release: "v0.1.0-rc.99", shortVersion: "0.1.0", build: "202610310001")
    let olderBundle = try fixtureBundle(release: nil, shortVersion: "0.0.7", build: "7")
    defer {
        try? FileManager.default.removeItem(at: installed.bundleURL)
        try? FileManager.default.removeItem(at: olderBundle.bundleURL)
    }

    let running = StatusParser.parseJSON(#"{"interface":"karst0","version":"v0.1.0-rc.31","revision":"running-commit","peers":[]}"#)
    let menu = NSMenu()
    SoftwareVersionMenu.addItems(to: menu, status: running, bundle: installed)
    let titles = menu.items.map(\.title)
    precondition(titles.contains("App: v0.1.0-rc.99 (build 202610310001)"), "prerelease identity must not collapse to the numeric marketing version")
    precondition(titles.contains("Running agent: v0.1.0-rc.31"), "an app upgrade must not relabel an old running agent")
    precondition(titles.contains("Agent revision: running-commit"))

    let legacy = StatusParser.parseJSON(#"{"interface":"karst0","peers":[]}"#)
    for status in [nil, legacy] as [DaemonStatus?] {
        let unknown = NSMenu()
        SoftwareVersionMenu.addItems(to: unknown, status: status, bundle: installed)
        precondition(unknown.items.map(\.title).contains("Running agent: Unknown"))
        precondition(unknown.items.map(\.title).contains("Agent revision: Unknown"))
        precondition(unknown.items.map(\.title).contains("App: v0.1.0-rc.99 (build 202610310001)"))
    }

    let fallback = NSMenu()
    SoftwareVersionMenu.addItems(to: fallback, status: nil, bundle: olderBundle)
    precondition(fallback.items.map(\.title).contains("App: 0.0.7 (build 7)"), "older bundles retain their own installed version")
    print("AppKit software menus preserve installed, running, prerelease, and unknown identities")
}
