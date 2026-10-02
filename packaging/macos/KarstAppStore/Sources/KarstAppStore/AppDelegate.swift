// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

import AppKit
import Foundation
import NetworkExtension
import os.log

/// The Mac App Store host app's menu-bar item — a deliberately minimal-
/// viable sibling to `KarstStatus`'s own `AppDelegate.swift`
/// (docs/adr/0040-mac-app-store-needs-a-sandboxed-app-extension.md,
/// docs/adr/0043-mac-app-store-sandboxed-app-extension-target.md).
///
/// **What this first pass deliberately leaves out, and why**, per the scope
/// agreed before building this target:
/// - No exit-node submenu, no `ExitNodeAuthorization`/`ExitConsent` round
///   trip — `KarstPacketTunnelAppExtension.handleAppMessage` does not answer
///   `exit-use`/`exit-disable` either (see that file's own header comment).
/// - No managed-device-ownership banner (`ManagerOwnership`,
///   `NetworkExtensionEnrollment.currentOwnership` in the Developer-ID
///   build) — ADR-0040 item 4 is explicit that the App Store build does not
///   need managed-device/MDM coexistence at all.
/// - No custom menu-bar icon assets (`KarstStatus`'s five `menu-*.png`
///   states) — a plain text status item is enough to prove enroll/status
///   works; the polished menu-bar presentation is feature-parity work for a
///   later pass, not foundational.
///
/// What is kept: enroll/re-enroll, the identity display, and periodic status
/// polling — the minimum needed to prove the sandboxed App Extension can be
/// enrolled and queried at all, the same bar `KarstStatus`/`KarstPacketTunnel`
/// themselves had to clear first (ADR-0026/27/28) before exit-node/
/// managed-device features were layered on top of them.
final class AppDelegate: NSObject, NSApplicationDelegate {
    private static let log = OSLog(subsystem: "dev.karst.appstore", category: "app")
    private static let pollInterval: TimeInterval = 2.0

    /// `KarstPacketTunnelAppExtension/Info.plist`'s `CFBundleIdentifier` —
    /// distinct from the Developer-ID build's `dev.karst.packettunnel` (new,
    /// separate Developer Portal App ID, see ADR-0043).
    private static let networkExtensionIdentifier = "dev.karst.appstore.packettunnel"

    private let statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
    private let client = NetworkExtensionStatusClient(providerBundleIdentifier: AppDelegate.networkExtensionIdentifier)
    private var timer: Timer?

    private var lastStatus: DaemonStatus?
    private var identityHandle: String?
    private var identityName: String?

    func applicationDidFinishLaunching(_ notification: Notification) {
        statusItem.button?.title = "karst: …"
        statusItem.menu = menu(for: nil)
        refresh()
        timer = Timer.scheduledTimer(withTimeInterval: Self.pollInterval, repeats: true) { [weak self] _ in
            self?.refresh()
        }

        // Unlike KarstStatus's own launch-time call, there is no
        // `SystemExtensionActivator.activate` step here: the App Extension
        // activates with the app's own installation, not a separate
        // `OSSystemExtensionRequest` a live GUI process must submit. Only
        // the `NETunnelProviderManager` needs ensuring.
        NetworkExtensionEnrollment.ensureConfiguration(
            providerBundleIdentifier: Self.networkExtensionIdentifier,
            controlURL: ""
        ) { [weak self] result in
            switch result {
            case .success:
                os_log("network extension configuration ready at launch", log: Self.log, type: .info)
                self?.refreshIdentity()
            case .failure(let error):
                os_log(
                    "network extension configuration not ready at launch (will retry from the menu): %{public}@",
                    log: Self.log, type: .info, error.localizedDescription
                )
            }
        }
    }

    private func refresh() {
        client.fetchStatusJSON { [weak self] result in
            guard let self else { return }
            let status: DaemonStatus?
            switch result {
            case .success(let json):
                status = StatusParser.parseJSON(json)
            case .failure:
                status = nil
            }
            DispatchQueue.main.async {
                self.render(status)
            }
        }
    }

    private func render(_ status: DaemonStatus?) {
        lastStatus = status
        guard let status, !status.interface.isEmpty else {
            statusItem.button?.title = "karst: not running"
            statusItem.menu = menu(for: nil)
            return
        }
        let established = status.peers.filter { $0.state.hasPrefix("established") }
        let label = established.isEmpty ? "no peers" : "\(established.count) connected"
        statusItem.button?.title = "karst: \(label)"
        statusItem.menu = menu(for: status)
    }

    private func menu(for status: DaemonStatus?) -> NSMenu {
        let menu = NSMenu()
        guard let status else {
            menu.addItem(
                withTitle: "Karst tunnel is not running — not yet enrolled, or not connected",
                action: nil,
                keyEquivalent: ""
            )
            menu.addItem(NSMenuItem.separator())
            addIdentityAndEnrollItems(to: menu)
            menu.addItem(NSMenuItem.separator())
            menu.addItem(withTitle: "Quit", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
            return menu
        }

        menu.addItem(withTitle: "Interface: \(status.interface) (MTU \(status.mtu))", action: nil, keyEquivalent: "")
        let established = status.peers.filter { $0.state.hasPrefix("established") }
        menu.addItem(withTitle: established.isEmpty
            ? "No peers connected"
            : "\(established.count) of \(status.peers.count) peers connected", action: nil, keyEquivalent: "")
        menu.addItem(NSMenuItem.separator())
        addIdentityAndEnrollItems(to: menu)
        menu.addItem(NSMenuItem.separator())
        menu.addItem(withTitle: "Quit", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        return menu
    }

    private func addIdentityAndEnrollItems(to menu: NSMenu) {
        guard let identityHandle else {
            let item = NSMenuItem(title: "Enroll…", action: #selector(runEnroll), keyEquivalent: "")
            item.target = self
            menu.addItem(item)
            return
        }
        let identityItem = NSMenuItem(
            title: identityName.map { "Enrolled as \($0)" }
                ?? "Enrolled as \(Self.truncatedHandle(identityHandle))",
            action: nil,
            keyEquivalent: ""
        )
        identityItem.toolTip = identityName.map { "\($0)\n\(identityHandle)" } ?? identityHandle
        menu.addItem(identityItem)
        let reEnrollItem = NSMenuItem(title: "Re-enroll…", action: #selector(runReEnroll), keyEquivalent: "")
        reEnrollItem.target = self
        menu.addItem(reEnrollItem)
    }

    private static func truncatedHandle(_ handle: String) -> String {
        guard handle.count > 16 else { return handle }
        let start = handle.prefix(8)
        let end = handle.suffix(8)
        return "\(start)…\(end)"
    }

    private func refreshIdentity() {
        client.fetchIdentityHandle { [weak self] result in
            guard let self else { return }
            let handle: String?
            let name: String?
            switch result {
            case .success(let json):
                (handle, name) = Self.parseIdentity(json)
            case .failure:
                (handle, name) = (nil, nil)
            }
            DispatchQueue.main.async {
                self.identityHandle = handle
                self.identityName = name
                self.rebuildMenu()
            }
        }
    }

    private static func parseIdentity(_ json: String) -> (handle: String?, name: String?) {
        guard
            let data = json.data(using: .utf8),
            let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return (nil, nil) }
        return (object["handle"] as? String, object["name"] as? String)
    }

    private func rebuildMenu() {
        statusItem.menu = menu(for: lastStatus)
    }

    @objc private func runEnroll() {
        NetworkExtensionEnrollment.ensureConfiguration(
            providerBundleIdentifier: Self.networkExtensionIdentifier,
            controlURL: ""
        ) { [weak self] result in
            guard let self else { return }
            switch result {
            case .failure(let error):
                self.showAlert(title: "Could Not Prepare the Network Extension", message: error.localizedDescription)
            case .success(let manager):
                guard let invitation = self.askInvitation() else { return }
                NetworkExtensionEnrollment.enroll(invitation: invitation, manager: manager) { [weak self] result in
                    guard let self else { return }
                    switch result {
                    case .failure(let error):
                        self.showAlert(title: "Enrollment Failed", message: error.localizedDescription)
                    case .success:
                        self.refreshIdentity()
                        self.showAlert(title: "Enrolled", message: "This device is now enrolled.")
                    }
                }
            }
        }
    }

    @objc private func runReEnroll() {
        NetworkExtensionEnrollment.ensureConfiguration(
            providerBundleIdentifier: Self.networkExtensionIdentifier,
            controlURL: ""
        ) { [weak self] result in
            guard let self else { return }
            switch result {
            case .failure(let error):
                self.showAlert(title: "Could Not Prepare the Network Extension", message: error.localizedDescription)
            case .success(let manager):
                guard let invitation = self.askInvitation() else { return }
                NetworkExtensionEnrollment.reEnroll(invitation: invitation, manager: manager) { [weak self] result in
                    guard let self else { return }
                    switch result {
                    case .failure(let error):
                        self.showAlert(title: "Re-enrollment Failed", message: error.localizedDescription)
                    case .success:
                        self.refreshIdentity()
                        self.showAlert(title: "Re-enrolled", message: "This device is now enrolled under the new invitation.")
                    }
                }
            }
        }
    }

    private func askInvitation() -> String? {
        let alert = NSAlert()
        alert.messageText = "Paste the enrollment invitation from your administrator."
        alert.addButton(withTitle: "Connect")
        alert.addButton(withTitle: "Cancel")

        let textView = NSTextView(frame: NSRect(x: 0, y: 0, width: 560, height: 140))
        textView.font = NSFont.systemFont(ofSize: 13)
        textView.isVerticallyResizable = true
        textView.isHorizontallyResizable = false
        textView.autoresizingMask = [.width]
        textView.textContainer?.containerSize = NSSize(width: 560, height: CGFloat.greatestFiniteMagnitude)
        textView.textContainer?.widthTracksTextView = true

        let scrollView = NSScrollView(frame: NSRect(x: 0, y: 0, width: 560, height: 140))
        scrollView.borderType = .bezelBorder
        scrollView.hasVerticalScroller = true
        scrollView.autohidesScrollers = true
        scrollView.documentView = textView
        alert.accessoryView = scrollView

        NSApp.activate(ignoringOtherApps: true)
        guard alert.runModal() == .alertFirstButtonReturn else { return nil }
        let invitation = textView.string.trimmingCharacters(in: .whitespacesAndNewlines)
        return invitation.isEmpty ? nil : invitation
    }

    private func showAlert(title: String, message: String) {
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = message
        alert.addButton(withTitle: "OK")
        NSApp.activate(ignoringOtherApps: true)
        alert.runModal()
    }
}
