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
/// - No managed-device-ownership banner (`ManagerOwnership`,
///   `NetworkExtensionEnrollment.currentOwnership` in the Developer-ID
///   build) — ADR-0040 item 4 is explicit that the App Store build does not
///   need managed-device/MDM coexistence at all.
/// - No custom menu-bar icon assets (`KarstStatus`'s five `menu-*.png`
///   states) — a plain text status item is enough to prove enroll/status
///   works; the polished menu-bar presentation is feature-parity work for a
///   later pass, not foundational.
///
/// What is kept: enroll/re-enroll, the identity display, periodic status
/// polling, and (#499) the Exit node menu — `KarstStatus`'s own
/// `ExitNodeMenu`/`changeExitNode` ported verbatim, since ADR-0036 §3's
/// decision (no local authorization gate on a self-service install) applies
/// identically here: both this host app and its extension already run as
/// the same console user with no credential check available to either side,
/// which is the condition ADR-0036 §3 actually turns on, not a root/non-root
/// distinction. Managed-device auto-consent (ADR-0036 §4) stays out of scope
/// (ADR-0040 item 4).
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
        SoftwareVersionMenu.addItems(to: menu, status: status)
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
        addExitNodeItem(to: menu, status: status)
        menu.addItem(NSMenuItem.separator())
        addIdentityAndEnrollItems(to: menu)
        menu.addItem(NSMenuItem.separator())
        menu.addItem(withTitle: "Quit", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        return menu
    }

    /// The Exit node submenu (ADR-0036 §3) — see `ExitNodeMenu`. Always
    /// unmanaged on this build: ADR-0040 item 4 keeps `ExitNodeAutoConsent`/
    /// managed-device coexistence out of scope for this self-service-only
    /// distribution channel, so there is no `exitManaged` state to track.
    private func addExitNodeItem(to menu: NSMenu, status: DaemonStatus) {
        ExitNodeMenu.addItems(
            to: menu,
            status: status,
            exitManaged: false,
            target: self,
            useAction: #selector(runExitUse(_:)),
            disableAction: #selector(runExitDisable)
        )
    }

    @objc private func runExitUse(_ sender: NSMenuItem) {
        guard let offer = sender.representedObject as? ExitOffer else { return }
        // The disclosure docs/subnet-routers-and-exit-nodes.md §3 requires
        // before consent, in the words that section uses.
        let alert = NSAlert()
        alert.messageText = "Send this Mac's traffic through \(offer.gatewayName ?? "the exit node")?"
        alert.informativeText = """
            All of this Mac's internet traffic will leave through the exit node, \
            which can see the destinations it reaches (and the contents of anything \
            not encrypted).
            """
        alert.addButton(withTitle: "Use Exit Node")
        alert.addButton(withTitle: "Cancel")
        NSApp.activate(ignoringOtherApps: true)
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        changeExitNode(routeID: offer.routeID)
    }

    @objc private func runExitDisable() {
        changeExitNode(routeID: nil)
    }

    /// Ask the extension to consent to `routeID` or, with `nil`, to
    /// withdraw consent (ADR-0036 §3). Not gated locally — this build is
    /// self-service only (ADR-0040 item 4).
    private func changeExitNode(routeID: String?) {
        client.sendExitCommand(routeID: routeID) { [weak self] result in
            DispatchQueue.main.async {
                guard let self else { return }
                switch result {
                case .failure(let error):
                    self.showAlert(title: "Exit Node Not Changed", message: error.localizedDescription)
                case .success(let text):
                    if
                        let data = text.data(using: .utf8),
                        let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                        let refusal = object["error"] as? String
                    {
                        self.showAlert(title: "Exit Node Not Changed", message: refusal)
                    }
                    self.refresh()
                }
            }
        }
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
