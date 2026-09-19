// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

import AppKit
import Foundation
import NetworkExtension
import os.log

/// The whole app: one `NSStatusItem`, refreshed on a timer.
///
/// No window, no Dock icon — `main.swift` sets `.accessory` activation
/// policy — because this exists to be glanced at, not opened.
///
/// NetworkExtension is the sole macOS backend (ADR-0026's amended
/// decision, #159): there used to be a second, independent `karstd`
/// LaunchDaemon backend here too, with its own separate "Enrollment…" menu
/// item — dropped once real device testing verified the NetworkExtension
/// path end to end (activation, entitlements, enrollment) and confirmed
/// Bedrock's actual cryptographic guarantee (peering trust,
/// `spec/bedrock-v1.md`) already runs identically on both, since
/// `EngineHandle`/`run_with_adopted_fd` (ADR-0030) reuses the same shared
/// Rust engine either way — the only real gap was full-tunnel routing
/// lockdown, tracked as its own follow-up rather than blocking this.
final class AppDelegate: NSObject, NSApplicationDelegate {
    private static let log = OSLog(subsystem: "dev.karst.karststatus", category: "app")
    private static let pollInterval: TimeInterval = 2.0

    /// The `NEPacketTunnelProvider` system extension's own bundle
    /// identifier — `KarstPacketTunnel/Info.plist`'s `CFBundleIdentifier`,
    /// the same value `SystemExtensionActivator`/`NetworkExtensionEnrollment`/
    /// `NetworkExtensionStatusClient` all take as a parameter rather than
    /// hardcoding themselves.
    private static let networkExtensionIdentifier = "dev.karst.packettunnel"

    private let statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
    private let client = NetworkExtensionStatusClient(providerBundleIdentifier: AppDelegate.networkExtensionIdentifier)
    private var timer: Timer?

    /// Previous poll's totals per peer hint, so throughput can be shown as a
    /// rate. `PeerStatus.txBytes`/`rxBytes` are cumulative — see its doc
    /// comment — and differencing them is this client's job, not the
    /// daemon's (plans/phase-6/13-macos-status-indicators.md §1).
    private var previous: [String: (txBytes: UInt64, rxBytes: UInt64, at: Date)] = [:]

    func applicationDidFinishLaunching(_ notification: Notification) {
        statusItem.button?.imagePosition = .imageLeft
        statusItem.button?.image = Self.karstMarkIcon(.loading, accessibilityDescription: "karst: loading")
        statusItem.button?.title = "karst: …"
        statusItem.menu = menu(for: nil)
        refresh()
        timer = Timer.scheduledTimer(withTimeInterval: Self.pollInterval, repeats: true) { [weak self] _ in
            self?.refresh()
        }

        // Activation and VPN-configuration registration are one-time,
        // idempotent, invitation-independent steps (#159) — running them
        // here, silently, at every launch means a user who opens "Enroll…"
        // usually finds both already done, rather than needing a menu
        // item to do them first. Can't move this into the .pkg's
        // `postinstall` instead: `OSSystemExtensionRequest` must be
        // submitted by a live GUI app process tied to the console user's
        // session, which a root-context installer script never has. The
        // one OS-level "Allow" prompt this triggers is unavoidable and
        // shows itself; nothing else here should surprise a user who
        // hasn't clicked anything yet, so failures are logged, not alerted.
        ensureNetworkExtensionReady { result in
            switch result {
            case .success:
                os_log("network extension ready at launch", log: Self.log, type: .info)
            case .failure(let error):
                os_log(
                    "network extension not ready at launch (will retry from the menu): %{public}@",
                    log: Self.log, type: .info, error.localizedDescription
                )
            }
        }
    }

    /// `NetworkExtensionStatusClient`'s completion is not guaranteed to
    /// fire on any particular queue (the underlying `NETunnelProviderManager`/
    /// `sendProviderMessage` APIs do not document one), so `render` is
    /// always dispatched to the main queue explicitly rather than assumed.
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

    /// **No state here is color-only** —
    /// plans/phase-6/13-macos-status-indicators.md §2 item 4, applying
    /// PLAN.md §8.3's console rule to this client. Each state pairs a
    /// distinct icon shape with distinct text; a colorblind user reads the
    /// icon and the words, never a dot's hue alone. SF Symbols render as
    /// template images (`isTemplate = true`, set in `symbolImage`), so
    /// AppKit — not this code — handles light/dark menu bar and the
    /// selected-item tint.
    private func render(_ status: DaemonStatus?) {
        guard let status, !status.interface.isEmpty else {
            statusItem.button?.image = Self.karstMarkIcon(.notRunning, accessibilityDescription: "karst: not running")
            statusItem.button?.title = "karst: not running"
            statusItem.menu = menu(for: nil)
            return
        }

        let established = status.peers.filter { $0.state.hasPrefix("established") }
        let markState: MarkState
        let label: String
        if established.isEmpty {
            markState = .noPeers
            label = "no peers"
        } else if established.contains(where: { $0.transport == "relay" || $0.transport == "turn" }) {
            // A mix of direct and relayed peers still reports the relayed
            // state — the whole point of `Transport` not collapsing to a
            // bool (`engine.rs`'s doc comment on it) is that "slower and
            // through a third party" must stay visible, not be averaged
            // away by a healthier peer sitting next to it.
            markState = .relayed
            label = "\(established.count) via relay/TURN"
        } else {
            markState = .direct
            label = "\(established.count) direct"
        }

        let rate = throughputRate(for: status.peers)
        statusItem.button?.image = Self.karstMarkIcon(markState, accessibilityDescription: label)
        statusItem.button?.title = "karst: \(label)\(rate)"
        statusItem.menu = menu(for: status)
    }

    /// Template images so AppKit re-tints them for light/dark menu bars and
    /// the highlighted state, rather than this code tracking appearance
    /// itself. `nil` only if `name` is not a real SF Symbol — a programmer
    /// error, not a runtime condition, so callers pass string literals.
    private static func symbolImage(_ name: String, accessibilityDescription: String) -> NSImage? {
        let image = NSImage(systemSymbolName: name, accessibilityDescription: accessibilityDescription)
        image?.isTemplate = true
        return image
    }

    /// The five menu-bar states. Each names a bundled
    /// `Contents/Resources/menu-<state>.png` (`scripts/build-macos-pkg.sh`
    /// stages them — not a SwiftPM `resources:` entry, since
    /// `Bundle.module`'s lookup differs depending on whether this is
    /// running from inside an .app bundle or a bare `swift build` binary,
    /// and this way sidesteps that entirely). A code-drawn version of these
    /// (composited SF Symbols, then hand-built vector shapes) was tried and
    /// rejected on real hardware — neither read cleanly at menu bar size —
    /// so this is deliberately dumb: five flat image files, each a
    /// hand-designed asset rather than something this code generates.
    private enum MarkState: String {
        case loading = "menu-loading"
        case notRunning = "menu-not-running"
        case noPeers = "menu-no-peers"
        case relayed = "menu-relayed"
        case direct = "menu-direct"
    }

    /// The height every menu-bar icon renders at, in points. Deliberately
    /// set explicitly rather than left at `NSImage`'s own default: loading a
    /// PNG with `NSImage(contentsOfFile:)` sizes it from the file's raw
    /// pixel dimensions (256×226 for these assets) with no DPI-aware
    /// scaling, so an unmodified load reports itself as 256×226 *points* —
    /// enormous next to an actual ~22pt menu bar. `NSStatusBarButton` does
    /// not scale a custom image down to fit; it draws at the image's own
    /// reported size and lets the bar clip whatever does not fit, which is
    /// what "zoomed in too far" (#159) actually was: a small, cropped
    /// corner of a huge image, not a rendering bug in the assets themselves.
    private static let menuBarIconHeight: CGFloat = 18

    private static func karstMarkIcon(_ state: MarkState, accessibilityDescription: String) -> NSImage? {
        guard let path = Bundle.main.path(forResource: state.rawValue, ofType: "png"),
              let image = NSImage(contentsOfFile: path)
        else { return nil }
        let aspect = image.size.width / image.size.height
        image.size = NSSize(width: menuBarIconHeight * aspect, height: menuBarIconHeight)
        image.isTemplate = true
        image.accessibilityDescription = accessibilityDescription
        return image
    }

    private func throughputRate(for peers: [PeerStatus]) -> String {
        let now = Date()
        var totalTx: Double = 0
        var totalRx: Double = 0
        for peer in peers {
            if let prev = previous[peer.hint] {
                let elapsed = now.timeIntervalSince(prev.at)
                // A negative delta means the counter was not carried over —
                // `karstd` restarted, or this peer's session slot is new.
                // Reporting that as negative throughput would be nonsense;
                // skipping it for one tick and resuming next poll is not.
                if elapsed > 0, peer.txBytes >= prev.txBytes, peer.rxBytes >= prev.rxBytes {
                    totalTx += Double(peer.txBytes - prev.txBytes) / elapsed
                    totalRx += Double(peer.rxBytes - prev.rxBytes) / elapsed
                }
            }
            previous[peer.hint] = (peer.txBytes, peer.rxBytes, now)
        }
        guard totalTx > 0 || totalRx > 0 else { return "" }
        return " (↑\(formatRate(totalTx)) ↓\(formatRate(totalRx)))"
    }

    private func formatRate(_ bytesPerSecond: Double) -> String {
        let units = ["B/s", "KB/s", "MB/s", "GB/s"]
        var value = bytesPerSecond
        var unitIndex = 0
        while value >= 1024, unitIndex < units.count - 1 {
            value /= 1024
            unitIndex += 1
        }
        return String(format: "%.1f %@", value, units[unitIndex])
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
            addEnrollItem(to: menu)
            menu.addItem(NSMenuItem.separator())
            menu.addItem(withTitle: "Quit", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
            return menu
        }

        menu.addItem(withTitle: "Interface: \(status.interface) (MTU \(status.mtu))", action: nil, keyEquivalent: "")
        menu.addItem(NSMenuItem.separator())
        if status.peers.isEmpty {
            menu.addItem(withTitle: "No peers configured", action: nil, keyEquivalent: "")
        }
        for peer in status.peers {
            let title = "\(peer.name) — \(peer.state), \(peer.transport)"
            let item = NSMenuItem(title: title, action: nil, keyEquivalent: "")
            item.image = Self.symbolImage(stateSymbolName(for: peer), accessibilityDescription: peer.state)
            menu.addItem(item)
        }
        menu.addItem(NSMenuItem.separator())
        addEnrollItem(to: menu)
        menu.addItem(NSMenuItem.separator())
        menu.addItem(withTitle: "Quit", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        return menu
    }

    /// Always present, running or not: it is also how an already-enrolled
    /// device recovers from a config a resume path can't use, not only how
    /// first enrollment happens.
    private func addEnrollItem(to menu: NSMenu) {
        let item = NSMenuItem(title: "Enroll…", action: #selector(runEnroll), keyEquivalent: "")
        item.target = self
        menu.addItem(item)
    }

    /// Activates the system extension and ensures its `NETunnelProviderManager`
    /// configuration is saved — the two one-time, invitation-independent
    /// steps `applicationDidFinishLaunching` already runs silently at every
    /// launch. Called again here, idempotently, as the natural retry path
    /// if launch-time setup did not finish (denied, or not yet approved) —
    /// in the common case this resolves near-instantly since both steps
    /// are already done by the time a user opens this menu at all.
    private func ensureNetworkExtensionReady(
        completion: @escaping (Result<NETunnelProviderManager, Error>) -> Void
    ) {
        SystemExtensionActivator.activate(extensionIdentifier: Self.networkExtensionIdentifier) { result in
            switch result {
            case .failure(let error):
                completion(.failure(error))
            case .success:
                // `controlURL` is a placeholder empty string:
                // `NETunnelProviderProtocol.serverAddress` is System
                // Settings' own VPN-list display field, not something the
                // enrollment handshake itself reads — the invitation
                // pasted into `askInvitation` carries the real
                // control-plane address, inside the Rust enrollment logic
                // `enrollInvitation` runs — see
                // `NetworkExtensionEnrollment.ensureConfiguration`'s own
                // doc comment. Parsing the invitation client-side in Swift
                // just to populate a display string before the user has
                // pasted one yet is not worth doing until something other
                // than System Settings' own list actually reads it.
                NetworkExtensionEnrollment.ensureConfiguration(
                    providerBundleIdentifier: Self.networkExtensionIdentifier,
                    controlURL: "",
                    completion: completion
                )
            }
        }
    }

    /// The one remaining user-facing action: pasting an invitation. Each
    /// step reports its own failure by name, since the chain has
    /// independently-shaped ways to fail (an activation the user must
    /// separately approve in System Settings, a `NETunnelProviderManager`
    /// save, and the enrollment handshake itself) — collapsing them into
    /// one generic error would leave an operator guessing which step to
    /// retry.
    @objc private func runEnroll() {
        ensureNetworkExtensionReady { [weak self] result in
            guard let self else { return }
            switch result {
            case .failure(let error):
                self.showAlert(
                    title: "Could Not Prepare the Network Extension",
                    message: error.localizedDescription
                )
            case .success(let manager):
                guard let invitation = self.askInvitation() else { return }
                NetworkExtensionEnrollment.enroll(invitation: invitation, manager: manager) { [weak self] result in
                    guard let self else { return }
                    switch result {
                    case .failure(let error):
                        self.showAlert(title: "Enrollment Failed", message: error.localizedDescription)
                    case .success:
                        self.showAlert(title: "Enrolled", message: "This device is now enrolled.")
                    }
                }
            }
        }
    }

    /// A roomy paste field for an invitation — native `AppKit`.
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

    /// One shape for every result this flow reports, success or failure —
    /// an operator reads whichever `title` fired, not a distinct dialog
    /// class per step.
    private func showAlert(title: String, message: String) {
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = message
        alert.addButton(withTitle: "OK")
        NSApp.activate(ignoringOtherApps: true)
        alert.runModal()
    }

    private func stateSymbolName(for peer: PeerStatus) -> String {
        guard peer.state.hasPrefix("established") else { return "circle" }
        switch peer.transport {
        case "direct": return "circle.fill"
        case "relay", "turn": return "circle.lefthalf.filled"
        default: return "triangle"
        }
    }
}
