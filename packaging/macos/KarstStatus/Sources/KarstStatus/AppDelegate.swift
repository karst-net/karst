// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

import AppKit
import Foundation

/// The whole app: one `NSStatusItem`, refreshed on a timer.
///
/// No window, no Dock icon — `main.swift` sets `.accessory` activation
/// policy — because this exists to be glanced at, not opened.
final class AppDelegate: NSObject, NSApplicationDelegate {
    /// Where `karstd --status-socket` was told to listen —
    /// `ipc::DEFAULT_STATUS_SOCKET` on the Rust side (its macOS variant:
    /// `/run` does not exist on macOS at all — the root volume is a
    /// read-only sealed system volume — `/var/run` is Darwin's equivalent).
    /// Hardcoded rather than configurable: the two must agree, and a
    /// mismatched pair fails as "not running" rather than something a user
    /// can debug from this app alone.
    private static let socketPath = "/var/run/karst-status/karstd.sock"
    private static let pollInterval: TimeInterval = 2.0

    private let statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
    private let client = StatusClient(socketPath: AppDelegate.socketPath)
    private var timer: Timer?

    /// Previous poll's totals per peer hint, so throughput can be shown as a
    /// rate. `PeerStatus.txBytes`/`rxBytes` are cumulative — see its doc
    /// comment — and differencing them is this client's job, not the
    /// daemon's (plans/phase-6/13-macos-status-indicators.md §1).
    private var previous: [String: (txBytes: UInt64, rxBytes: UInt64, at: Date)] = [:]

    func applicationDidFinishLaunching(_ notification: Notification) {
        statusItem.button?.imagePosition = .imageLeft
        statusItem.button?.image = Self.brandedIcon(badge: "ellipsis.circle", accessibilityDescription: "karst: loading")
        statusItem.button?.title = "karst: …"
        statusItem.menu = menu(for: nil)
        refresh()
        timer = Timer.scheduledTimer(withTimeInterval: Self.pollInterval, repeats: true) { [weak self] _ in
            self?.refresh()
        }
    }

    /// Fetches off the main thread — a slow or hung daemon must not freeze
    /// the menu bar, which is the one thing this app exists to keep
    /// responsive.
    private func refresh() {
        DispatchQueue.global(qos: .utility).async { [weak self] in
            guard let self else { return }
            let status: DaemonStatus?
            do {
                status = StatusParser.parse(try self.client.fetchStatus())
            } catch {
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
            statusItem.button?.image = Self.brandedIcon(badge: "xmark.circle.fill", accessibilityDescription: "karst: not running")
            statusItem.button?.title = "karst: not running"
            statusItem.menu = menu(for: nil)
            return
        }

        let established = status.peers.filter { $0.state.hasPrefix("established") }
        let symbolName: String
        let label: String
        if established.isEmpty {
            symbolName = "circle"
            label = "no peers"
        } else if established.contains(where: { $0.transport == "relay" || $0.transport == "turn" }) {
            // A mix of direct and relayed peers still reports the relayed
            // state — the whole point of `Transport` not collapsing to a
            // bool (`engine.rs`'s doc comment on it) is that "slower and
            // through a third party" must stay visible, not be averaged
            // away by a healthier peer sitting next to it.
            symbolName = "circle.lefthalf.filled"
            label = "\(established.count) via relay/TURN"
        } else {
            symbolName = "circle.fill"
            label = "\(established.count) direct"
        }

        let rate = throughputRate(for: status.peers)
        statusItem.button?.image = Self.brandedIcon(badge: symbolName, accessibilityDescription: label)
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

    /// The Karst mountain mark, bundled at `Contents/Resources/karst-menu.png`
    /// by `scripts/build-macos-pkg.sh` (not a SwiftPM `resources:` entry —
    /// see that script's comment on why). Template so it tints like the SF
    /// Symbol badges it sits next to. Loaded once: the file never changes at
    /// runtime, only the badge composited onto it does.
    private static let brandMark: NSImage? = {
        guard let path = Bundle.main.path(forResource: "karst-menu", ofType: "png"),
              let image = NSImage(contentsOfFile: path)
        else { return nil }
        image.isTemplate = true
        return image
    }()

    /// Brand mark + a small state badge, composited into one image —
    /// `NSStatusBarButton` tints and highlights whatever single image it's
    /// given, so the badge has to be baked in rather than laid over the mark
    /// as a second view. Side-by-side, not corner-overlaid: the mark's
    /// silhouette runs edge-to-edge (see `karst-menu.png`'s crop), so a
    /// badge stamped over a corner would sit on top of the mountain shape
    /// rather than beside it.
    private static func brandedIcon(badge symbolName: String, accessibilityDescription: String) -> NSImage? {
        let badge = symbolImage(symbolName, accessibilityDescription: accessibilityDescription)
        guard let brand = brandMark, let badge else { return badge }
        let height: CGFloat = 16
        let gap: CGFloat = 3
        let badgeSize: CGFloat = 10
        let brandWidth = height * (brand.size.width / brand.size.height)
        let canvas = NSSize(width: brandWidth + gap + badgeSize, height: height)
        let composite = NSImage(size: canvas, flipped: false) { rect in
            brand.draw(in: NSRect(x: 0, y: 0, width: brandWidth, height: height))
            badge.draw(in: NSRect(x: brandWidth + gap, y: (height - badgeSize) / 2, width: badgeSize, height: badgeSize))
            return true
        }
        composite.isTemplate = true
        return composite
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
                withTitle: "karstd is not running, or was not started with --status-socket",
                action: nil,
                keyEquivalent: ""
            )
            menu.addItem(NSMenuItem.separator())
            addSetupItem(to: menu)
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
        addSetupItem(to: menu)
        menu.addItem(NSMenuItem.separator())
        menu.addItem(withTitle: "Quit", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        return menu
    }

    /// "Setup…" is always present, running or not: it is also how an
    /// already-enrolled device recovers from a config `--resume` cannot use
    /// (packaging/macos/karst-setup's `ask_recovery`/"Start Over"), not only
    /// how first enrollment happens.
    private func addSetupItem(to menu: NSMenu) {
        let item = NSMenuItem(title: "Setup…", action: #selector(runSetup), keyEquivalent: "")
        item.target = self
        menu.addItem(item)
    }

    /// Runs the guided-enrollment flow this used to be a second app for
    /// (Karst Setup.app). Its dialogs and privileged-enrollment logic
    /// (packaging/macos/karst-setup, bundled here as a resource rather than
    /// reimplemented in Swift) are unchanged; only how it is reached changed,
    /// from a separate Launchpad entry to this menu item. Launched detached
    /// — its own `display dialog` calls are independent windows with nothing
    /// here worth blocking the status item on while they run.
    @objc private func runSetup() {
        guard let script = Bundle.main.path(forResource: "karst-setup", ofType: nil) else { return }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/bash")
        process.arguments = [script]
        try? process.run()
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
