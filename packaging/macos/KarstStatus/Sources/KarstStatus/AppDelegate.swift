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
    /// `ipc::DEFAULT_STATUS_SOCKET` on the Rust side. Hardcoded rather than
    /// configurable: the two must agree, and a mismatched pair fails as "not
    /// running" rather than something a user can debug from this app alone.
    private static let socketPath = "/run/karst-status/karstd.sock"
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
    /// distinct glyph with distinct text; a colorblind user reads the glyph
    /// and the words, never a dot's hue alone.
    private func render(_ status: DaemonStatus?) {
        guard let status, !status.interface.isEmpty else {
            statusItem.button?.title = "⛔ karst: not running"
            statusItem.menu = menu(for: nil)
            return
        }

        let established = status.peers.filter { $0.state.hasPrefix("established") }
        let glyph: String
        let label: String
        if established.isEmpty {
            glyph = "○"
            label = "no peers"
        } else if established.contains(where: { $0.transport == "relay" || $0.transport == "turn" }) {
            // A mix of direct and relayed peers still reports the relayed
            // state — the whole point of `Transport` not collapsing to a
            // bool (`engine.rs`'s doc comment on it) is that "slower and
            // through a third party" must stay visible, not be averaged
            // away by a healthier peer sitting next to it.
            glyph = "◐"
            label = "\(established.count) via relay/TURN"
        } else {
            glyph = "●"
            label = "\(established.count) direct"
        }

        let rate = throughputRate(for: status.peers)
        statusItem.button?.title = "\(glyph) karst: \(label)\(rate)"
        statusItem.menu = menu(for: status)
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
            menu.addItem(withTitle: "Quit", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
            return menu
        }

        menu.addItem(withTitle: "Interface: \(status.interface) (MTU \(status.mtu))", action: nil, keyEquivalent: "")
        menu.addItem(NSMenuItem.separator())
        if status.peers.isEmpty {
            menu.addItem(withTitle: "No peers configured", action: nil, keyEquivalent: "")
        }
        for peer in status.peers {
            let title = "\(stateSymbol(for: peer)) \(peer.name) — \(peer.state), \(peer.transport)"
            menu.addItem(withTitle: title, action: nil, keyEquivalent: "")
        }
        menu.addItem(NSMenuItem.separator())
        menu.addItem(withTitle: "Quit", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        return menu
    }

    private func stateSymbol(for peer: PeerStatus) -> String {
        guard peer.state.hasPrefix("established") else { return "○" }
        switch peer.transport {
        case "direct": return "●"
        case "relay", "turn": return "◐"
        default: return "△"
        }
    }
}
