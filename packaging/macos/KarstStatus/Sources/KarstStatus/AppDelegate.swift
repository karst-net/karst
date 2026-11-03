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

    /// The status `render` last drew the menu from — kept so
    /// `rebuildMenu()` can redraw the menu on its own (after an identity
    /// refresh) without waiting for the next `refresh()` tick to hand it a
    /// fresh one.
    private var lastStatus: DaemonStatus?
    /// Whether an MDM profile manages the exit node (`ExitNodeAutoConsent`,
    /// ADR-0036 §4): the menu then shows the choice but offers no change.
    private var exitManaged = false

    /// This device's enrollment identity, as last established — see
    /// `IdentityStatus` (#481). Fetched once at launch and again after a
    /// successful enroll/re-enroll, not polled every tick like peer
    /// status: unlike that, it does not change on its own between
    /// enrollments.
    private var identityStatus: IdentityStatus = .unknown

    /// `nil` until the first `NetworkExtensionEnrollment.currentOwnership`
    /// check resolves — deliberately distinct from `.unknownOrForeign`,
    /// the same "not checked yet is not the same claim as checked and
    /// negative" distinction `identityStatus`'s own `.unknown` case now
    /// makes (#481) — so the very first render, before that async check
    /// has ever run, shows nothing rather than incorrectly claiming a
    /// personal install is organization-managed.
    private var managerOwnership: NetworkExtensionEnrollment.ManagerOwnership?

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
        ensureNetworkExtensionReady { [weak self] result in
            switch result {
            case .success:
                os_log("network extension ready at launch", log: Self.log, type: .info)
                // A device enrolled in an earlier launch already has an
                // identity on disk the extension can report without
                // needing another invitation — check now so the menu
                // shows "Re-enroll…" from the start rather than "Enroll…"
                // until the next status poll happens to notice.
                self?.refreshIdentity()
                self?.refreshManagerOwnership()
            case .failure(let error):
                os_log(
                    "network extension not ready at launch (will retry from the menu): %{public}@",
                    log: Self.log, type: .info, error.localizedDescription
                )
            }
        }
    }

    /// As `refreshIdentity()`, but for the UI-only "does this look like a
    /// managed configuration" heuristic
    /// (`NetworkExtensionEnrollment.currentOwnership`, #162) rather than
    /// enrollment identity — same trigger points (launch, after enroll/
    /// re-enroll), since either can change who owns the current
    /// `NETunnelProviderManager`.
    private func refreshManagerOwnership() {
        NetworkExtensionEnrollment.currentOwnership(providerBundleIdentifier: Self.networkExtensionIdentifier) { [weak self] ownership in
            DispatchQueue.main.async {
                self?.managerOwnership = ownership
                self?.rebuildMenu()
            }
        }
    }

    /// `NetworkExtensionStatusClient`'s completion is not guaranteed to
    /// fire on any particular queue (the underlying `NETunnelProviderManager`/
    /// `sendProviderMessage` APIs do not document one), so `render` is
    /// always dispatched to the main queue explicitly rather than assumed.
    private func refresh() {
        client.fetchExitManaged { [weak self] managed in
            DispatchQueue.main.async { self?.exitManaged = managed }
        }
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
        lastStatus = status
        guard let status, !status.interface.isEmpty else {
            statusItem.button?.image = Self.karstMarkIcon(.notRunning, accessibilityDescription: "karst: not running")
            statusItem.button?.title = "karst: not running"
            // `status` (not forced to `nil`): a reachable extension
            // answering "the engine is not running" carries a `refusal`
            // worth showing (#481) — only a genuine fetch failure has
            // nothing here at all.
            statusItem.menu = menu(for: status)
            return
        }

        let (markState, establishedCount) = Self.connectivitySummary(for: status.peers)
        let label: String
        if status.peers.isEmpty {
            label = "no peers configured"
        } else if establishedCount == 0 {
            label = "no peers"
        } else {
            label = "\(establishedCount) connected"
        }

        let rate = throughputRate(for: status.peers)
        statusItem.button?.image = Self.karstMarkIcon(markState, accessibilityDescription: label)
        statusItem.button?.title = "karst: \(label)\(rate)"
        statusItem.menu = menu(for: status)
    }

    /// This device's own connectivity, classified from every peer's state —
    /// the status bar icon/title's own classification, factored out so the
    /// menu's aggregate summary line (#207) computes the identical thing
    /// rather than a second, driftable copy of it.
    ///
    /// Transport (direct vs. relay/TURN) no longer affects this
    /// classification — the menu bar mark now only distinguishes "at least
    /// one peer established, or none configured to begin with" from "peers
    /// are configured but unreachable," dropping the separate relayed state
    /// the mark used to carry (per-peer transport is still in
    /// `PeerStatus.transport` for anything that wants it).
    ///
    /// No peers *configured* is not a failure — a lone device on the mesh
    /// is a perfectly normal topology, not "disconnected," so it reads as
    /// `.direct` too. Peers configured but none *established* is the real
    /// problem case and keeps the `.notRunning` look.
    private static func connectivitySummary(for peers: [PeerStatus]) -> (state: MarkState, established: Int) {
        guard !peers.isEmpty else { return (.direct, 0) }
        let established = peers.filter { $0.state.hasPrefix("established") }
        guard !established.isEmpty else { return (.notRunning, 0) }
        return (.direct, established.count)
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

    /// The three menu-bar states. Each names a bundled
    /// `Contents/Resources/menu-<state>.png` (`scripts/build-macos-pkg.sh`
    /// stages them — not a SwiftPM `resources:` entry, since
    /// `Bundle.module`'s lookup differs depending on whether this is
    /// running from inside an .app bundle or a bare `swift build` binary,
    /// and this way sidesteps that entirely). A code-drawn version of these
    /// (composited SF Symbols, then hand-built vector shapes) was tried and
    /// rejected on real hardware — neither read cleanly at menu bar size —
    /// so this is deliberately dumb: three flat image files, each a
    /// hand-designed asset rather than something this code generates.
    ///
    /// `.notRunning` doubles as "the tunnel is up but no peer is
    /// established" (`connectivitySummary`'s fallback) as well as its
    /// literal name — the dedicated no-peers mark was dropped, and from a
    /// glance at the menu bar, "connected to nothing" and "not running"
    /// look the same; the text next to it (`render`'s `label`) still tells
    /// them apart.
    private enum MarkState: String {
        case loading = "menu-loading"
        case notRunning = "menu-not-running"
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

    /// The top line shown when there is no running tunnel to report on —
    /// three different reasons (#481), not one hedge covering all of
    /// them: the extension itself could not be reached at all
    /// (`status == nil`), it answered but the engine/tunnel is not
    /// running (`status.refusal`), or it answered with something this
    /// app could not parse. Enrollment state is reported separately, by
    /// `addIdentityAndEnrollItems` below this line — it no longer needs
    /// to be hedged into this text at all.
    private static func notRunningMessage(status: DaemonStatus?) -> String {
        guard let status else {
            return "Karst's network extension could not be reached — try again from this menu"
        }
        return status.refusal.map { "Karst tunnel is not running: \($0)" } ?? "Karst tunnel is not running"
    }

    private func menu(for status: DaemonStatus?) -> NSMenu {
        let menu = NSMenu()
        SoftwareVersionMenu.addItems(to: menu, status: status)
        guard let status, !status.interface.isEmpty else {
            menu.addItem(withTitle: Self.notRunningMessage(status: status), action: nil, keyEquivalent: "")
            menu.addItem(NSMenuItem.separator())
            addIdentityAndEnrollItems(to: menu)
            menu.addItem(NSMenuItem.separator())
            menu.addItem(withTitle: "Quit", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
            return menu
        }

        menu.addItem(withTitle: "Interface: \(status.interface) (MTU \(status.mtu))", action: nil, keyEquivalent: "")
        menu.addItem(NSMenuItem.separator())
        menu.addItem(peerSummaryItem(for: status.peers))
        addExitNodeItem(to: menu, status: status)
        menu.addItem(NSMenuItem.separator())
        addIdentityAndEnrollItems(to: menu)
        menu.addItem(NSMenuItem.separator())
        menu.addItem(withTitle: "Quit", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        return menu
    }

    /// One aggregate line, not one item per peer (#207). An account can have
    /// hundreds of enrolled devices, all of them this node's WireGuard peers
    /// in Karst's full-mesh design — a menu-bar dropdown is not where that
    /// belongs, both because it does not scale and because it would show
    /// every peer's name and connection state to anyone at this Mac, not
    /// just an administrator. `web/console`'s machines view is the real
    /// per-device listing; this line answers only "is *this* device okay."
    private func peerSummaryItem(for peers: [PeerStatus]) -> NSMenuItem {
        guard !peers.isEmpty else {
            return NSMenuItem(title: "No peers configured", action: nil, keyEquivalent: "")
        }
        let (markState, establishedCount) = Self.connectivitySummary(for: peers)
        let title: String
        switch markState {
        case .notRunning:
            title = peers.count == 1 ? "1 peer configured, not connected" : "\(peers.count) peers configured, none connected"
        case .direct:
            title = establishedCount == peers.count
                ? "\(establishedCount) peers connected"
                : "\(establishedCount) of \(peers.count) peers connected"
        default:
            // Unreachable: connectivitySummary only ever returns .notRunning
            // or .direct — .loading exists only for the status bar icon
            // before a status has ever been fetched.
            title = "\(peers.count) peers configured"
        }
        let item = NSMenuItem(title: title, action: nil, keyEquivalent: "")
        item.image = Self.symbolImage(
            markState == .direct ? "circle.fill" : "circle",
            accessibilityDescription: title
        )
        return item
    }

    /// The Exit node submenu (ADR-0036 §3) — see `ExitNodeMenu`. Changing
    /// it needs an administrator — the extension verifies that itself —
    /// so any user sees the choice but only an administrator can make it.
    private func addExitNodeItem(to menu: NSMenu, status: DaemonStatus) {
        ExitNodeMenu.addItems(
            to: menu,
            status: status,
            exitManaged: exitManaged,
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
    /// withdraw consent. Not gated locally on a self-service install
    /// (ADR-0036 §3, revised); the extension itself still refuses this on a
    /// managed install (`managedExitAutoConsent`), where the menu item has
    /// no action in the first place.
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

    /// Always present, running or not: it is also how an already-enrolled
    /// device recovers from a config a resume path can't use, not only how
    /// first enrollment happens. See `IdentityMenu` for how `identityStatus`
    /// becomes the text and items shown here (#481).
    private func addIdentityAndEnrollItems(to menu: NSMenu) {
        IdentityMenu.addItems(
            to: menu,
            identity: identityStatus,
            managerOwnership: managerOwnership,
            target: self,
            enrollAction: #selector(runEnroll),
            reEnrollAction: #selector(runReEnroll)
        )
    }

    /// Fetches this device's identity handle over the same
    /// `sendProviderMessage` channel `refresh()` uses for status, and
    /// redraws the menu once it lands — see `IdentityStatus`'s own doc
    /// comment for why this is called explicitly rather than folded into
    /// the periodic poll.
    private func refreshIdentity() {
        client.fetchIdentityHandle { [weak self] result in
            guard let self else { return }
            DispatchQueue.main.async {
                switch result {
                case .success(let json):
                    self.identityStatus = Self.parseIdentity(json, previous: self.identityStatus)
                case .failure:
                    // A transport-level failure (extension unreachable, no
                    // manager configured, …), not a reply at all — kept as
                    // "stale"/"unknown" rather than treated as confirmed
                    // non-enrollment (#481): retrying enrollment is always
                    // safe, but offering it to an already-enrolled device
                    // on a guess is not harmless, it is misleading.
                    self.identityStatus = self.identityStatus.afterFailedCheck
                }
                self.rebuildMenu()
            }
        }
    }

    /// Parses `{"handle": "..."|null, "name": "..."|null}` — the
    /// confirmed shape `identity_handle`'s `Ok` arm produces — or
    /// `{"error": "..."}`, the shape its `Err` arm produces (a corrupt or
    /// unreadable identity file, not evidence of "not enrolled") —
    /// `PacketTunnelProvider.handleAppMessage`'s `"identity"` verb's own
    /// two response shapes (#481). `previous` is carried through on the
    /// error shape or on malformed JSON, for the same reason a transport
    /// failure carries it through in `refreshIdentity` above.
    private static func parseIdentity(_ json: String, previous: IdentityStatus) -> IdentityStatus {
        guard
            let data = json.data(using: .utf8),
            let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return previous.afterFailedCheck }
        if object["error"] is String {
            return previous.afterFailedCheck
        }
        guard let handle = object["handle"] as? String else {
            return .notEnrolled
        }
        return .enrolled(handle: handle, name: object["name"] as? String)
    }

    /// Redraws the menu from `lastStatus` without waiting for the next
    /// `refresh()` tick — `refreshIdentity()`'s own reason for existing:
    /// an operator who just finished pasting an invitation should see
    /// "Enrolled as …" appear immediately, not up to `pollInterval` later.
    private func rebuildMenu() {
        statusItem.menu = menu(for: lastStatus)
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
                        self.refreshIdentity()
                        self.refreshManagerOwnership()
                        self.showAlert(title: "Enrolled", message: "This device is now enrolled.")
                    }
                }
            }
        }
    }

    /// As `runEnroll`, but for a device `identityStatus` already shows as
    /// enrolled — the "Re-enroll…" item's action, going through
    /// `NetworkExtensionEnrollment.reEnroll` (the `"re-enroll"` verb,
    /// `reEnrollInvitation` on the Rust side) rather than `enroll`, which
    /// would refuse: this device's `config.toml` already exists.
    @objc private func runReEnroll() {
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
                NetworkExtensionEnrollment.reEnroll(invitation: invitation, manager: manager) { [weak self] result in
                    guard let self else { return }
                    switch result {
                    case .failure(let error):
                        self.showAlert(title: "Re-enrollment Failed", message: error.localizedDescription)
                    case .success:
                        self.refreshIdentity()
                        self.refreshManagerOwnership()
                        self.showAlert(title: "Re-enrolled", message: "This device is now enrolled under the new invitation.")
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
}
