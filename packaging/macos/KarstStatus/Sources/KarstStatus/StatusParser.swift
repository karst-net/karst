// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

import Foundation

/// One `[[peer]]` table from `karstd`'s status text.
///
/// Field names and shapes mirror `PeerStatus`
/// (`bins/karstd/src/engine.rs`) and its rendering in `run.rs`'s `report`
/// deliberately, not coincidentally — this struct exists to stay a mechanical
/// translation of that output, not to reinterpret it.
struct PeerStatus {
    var name = ""
    var hint = ""
    var endpoint = "-"
    /// One of `"connecting"`, `"established"`, `"established (rekeying)"` —
    /// `run.rs`'s `state` line, not re-derived from `established`/`rekeying`
    /// separately.
    var state = "connecting"
    var pskFallback = false
    /// `"direct"`, `"relay"`, `"turn"`, or `"none"` — `Transport`'s
    /// `Display` impl (`engine.rs`), verbatim.
    var transport = "none"
    /// Cumulative, not a rate — `PeerStatus::tx_bytes`'s own doc comment.
    /// `AppDelegate` differences successive polls.
    var txBytes: UInt64 = 0
    var rxBytes: UInt64 = 0
}

/// Everything from one `karst status`-shaped reply that this app reads.
///
/// Deliberately not a full model of the format: `[portmap]`, `[stats]` and
/// `[policy]` all appear in the real text and are parsed past, not into
/// anything, because nothing here shows them yet. Add fields as the UI grows
/// rather than up front.
struct DaemonStatus {
    var interface = ""
    var mtu = 0
    var peers: [PeerStatus] = []
    /// Set when the daemon answered but refused the request — the
    /// unprivileged socket's answer to anything but `status`
    /// (`ipc.rs`'s module note). Should never actually appear here, since
    /// this client only ever sends `status`; kept as a visible signal rather
    /// than a silently empty `DaemonStatus` in case it ever does.
    var refusal: String?
}

/// A hand-written line parser for `karstd`'s status output, not a TOML
/// library.
///
/// The format is intentionally simple — `writeln!`-built, one `key = value`
/// per line, blank-line-separated `[section]`/`[[peer]]` headers, and never
/// nested more than one level (`run.rs`'s `report` function is the producer
/// and the ground truth) — so a general TOML parser would be a dependency
/// bought for generality this client does not need. If `karstd`'s output
/// format ever grows real nesting or multi-line values, this needs to grow
/// with it or be replaced; it is not meant to be a permanent bet against
/// TOML.
enum StatusParser {
    static func parse(_ text: String) -> DaemonStatus {
        var status = DaemonStatus()
        var current: PeerStatus?
        var inPeerTable = false

        func closeCurrentPeer() {
            if let peer = current {
                status.peers.append(peer)
            }
            current = nil
        }

        for rawLine in text.split(separator: "\n", omittingEmptySubsequences: false) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.isEmpty { continue }

            if line == "[[peer]]" {
                closeCurrentPeer()
                current = PeerStatus()
                inPeerTable = true
                continue
            }
            if line.hasPrefix("[") {
                // Any other section header ends the peer table currently
                // being built, if there is one — peers are the last thing in
                // the real output, but nothing here assumes that ordering.
                closeCurrentPeer()
                inPeerTable = false
                continue
            }
            guard let eq = line.firstIndex(of: "=") else { continue }
            let key = line[line.startIndex..<eq].trimmingCharacters(in: .whitespaces)
            var value = String(line[line.index(after: eq)...]).trimmingCharacters(in: .whitespaces)
            if value.hasPrefix("\""), value.hasSuffix("\""), value.count >= 2 {
                value = String(value.dropFirst().dropLast())
            }

            if key == "error" {
                status.refusal = value
                continue
            }

            if inPeerTable {
                switch key {
                case "name": current?.name = value
                case "hint": current?.hint = value
                case "endpoint": current?.endpoint = value
                case "state": current?.state = value
                case "psk_fallback": current?.pskFallback = (value == "true")
                case "transport": current?.transport = value
                case "tx_bytes": current?.txBytes = UInt64(value) ?? 0
                case "rx_bytes": current?.rxBytes = UInt64(value) ?? 0
                default: break
                }
            } else {
                switch key {
                case "interface": status.interface = value
                case "mtu": status.mtu = Int(value) ?? 0
                default: break
                }
            }
        }
        closeCurrentPeer()
        return status
    }

    /// As `parse(_:)`, for `karst status --json`'s body
    /// (`ipc::Command::StatusJson`, `run.rs`'s `status_json`) instead of the
    /// TOML-ish text form — docs/adr/0027-macos-system-extension-host-app-ipc.md,
    /// which is why this exists at all: the NetworkExtension build's
    /// `handleAppMessage` answers with this JSON body, not the text one, so
    /// `NetworkExtensionStatusClient` needs a parser for it. Deliberately
    /// produces the *same* `DaemonStatus`/`PeerStatus` this file already
    /// has, so `AppDelegate`'s rendering code does not need to know which
    /// transport supplied the value — only `NetworkExtensionStatusClient`
    /// versus `StatusClient` differ.
    ///
    /// **Unverified beyond visual review against the Rust `Serialize` impl
    /// (`bins/karstd/src/run.rs`'s `StatusJson`/`PeerJson` structs) — there is
    /// no NetworkExtension build to run this against yet.** Same posture
    /// this package's Swift shipped under originally
    /// (plans/phase-6/13-macos-status-indicators.md): reviewed line by line,
    /// not run.
    static func parseJSON(_ text: String) -> DaemonStatus {
        var status = DaemonStatus()
        guard
            let data = text.data(using: .utf8),
            let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else {
            status.refusal = "malformed status-json reply: not a JSON object"
            return status
        }

        // `status_json`'s own fallback path emits `{"error": "..."}` on a
        // `Serialize` failure; the unprivileged status socket's refusal for
        // any command but `status`/`status-json` is the same shape in
        // spirit as the text form's `error = "..."` line — one field to
        // check either way.
        if let error = object["error"] as? String {
            status.refusal = error
            return status
        }

        status.interface = object["interface"] as? String ?? ""
        status.mtu = object["mtu"] as? Int ?? 0

        for case let peerObject as [String: Any] in object["peers"] as? [Any] ?? [] {
            var peer = PeerStatus()
            peer.name = peerObject["name"] as? String ?? ""
            peer.hint = peerObject["hint"] as? String ?? ""
            peer.endpoint = peerObject["endpoint"] as? String ?? "-"
            peer.pskFallback = peerObject["psk_fallback"] as? Bool ?? false
            peer.transport = peerObject["transport"] as? String ?? "none"
            // JSON numbers decode as `NSNumber` through `Any`; `uint64Value`
            // rather than `as? UInt64`, which fails on every plain JSON
            // integer literal because `JSONSerialization` never hands back
            // that exact Swift type.
            peer.txBytes = (peerObject["tx_bytes"] as? NSNumber)?.uint64Value ?? 0
            peer.rxBytes = (peerObject["rx_bytes"] as? NSNumber)?.uint64Value ?? 0

            // `status_json`'s `PeerJson` carries `established`/`rekeying`
            // booleans rather than the text form's pre-rendered `state`
            // string — rebuilt here to the identical three values `run.rs`'s
            // `report` writes, so `AppDelegate`'s `stateSymbolName(for:)`
            // (which matches on `state.hasPrefix("established")`) needs no
            // changes to read either transport's result.
            let established = peerObject["established"] as? Bool ?? false
            let rekeying = peerObject["rekeying"] as? Bool ?? false
            peer.state = !established ? "connecting" : (rekeying ? "established (rekeying)" : "established")

            status.peers.append(peer)
        }
        return status
    }
}
