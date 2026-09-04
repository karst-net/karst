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
}
