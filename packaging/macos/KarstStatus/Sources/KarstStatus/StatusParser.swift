// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

import Foundation

/// One peer entry from `status_json`'s `peers` array.
///
/// Field names and shapes mirror `PeerStatus`
/// (`bins/karstd/src/engine.rs`) and its JSON form in `run.rs`'s
/// `PeerJson` deliberately, not coincidentally — this struct exists to stay
/// a mechanical translation of that output, not to reinterpret it.
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

/// Everything from one `status_json`-shaped reply that this app reads.
///
/// Deliberately not a full model of the format: `portmap`, `stats` and
/// `policy` all appear in the real JSON and are ignored, not parsed into
/// anything, because nothing here shows them yet. Add fields as the UI grows
/// rather than up front.
struct DaemonStatus {
    var interface = ""
    var mtu = 0
    var peers: [PeerStatus] = []
    /// Set when the extension answered but refused the request — the
    /// `{"error": "..."}` shape `status_json`'s own `Serialize`-failure
    /// fallback uses, and the same shape `PacketTunnelProvider.handleAppMessage`
    /// falls back to when the tunnel is not running at all (`engine == nil`)
    /// — the far more common way this actually gets set in practice, since
    /// enrollment alone does not start the tunnel.
    var refusal: String?
}

/// Parses `karst status --json`'s body (`ipc::Command::StatusJson`,
/// `bins/karstd/src/run.rs`'s `status_json`) — the same JSON
/// `PacketTunnelProvider.handleAppMessage`'s `"status"` verb answers with
/// on the NetworkExtension build, which is what `NetworkExtensionStatusClient`
/// actually calls this on. Verified end to end on real hardware (#159), not
/// just reviewed against the Rust `Serialize` impl — a text/TOML-ish parser
/// for the LaunchDaemon build's now-removed status socket protocol used to
/// live here too; dropped once NetworkExtension became the sole macOS
/// backend and nothing called it anymore.
enum StatusParser {
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
