// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.
//
// A trimmed copy of packaging/macos/KarstStatus/Sources/KarstStatus/
// StatusParser.swift: `exitOffers`/`selectedExit` and their parsing are
// dropped — this target's minimal-viable scope has no exit-node menu (see
// AppDelegate.swift's own header comment) — everything else is identical,
// since the underlying status-json shape this reads is unchanged by which
// NetworkExtension packaging produced it.

import Foundation

/// One peer entry from `status_json`'s `peers` array.
struct PeerStatus {
    var name = ""
    var hint = ""
    var endpoint = "-"
    var state = "connecting"
    var pskFallback = false
    var transport = "none"
    var txBytes: UInt64 = 0
    var rxBytes: UInt64 = 0
}

/// Everything from one `status_json`-shaped reply that this app reads.
struct DaemonStatus {
    var interface = ""
    var mtu = 0
    var peers: [PeerStatus] = []
    var refusal: String?
}

/// Parses `status_json`'s body — the same JSON
/// `PacketTunnelProvider.handleAppMessage`'s `"status"` verb answers with.
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
            peer.txBytes = (peerObject["tx_bytes"] as? NSNumber)?.uint64Value ?? 0
            peer.rxBytes = (peerObject["rx_bytes"] as? NSNumber)?.uint64Value ?? 0

            let established = peerObject["established"] as? Bool ?? false
            let rekeying = peerObject["rekeying"] as? Bool ?? false
            peer.state = !established ? "connecting" : (rekeying ? "established (rekeying)" : "established")

            status.peers.append(peer)
        }
        return status
    }
}
