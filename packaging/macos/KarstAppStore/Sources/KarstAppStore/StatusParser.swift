// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.
//
// A copy of packaging/macos/KarstStatus/Sources/KarstStatus/StatusParser.swift
// — including `exitOffers`/`selectedExit`/`controlSynchronized` and their
// parsing (#499) — since the underlying status-json shape this reads is
// unchanged by which NetworkExtension packaging produced it.

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
    // These identify the responding agent, independently of the app bundle.
    // Older agents omit these fields; never substitute the app's version.
    var version = "Unknown"
    var revision = "Unknown"
    var interface = ""
    var mtu = 0
    var peers: [PeerStatus] = []
    var refusal: String?
    /// Exit routes offered to this device as a recipient, from
    /// `control.routing.routes` (ADR-0036's Exit node menu).
    var exitOffers: [ExitOffer] = []
    /// The route ID the local user has consented to, if any
    /// (`control.routing.selected_exit`) — kept even while that offer is
    /// withdrawn, which is how consent stays dormant.
    var selectedExit: String?
    /// Whether the control-plane sync that actually populates `exitOffers`
    /// has completed at least once since start — `control.control_synchronized`.
    /// `true` when the field is absent, so neither reads as "stale" on a guess.
    var controlSynchronized = true
}

/// One exit route offered to this device.
struct ExitOffer: Equatable {
    var routeID = ""
    var prefix = ""
    /// Whether this device currently routes through it (consented and
    /// installed).
    var active = false
    /// The gateway peer's name, when one of this device's peers carries the
    /// offer's prefix in its allowed IPs; nil if none does yet.
    var gatewayName: String?
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

        if let version = object["version"] as? String, !version.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            status.version = version
        }
        if let revision = object["revision"] as? String, !revision.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            status.revision = revision
        }
        status.interface = object["interface"] as? String ?? ""
        status.mtu = object["mtu"] as? Int ?? 0

        // An exit offer's gateway is the peer whose allowed IPs carry the
        // offer's prefix (karstd routes it there before any consent).
        var gatewayByPrefix: [String: String] = [:]
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
            let allowed = peerObject["allowed_ips"] as? [String] ?? []
            for prefix in allowed where gatewayByPrefix[prefix] == nil {
                gatewayByPrefix[prefix] = peer.name
            }
        }

        let control = object["control"] as? [String: Any]
        status.controlSynchronized = control?["control_synchronized"] as? Bool ?? true
        let routing = control?["routing"] as? [String: Any]
        status.selectedExit = routing?["selected_exit"] as? String
        for case let route as [String: Any] in routing?["routes"] as? [Any] ?? [] {
            guard route["kind"] as? String == "exit", route["role"] as? String == "recipient" else { continue }
            var offer = ExitOffer()
            offer.routeID = route["route_id"] as? String ?? ""
            offer.prefix = route["prefix"] as? String ?? ""
            offer.active = route["active"] as? Bool ?? false
            offer.gatewayName = gatewayByPrefix[offer.prefix]
            if !offer.routeID.isEmpty {
                status.exitOffers.append(offer)
            }
        }
        return status
    }
}
