import Foundation
import NetworkExtension
import XCTest
@testable import KarstPacketTunnel

final class PacketTunnelRouteTests: XCTestCase {
    private func status(
        addresses: [String] = ["100.64.0.1/10"],
        allowedIPs: [[String]] = [],
        // Defaults every peer to established so the many existing tests
        // below, written before that field existed, keep meaning what they
        // already say: "this peer's allowed_ips are live routes." Only the
        // readiness-gate tests need to pass `false` explicitly.
        established: [Bool] = [],
        routes: [[String: Any]] = []
    ) throws -> String {
        let object: [String: Any] = [
            "addresses": addresses,
            "mtu": 1280,
            "peers": allowedIPs.enumerated().map { index, ips in
                ["allowed_ips": ips, "established": index < established.count ? established[index] : true]
            },
            "control": ["routing": ["routes": routes]],
        ]
        return String(data: try JSONSerialization.data(withJSONObject: object), encoding: .utf8)!
    }

    private func ipv4Routes(_ settings: NEPacketTunnelNetworkSettings) -> [String] {
        (settings.ipv4Settings?.includedRoutes ?? []).map {
            "\($0.destinationAddress)/\($0.destinationSubnetMask)"
        }.sorted()
    }

    private func ipv6Routes(_ settings: NEPacketTunnelNetworkSettings) -> [String] {
        (settings.ipv6Settings?.includedRoutes ?? []).map {
            "\($0.destinationAddress)/\($0.destinationNetworkPrefixLength)"
        }.sorted()
    }

    func testPeerRoutesAndActiveRecipientExitRoutesBecomeTunnelRoutes() throws {
        let settings = try PacketTunnelProvider.networkSettings(fromStatusJSON: status(
            addresses: ["100.64.0.1/10", "fd00::1/64"],
            allowedIPs: [["100.64.0.0/10", "fd00::/64"]],
            routes: [
                ["prefix": "0.0.0.0/0", "kind": "exit", "role": "recipient", "active": true],
                ["prefix": "::/0", "kind": "exit", "role": "recipient", "active": true],
                ["prefix": "198.51.100.0/24", "kind": "exit", "role": "gateway", "active": true],
                ["prefix": "203.0.113.0/24", "kind": "exit", "role": "recipient", "active": false],
            ]
        ))

        XCTAssertEqual(settings.tunnelRemoteAddress, "100.64.0.1")
        XCTAssertEqual(settings.mtu?.intValue, 1280)
        XCTAssertEqual(
            ipv4Routes(settings),
            ["0.0.0.0/0.0.0.0", "100.64.0.0/255.192.0.0"]
        )
        XCTAssertEqual(ipv6Routes(settings), ["::/0", "fd00::/64"])
    }

    /// Found on the lab hardware: an exit offer's default prefix appears in
    /// the gateway peer's `allowed_ips` before any consent. Mapped into an
    /// included route it captured the Mac's default route and black-holed
    /// its internet. Only an *active* recipient exit may add one.
    func testUnconsentedExitOfferInAllowedIPsDoesNotCaptureTheDefaultRoute() throws {
        let offered = try status(
            addresses: ["100.64.0.1/10", "fd00::1/64"],
            allowedIPs: [["100.64.0.2/32", "10.203.0.0/24", "0.0.0.0/0", "::/0"]],
            routes: [
                ["prefix": "0.0.0.0/0", "kind": "exit", "role": "recipient", "active": false],
                ["prefix": "::/0", "kind": "exit", "role": "recipient", "active": false],
            ]
        )
        let settings = try PacketTunnelProvider.networkSettings(fromStatusJSON: offered)

        XCTAssertEqual(
            ipv4Routes(settings),
            ["10.203.0.0/255.255.255.0", "100.64.0.2/255.255.255.255"]
        )
        XCTAssertEqual(ipv6Routes(settings), [])

        let withoutOffer = try status(
            addresses: ["100.64.0.1/10", "fd00::1/64"],
            allowedIPs: [["100.64.0.2/32", "10.203.0.0/24"]]
        )
        XCTAssertEqual(
            PacketTunnelProvider.routeSignature(fromStatusJSON: offered),
            PacketTunnelProvider.routeSignature(fromStatusJSON: withoutOffer)
        )
    }

    /// Diagnosed on real hardware: a client whose exit peer's session never
    /// finished negotiating (a dead relay, in the real case) still got
    /// `active == true` from `exit-node use` — that field means *selected*,
    /// not *working*. Mapped into `includedRoutes` anyway, it would have
    /// captured 100% of the Mac's traffic into a tunnel with no live
    /// session behind it. Only an active recipient exit route backed by an
    /// *established* peer may add one.
    func testAnActiveExitRouteWithNoEstablishedPeerDoesNotCaptureTheDefaultRoute() throws {
        let notYetConnected = try status(
            addresses: ["100.64.0.1/10"],
            allowedIPs: [["100.64.0.2/32", "0.0.0.0/0"]],
            established: [false],
            routes: [["prefix": "0.0.0.0/0", "kind": "exit", "role": "recipient", "active": true]]
        )
        let settings = try PacketTunnelProvider.networkSettings(fromStatusJSON: notYetConnected)
        XCTAssertEqual(ipv4Routes(settings), ["100.64.0.2/255.255.255.255"])

        let connected = try status(
            addresses: ["100.64.0.1/10"],
            allowedIPs: [["100.64.0.2/32", "0.0.0.0/0"]],
            established: [true],
            routes: [["prefix": "0.0.0.0/0", "kind": "exit", "role": "recipient", "active": true]]
        )
        let settingsOnceConnected = try PacketTunnelProvider.networkSettings(fromStatusJSON: connected)
        XCTAssertEqual(
            ipv4Routes(settingsOnceConnected),
            ["0.0.0.0/0.0.0.0", "100.64.0.2/255.255.255.255"]
        )

        // The signature must itself change across that transition, or
        // `pollHealth()` would never recompute settings once the peer
        // actually connects — see `routeSignature`'s own doc comment.
        XCTAssertNotEqual(
            PacketTunnelProvider.routeSignature(fromStatusJSON: notYetConnected),
            PacketTunnelProvider.routeSignature(fromStatusJSON: connected)
        )
    }

    func testRouteSignatureIgnoresOrderButChangesOnWithdrawal() throws {
        let active = try status(
            addresses: ["fd00::1/64", "100.64.0.1/10"],
            allowedIPs: [["fd00::/64", "100.64.0.0/10"]],
            routes: [["prefix": "0.0.0.0/0", "kind": "exit", "role": "recipient", "active": true]]
        )
        let reordered = try status(
            addresses: ["100.64.0.1/10", "fd00::1/64"],
            allowedIPs: [["100.64.0.0/10", "fd00::/64"]],
            routes: [["prefix": "0.0.0.0/0", "kind": "exit", "role": "recipient", "active": true]]
        )
        let withdrawn = try status(
            addresses: ["100.64.0.1/10", "fd00::1/64"],
            allowedIPs: [["100.64.0.0/10", "fd00::/64"]],
            routes: [["prefix": "0.0.0.0/0", "kind": "exit", "role": "recipient", "active": false]]
        )

        XCTAssertEqual(
            PacketTunnelProvider.routeSignature(fromStatusJSON: active),
            PacketTunnelProvider.routeSignature(fromStatusJSON: reordered)
        )
        XCTAssertNotEqual(
            PacketTunnelProvider.routeSignature(fromStatusJSON: active),
            PacketTunnelProvider.routeSignature(fromStatusJSON: withdrawn)
        )
    }

    func testMalformedPrefixesAreRejectedWithoutConstructingRoutes() throws {
        XCTAssertNil(PacketTunnelProvider.splitCIDR("100.64.0.0/33"))
        XCTAssertNil(PacketTunnelProvider.splitCIDR("fd00::/129"))
        XCTAssertNil(PacketTunnelProvider.splitCIDR("100.64.0.0/nope"))

        let settings = try PacketTunnelProvider.networkSettings(fromStatusJSON: status(
            allowedIPs: [["100.64.0.0/33", "fd00::/129", "100.64.0.0/10"]]
        ))
        XCTAssertEqual(ipv4Routes(settings), ["100.64.0.0/255.192.0.0"])
        XCTAssertTrue(ipv6Routes(settings).isEmpty)
    }
}
