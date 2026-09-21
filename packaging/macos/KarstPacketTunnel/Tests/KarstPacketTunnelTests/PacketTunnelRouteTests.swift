import Foundation
import NetworkExtension
import XCTest
@testable import KarstPacketTunnel

final class PacketTunnelRouteTests: XCTestCase {
    private func status(
        addresses: [String] = ["100.64.0.1/10"],
        allowedIPs: [[String]] = [],
        routes: [[String: Any]] = []
    ) throws -> String {
        let object: [String: Any] = [
            "addresses": addresses,
            "mtu": 1280,
            "peers": allowedIPs.map { ["allowed_ips": $0] },
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
