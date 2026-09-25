// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

// CI-only integration driver for a *packaged* Karst Network Extension.
//
// This target is intentionally absent from build-macos-pkg.sh. It accepts a
// short-lived invitation only from a root-owned CI file, sends it through the
// same NETunnelProviderSession app-message interface Karst.app uses, waits for
// an established peer, and fetches a known-size HTTP response through the
// overlay. It needs a physical, pre-approved macOS runner; it is not useful on
// GitHub-hosted macOS VMs, which cannot prove System Extension packet flow.

import Foundation
import NetworkExtension
import Darwin
import Network

private let defaultProviderBundleIdentifier = "dev.karst.packettunnel"

private struct Arguments {
    let invitationFile: URL
    let probeURL: URL
    let udpHost: String
    let udpPort: UInt16
    let providerBundleIdentifier: String
    let expectedTransport: String?
    let expectedRoute: String?
    let expectedRouteState: Bool
    let timeout: TimeInterval

    init() throws {
        var invitationPath: String?
        var probeURLText: String?
        var udpHost: String?
        var udpPort: UInt16?
        var providerBundleIdentifier = defaultProviderBundleIdentifier
        var expectedTransport: String?
        var expectedRoute: String?
        var expectedRouteState = true
        var timeout: TimeInterval = 90
        var iterator = Array(CommandLine.arguments.dropFirst()).makeIterator()
        while let argument = iterator.next() {
            switch argument {
            case "--invitation-file": invitationPath = iterator.next()
            case "--probe-url": probeURLText = iterator.next()
            case "--udp-host": udpHost = iterator.next()
            case "--udp-port": udpPort = UInt16(iterator.next() ?? "")
            case "--provider-bundle-id": providerBundleIdentifier = iterator.next() ?? providerBundleIdentifier
            case "--expect-transport": expectedTransport = iterator.next()
            case "--expect-route": expectedRoute = iterator.next()
            case "--expect-route-state":
                switch iterator.next() {
                case "present": expectedRouteState = true
                case "absent": expectedRouteState = false
                default: throw Failure("--expect-route-state must be present or absent")
                }
            case "--timeout": timeout = TimeInterval(iterator.next() ?? "") ?? timeout
            default: throw Failure("unknown argument \(argument)")
            }
        }
        guard let invitationPath, let probeURLText, let probeURL = URL(string: probeURLText),
              let udpHost, let udpPort else {
            throw Failure("usage: KarstConnectivityCI --invitation-file PATH --probe-url URL --udp-host HOST --udp-port PORT [--expect-transport direct|relay] [--timeout SECONDS]")
        }
        guard timeout > 0 else { throw Failure("--timeout must be positive") }
        guard expectedTransport == nil || ["direct", "relay"].contains(expectedTransport) else {
            throw Failure("--expect-transport must be direct or relay")
        }
        guard expectedRoute == nil || expectedRoute!.contains("/") else {
            throw Failure("--expect-route must be a CIDR")
        }
        self.invitationFile = URL(fileURLWithPath: invitationPath)
        self.probeURL = probeURL
        self.udpHost = udpHost
        self.udpPort = udpPort
        self.providerBundleIdentifier = providerBundleIdentifier
        self.expectedTransport = expectedTransport
        self.expectedRoute = expectedRoute
        self.expectedRouteState = expectedRouteState
        self.timeout = timeout
    }
}

private struct Failure: Error, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
}

private func wait<T>(_ timeout: TimeInterval, _ start: (@escaping (Result<T, Error>) -> Void) -> Void) throws -> T {
    let semaphore = DispatchSemaphore(value: 0)
    var result: Result<T, Error>?
    start {
        result = $0
        semaphore.signal()
    }
    guard semaphore.wait(timeout: .now() + timeout) == .success else {
        throw Failure("operation timed out")
    }
    return try result!.get()
}

private func manager(providerBundleIdentifier: String, deadline: Date) throws -> NETunnelProviderManager {
    while Date() < deadline {
        let loaded: [NETunnelProviderManager] = try wait(10) { completion in
            NETunnelProviderManager.loadAllFromPreferences { managers, error in
                if let error { completion(.failure(error)) }
                else { completion(.success(managers ?? [])) }
            }
        }
        if let manager = loaded.first(where: {
            ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == providerBundleIdentifier
        }) {
            return manager
        }
        Thread.sleep(forTimeInterval: 1)
    }
    throw Failure("Karst VPN configuration did not appear; launch Karst.app and approve its System Extension first")
}

private func providerMessage(_ session: NETunnelProviderSession, _ object: [String: Any], timeout: TimeInterval) throws -> [String: Any] {
    let request = try JSONSerialization.data(withJSONObject: object)
    let response: Data = try wait(timeout) { completion in
        do {
            try session.sendProviderMessage(request) { data in
                guard let data else {
                    completion(.failure(Failure("network extension returned no response")))
                    return
                }
                completion(.success(data))
            }
        } catch {
            completion(.failure(error))
        }
    }
    let json = try JSONSerialization.jsonObject(with: response)
    guard let object = json as? [String: Any] else {
        throw Failure("network extension returned a non-object response")
    }
    if let error = object["error"] as? String { throw Failure("network extension refused request: \(error)") }
    return object
}

private func waitForEstablishedPeer(
    _ session: NETunnelProviderSession,
    expectedTransport: String?,
    deadline: Date
) throws -> [String: Any] {
    while Date() < deadline {
        let status = try providerMessage(session, ["verb": "status"], timeout: 10)
        let peers = status["peers"] as? [[String: Any]] ?? []
        let matchingPeer = peers.contains { peer in
            peer["established"] as? Bool == true
                && (expectedTransport == nil || peer["transport"] as? String == expectedTransport)
        }
        if !((status["interface"] as? String) ?? "").isEmpty, matchingPeer {
            return status
        }
        Thread.sleep(forTimeInterval: 1)
    }
    let description = expectedTransport.map { " established \($0) peer" } ?? " established peer"
    throw Failure("no\(description) before timeout")
}

/// Wait for the engine to report a route offer in the requested state. The
/// route list is the same live `statusJson` body the provider turns into
/// `NEPacketTunnelNetworkSettings`; this check intentionally does not enroll,
/// restart, or otherwise perturb the already-running tunnel between a lab
/// control-plane mutation and the subsequent application traffic probe.
private func waitForRoute(
    _ session: NETunnelProviderSession,
    route: String,
    expectedPresent: Bool,
    deadline: Date
) throws {
    while Date() < deadline {
        let status = try providerMessage(session, ["verb": "status"], timeout: 10)
        let routes = (((status["control"] as? [String: Any])?["routing"] as? [String: Any])?["routes"] as? [[String: Any]]) ?? []
        let present = routes.contains { candidate in
            candidate["prefix"] as? String == route && candidate["active"] as? Bool == true
        }
        if present == expectedPresent { return }
        Thread.sleep(forTimeInterval: 1)
    }
    let state = expectedPresent ? "active" : "withdrawn"
    throw Failure("route \(route) was not \(state) before timeout")
}

private func fetchProbe(_ url: URL, timeout: TimeInterval) throws -> Int {
    let configuration = URLSessionConfiguration.ephemeral
    configuration.timeoutIntervalForRequest = timeout
    // This test must exercise the overlay route itself. Inheriting a runner's
    // corporate HTTP proxy could make an otherwise broken tunnel appear to
    // pass by sending the request somewhere other than the overlay peer.
    configuration.connectionProxyDictionary = [:]
    let session = URLSession(configuration: configuration)
    let result: (Data, URLResponse) = try wait(timeout + 5) { completion in
        session.dataTask(with: url) { data, response, error in
            if let error { completion(.failure(error)) }
            else if let data, let response { completion(.success((data, response))) }
            else { completion(.failure(Failure("probe returned no data"))) }
        }.resume()
    }
    guard let http = result.1 as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
        throw Failure("overlay HTTP probe returned a non-success status")
    }
    // A non-trivial body prevents a test from passing on a single TCP SYN/ACK.
    guard result.0.count >= 65_536 else {
        throw Failure("overlay HTTP probe returned \(result.0.count) bytes; expected at least 65536")
    }
    return result.0.count
}

private func probeUDP(host: String, port: UInt16, timeout: TimeInterval) throws -> Int {
    guard let endpointPort = NWEndpoint.Port(rawValue: port) else {
        throw Failure("invalid UDP port")
    }
    let connection = NWConnection(host: NWEndpoint.Host(host), port: endpointPort, using: .udp)
    let queue = DispatchQueue(label: "dev.karst.connectivity-ci.udp")
    let ready: Void = try wait(timeout) { completion in
        connection.stateUpdateHandler = { state in
            switch state {
            case .ready: completion(.success(()))
            case .failed(let error): completion(.failure(error))
            default: break
            }
        }
        connection.start(queue: queue)
    }
    _ = ready
    let payload = Data("karst-network-extension-udp-probe".utf8)
    let reply: Data = try wait(timeout) { completion in
        connection.send(content: payload, completion: .contentProcessed { error in
            if let error {
                completion(.failure(error))
                return
            }
            connection.receiveMessage { data, _, _, error in
                if let error { completion(.failure(error)) }
                else if let data { completion(.success(data)) }
                else { completion(.failure(Failure("UDP echo returned no data"))) }
            }
        })
    }
    connection.cancel()
    guard reply == payload else { throw Failure("UDP echo response did not match the probe") }
    return reply.count
}

do {
    let arguments = try Arguments()
    let invitation = try String(contentsOf: arguments.invitationFile, encoding: .utf8)
    guard invitation.hasPrefix("karst-invite-v1:") else { throw Failure("invitation file does not contain a Karst invitation") }
    let deadline = Date().addingTimeInterval(arguments.timeout)
    let vpnManager = try manager(providerBundleIdentifier: arguments.providerBundleIdentifier, deadline: deadline)
    guard let session = vpnManager.connection as? NETunnelProviderSession else {
        throw Failure("Karst configuration does not expose an NETunnelProviderSession")
    }
    if let expectedRoute = arguments.expectedRoute {
        try waitForRoute(
            session,
            route: expectedRoute,
            expectedPresent: arguments.expectedRouteState,
            deadline: deadline
        )
        let state = arguments.expectedRouteState ? "present" : "absent"
        print("{\"result\":\"ok\",\"route\":\"\(expectedRoute)\",\"route_state\":\"\(state)\"}")
        exit(0)
    }
    // "re-enroll", not "enroll": every lab run brings a fresh invitation to
    // a Mac that may still hold the previous run's identity, and "enroll"
    // refuses an existing configuration. On a fresh device the two verbs
    // behave identically (enrollment.rs's re_enroll_invitation).
    _ = try providerMessage(session, ["verb": "re-enroll", "invitation": invitation], timeout: arguments.timeout)
    switch session.status {
    case .connected, .connecting, .reasserting:
        break
    default:
        try session.startVPNTunnel()
    }
    let status = try waitForEstablishedPeer(
        session,
        expectedTransport: arguments.expectedTransport,
        deadline: deadline
    )
    let bytes = try fetchProbe(arguments.probeURL, timeout: min(30, arguments.timeout))
    let udpBytes = try probeUDP(host: arguments.udpHost, port: arguments.udpPort, timeout: min(30, arguments.timeout))
    let peerCount = (status["peers"] as? [[String: Any]] ?? []).count
    let expectedTransport = arguments.expectedTransport.map { "\"\($0)\"" } ?? "null"
    print("{\"result\":\"ok\",\"expected_transport\":\(expectedTransport),\"established_peers\":\(peerCount),\"tcp_probe_bytes\":\(bytes),\"udp_probe_bytes\":\(udpBytes)}")
} catch {
    fputs("KarstConnectivityCI: \(error)\n", stderr)
    exit(1)
}
