// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

// CI-only integration driver for a *packaged* Karst Network Extension.
//
// This target is intentionally absent from build-macos-pkg.sh. It runs as
// root on the lab runner: it hands a short-lived invitation to the provider
// as the root-only pending-invitation file `startTunnel` enrolls from, starts
// the saved Karst configuration with scutil, reads the embedded engine's live
// status from its root-only admin socket, and then pushes a known-size HTTP
// response and a UDP echo through the overlay. It needs a physical,
// pre-approved macOS runner; it is not useful on GitHub-hosted macOS VMs,
// which cannot prove System Extension packet flow.
//
// Why not NETunnelProviderSession.sendProviderMessage, as Karst.app does:
// macOS delivers provider messages only from the configuration's owning app
// (dev.karst.karststatus). Found on real hardware — messages from this
// separate binary are dropped without an error, so the harness only ever
// timed out.

import Foundation
import Darwin
import Network

private let stateDirectory = "/Library/Application Support/dev.karst.packettunnel"
private let controlSocketPath = "\(stateDirectory)/control.sock"
private let pendingInvitationPath = "\(stateDirectory)/pending-invitation"

private struct Arguments {
    let invitationFile: URL
    let probeURL: URL
    let udpHost: String
    let udpPort: UInt16
    let serviceName: String
    let expectedTransport: String?
    let expectedRoute: String?
    let expectedRouteState: Bool
    let timeout: TimeInterval

    init() throws {
        var invitationPath: String?
        var probeURLText: String?
        var udpHost: String?
        var udpPort: UInt16?
        var serviceName = "Karst"
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
            case "--service-name": serviceName = iterator.next() ?? serviceName
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
        self.serviceName = serviceName
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

/// The engine's live status — the same `status-json` body the provider turns
/// into `NEPacketTunnelNetworkSettings` — read from its root-only admin socket.
/// `nil` while the tunnel (and so the engine) is not running.
private func engineStatus() -> [String: Any]? {
    let fd = socket(AF_UNIX, SOCK_STREAM, 0)
    guard fd >= 0 else { return nil }
    defer { close(fd) }
    var address = sockaddr_un()
    address.sun_family = sa_family_t(AF_UNIX)
    let capacity = MemoryLayout.size(ofValue: address.sun_path)
    guard controlSocketPath.utf8.count < capacity else { return nil }
    withUnsafeMutablePointer(to: &address.sun_path) {
        $0.withMemoryRebound(to: CChar.self, capacity: capacity) { _ = strcpy($0, controlSocketPath) }
    }
    let connected = withUnsafePointer(to: &address) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
        }
    }
    guard connected == 0 else { return nil }
    let request = Array("status-json\n".utf8)
    guard write(fd, request, request.count) == request.count else { return nil }
    shutdown(fd, SHUT_WR)
    var response = Data()
    var buffer = [UInt8](repeating: 0, count: 65_536)
    while true {
        let n = read(fd, &buffer, buffer.count)
        if n <= 0 { break }
        response.append(contentsOf: buffer[0..<n])
    }
    return (try? JSONSerialization.jsonObject(with: response)) as? [String: Any]
}

/// `scutil --nc <verb> <service>`: starting and stopping a saved VPN
/// configuration needs no ownership of it, unlike provider messages.
@discardableResult
private func networkConnection(_ verb: String, _ serviceName: String) throws -> String {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/sbin/scutil")
    process.arguments = ["--nc", verb, serviceName]
    let pipe = Pipe()
    process.standardOutput = pipe
    process.standardError = pipe
    try process.run()
    process.waitUntilExit()
    let output = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
    if output.contains("No service") {
        throw Failure("no \(serviceName) VPN configuration; launch Karst.app and approve its configuration first")
    }
    return output
}

private func waitForStatus(_ serviceName: String, _ wanted: String, deadline: Date) throws {
    while Date() < deadline {
        if try networkConnection("status", serviceName).hasPrefix(wanted) { return }
        Thread.sleep(forTimeInterval: 1)
    }
    throw Failure("\(serviceName) did not reach \(wanted) before timeout")
}

/// Leave `invitation` where the provider's next `startTunnel` enrolls from
/// it: a root-owned, mode-0600 file, published by rename so the provider
/// never sees a partial one.
private func placePendingInvitation(_ invitation: String) throws {
    try FileManager.default.createDirectory(
        atPath: stateDirectory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700]
    )
    let staged = "\(pendingInvitationPath).\(getpid())"
    let fd = open(staged, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
    guard fd >= 0 else { throw Failure("cannot stage the pending invitation") }
    let bytes = Array(invitation.utf8)
    let written = write(fd, bytes, bytes.count)
    close(fd)
    guard written == bytes.count, rename(staged, pendingInvitationPath) == 0 else {
        unlink(staged)
        throw Failure("cannot publish the pending invitation")
    }
}

private func waitForEstablishedPeer(
    expectedTransport: String?,
    deadline: Date
) throws -> [String: Any] {
    while Date() < deadline {
        guard let status = engineStatus() else {
            Thread.sleep(forTimeInterval: 1)
            continue
        }
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

/// Whether the kernel sends `prefix`'s network address through a `utun`
/// interface — i.e. the provider has applied it via setTunnelNetworkSettings.
private func kernelRoutesThroughTunnel(_ prefix: String) -> Bool {
    guard let network = prefix.split(separator: "/").first else { return false }
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/sbin/route")
    process.arguments = ["-n", "get", String(network)]
    let pipe = Pipe()
    process.standardOutput = pipe
    process.standardError = Pipe()
    guard (try? process.run()) != nil else { return false }
    process.waitUntilExit()
    let output = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
    return output.split(separator: "\n").contains { line in
        line.trimmingCharacters(in: .whitespaces).hasPrefix("interface: utun")
    }
}

/// Wait for the engine to report a route offer in the requested state. The
/// route list is the same live `statusJson` body the provider turns into
/// `NEPacketTunnelNetworkSettings`; this check intentionally does not enroll,
/// restart, or otherwise perturb the already-running tunnel between a lab
/// control-plane mutation and the subsequent application traffic probe.
private func waitForRoute(
    route: String,
    expectedPresent: Bool,
    deadline: Date
) throws {
    while Date() < deadline {
        guard let status = engineStatus() else {
            Thread.sleep(forTimeInterval: 1)
            continue
        }
        let routes = (((status["control"] as? [String: Any])?["routing"] as? [String: Any])?["routes"] as? [[String: Any]]) ?? []
        // karstd's routing_json reports `active` only for a live gateway or
        // a selected, installed exit route; a subnet route this device
        // receives is never "active" on any platform. For those the signal
        // is the provider having applied it: the kernel routes the prefix
        // through the tunnel. The offer alone is not enough — the provider
        // applies it on its next health-poll tick, and a traffic probe sent
        // in between fails although nothing is wrong.
        let present = routes.contains { candidate in
            guard candidate["prefix"] as? String == route else { return false }
            if candidate["kind"] as? String == "subnet", candidate["role"] as? String == "recipient" {
                return kernelRoutesThroughTunnel(route)
            }
            return candidate["active"] as? Bool == true
        }
            // Withdrawal likewise is not done until the kernel route is gone.
            || (!expectedPresent && kernelRoutesThroughTunnel(route))
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
    guard geteuid() == 0 else { throw Failure("run as root: the pending invitation and the engine's admin socket are root-only") }
    let deadline = Date().addingTimeInterval(arguments.timeout)
    if let expectedRoute = arguments.expectedRoute {
        try waitForRoute(
            route: expectedRoute,
            expectedPresent: arguments.expectedRouteState,
            deadline: deadline
        )
        let state = arguments.expectedRouteState ? "present" : "absent"
        print("{\"result\":\"ok\",\"route\":\"\(expectedRoute)\",\"route_state\":\"\(state)\"}")
        exit(0)
    }
    // Every run enrolls afresh: the provider only reads a pending invitation
    // in startTunnel, so stop whatever is running first. It re-enrolls, which
    // replaces a previous run's identity and behaves like enroll on a fresh
    // device (enrollment.rs's re_enroll_invitation).
    try networkConnection("stop", arguments.serviceName)
    try waitForStatus(arguments.serviceName, "Disconnected", deadline: deadline)
    try placePendingInvitation(invitation)
    try networkConnection("start", arguments.serviceName)
    let status = try waitForEstablishedPeer(
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
