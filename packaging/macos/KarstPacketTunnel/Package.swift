// swift-tools-version:5.9
// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.
//
// KarstPacketTunnel — the macOS NEPacketTunnelProvider System Extension.
// docs/adr/0026-macos-network-extension-backend.md,
// docs/adr/0027-macos-system-extension-host-app-ipc.md,
// docs/adr/0028-macos-network-extension-enrollment.md.
//
// Written the same way packaging/macos/KarstStatus originally was: on a
// Linux machine with no Xcode and no macOS to develop against directly,
// reviewed line by line against real Darwin/NetworkExtension API signatures
// (checked against Apple's published documentation this session, not
// recalled alone), not typed against a compiler. Whether it compiles is
// unknown until .github/workflows/macos-packettunnel-swift-build.yml runs on
// a real macos-14 runner. Runtime behavior is unverified at every level
// beyond that — nothing has loaded this as a real System Extension or sent
// it a provider message. See PacketTunnelProvider.swift for exactly which
// calls are placeholders and why.
//
// macOS 13 (Ventura), matching packaging/macos/Distribution.xml's
// <allowed-os-versions> floor and KarstStatus's own Package.swift.

import PackageDescription

let package = Package(
    name: "KarstPacketTunnel",
    platforms: [.macOS(.v13)],
    targets: [
        .executableTarget(
            name: "KarstPacketTunnel",
            path: "Sources/KarstPacketTunnel"
        )
    ]
)
