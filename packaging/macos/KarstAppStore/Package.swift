// swift-tools-version:5.9
// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.
//
// KarstAppStore — the sandboxed host app for Mac App Store distribution,
// containing the KarstPacketTunnelAppExtension App Extension.
// docs/adr/0040-mac-app-store-needs-a-sandboxed-app-extension.md,
// docs/adr/0043-mac-app-store-sandboxed-app-extension-target.md.
//
// A sibling to packaging/macos/KarstStatus (the Developer-ID host app), not a
// replacement — independent SPM package, no shared Swift source, matching how
// KarstStatus and KarstPacketTunnel already relate to each other. Unlike
// KarstStatus, this app never links `karst-ffi` directly: it only talks to
// its extension over `NETunnelProviderSession.sendProviderMessage`.
//
// Minimal viable for this first pass (ADR-0043): enroll/status/quit only, no
// exit-node menu, no managed-device-ownership banner — see
// Sources/KarstAppStore/AppDelegate.swift's own header comment for why, and
// what's deliberately left out.
//
// Written the same way KarstStatus originally was — on a Linux machine with
// no Xcode/AppKit to develop against directly, compiled and tested by
// .github/workflows/macos-appextension-swift-build.yml on a real macos-14
// runner. Runtime behavior (a real `NSStatusItem`, a real enrollment round
// trip against a real, activated App Extension) is unverified — no Apple
// Developer Program Mac App Store credentials exist in this environment.
//
// macOS 13 (Ventura), matching KarstStatus's own floor.

import PackageDescription

let package = Package(
    name: "KarstAppStore",
    platforms: [.macOS(.v13)],
    targets: [
        .executableTarget(
            name: "KarstAppStore",
            path: "Sources/KarstAppStore"
        )
    ]
)
