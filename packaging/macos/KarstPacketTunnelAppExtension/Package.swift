// swift-tools-version:5.9
// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.
//
// KarstPacketTunnelAppExtension — the sandboxed macOS NEPacketTunnelProvider
// App Extension (`.appex`) for Mac App Store distribution.
// docs/adr/0040-mac-app-store-needs-a-sandboxed-app-extension.md,
// docs/adr/0043-mac-app-store-sandboxed-app-extension-target.md.
//
// A sibling to packaging/macos/KarstPacketTunnel (the Developer-ID System
// Extension), not a replacement for it — the two ship through different
// distribution channels and, per ADR-0040 item 4, never need to coexist in
// one bundle. This package is deliberately independent (its own Package.swift,
// its own copy of the generated karst-ffi Swift bindings) rather than sharing
// a library target with KarstPacketTunnel, matching how KarstStatus and
// KarstPacketTunnel already relate to each other — zero shared Swift source,
// so nothing about the already-shipping Developer-ID build is touched here.
//
// Written the same way KarstPacketTunnel originally was: on a Linux machine
// with no Xcode/NetworkExtension SDK to develop against directly, compiled by
// .github/workflows/macos-appextension-swift-build.yml on a real macos-14
// runner. See PacketTunnelProvider.swift's own header comment for the current
// runtime boundary — sandbox activation, App Group container resolution, and
// real traffic are all still unverified against real hardware or a real Mac
// App Store provisioning profile, neither of which exists in this environment.
//
// ## Linking `karst-ffi`
//
// Identical reasoning to KarstPacketTunnel/Package.swift — see that file's
// own header comment for the full explanation of `CKarstFFI`/`KarstFFI`,
// `KARST_FFI_LIB_DIR`, why the exact archive path (not `-L`/`-l`) is passed,
// and why the system libraries below are listed by hand. Nothing here differs
// for a sandboxed consumer: the compiled `karst-ffi` static library and its
// generated bindings are identical regardless of which NetworkExtension
// packaging shape links them.

import Foundation
import PackageDescription

let packageRoot = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
let defaultFfiLibDir = packageRoot
    .appendingPathComponent("../../../target/release")
    .standardizedFileURL.path
let ffiLibDir = ProcessInfo.processInfo.environment["KARST_FFI_LIB_DIR"] ?? defaultFfiLibDir

let package = Package(
    name: "KarstPacketTunnelAppExtension",
    platforms: [.macOS(.v13)],
    targets: [
        .target(
            name: "CKarstFFI",
            path: "Sources/CKarstFFI"
        ),
        .target(
            name: "KarstFFI",
            dependencies: ["CKarstFFI"],
            path: "Sources/KarstFFI",
            linkerSettings: [
                .unsafeFlags(["\(ffiLibDir)/libkarst_ffi.a"]),
                .linkedLibrary("resolv"),
                .linkedLibrary("c++"),
                .linkedFramework("Security"),
                .linkedFramework("CoreFoundation"),
            ]
        ),
        .testTarget(
            name: "KarstPacketTunnelAppExtensionTests",
            dependencies: ["KarstPacketTunnelAppExtension"],
            path: "Tests/KarstPacketTunnelAppExtensionTests"
        ),
        .executableTarget(
            name: "KarstPacketTunnelAppExtension",
            dependencies: ["KarstFFI"],
            path: "Sources/KarstPacketTunnelAppExtension"
        ),
    ]
)
