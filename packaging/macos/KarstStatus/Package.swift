// swift-tools-version:5.9
// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.
//
// KarstStatus — the macOS menu-bar status indicator.
// plans/phase-6/13-macos-status-indicators.md.
//
// Written on a Linux machine with no Xcode and no macOS to develop against
// directly — reviewed line by line against real Darwin API signatures from
// memory, not typed against a compiler. It does compile: both
// `.github/workflows/macos-status-swift-build.yml` (a plain `swift build`)
// and `scripts/build-macos-pkg.sh`'s universal-binary build of this package,
// wired into the real installer, have succeeded on a real macos-14 runner —
// see the plan doc §2 item 1 for the run. Runtime behavior is still
// unverified: nothing has shown an `NSStatusItem`, polled a live `karstd`,
// or exercised the parser against real output. Treat that gap, not
// "does it build," as what remains before trusting this.
//
// macOS 13 (Ventura), matching `packaging/macos/Distribution.xml`'s
// `<allowed-os-versions>` floor for the daemon this talks to.

import PackageDescription

let package = Package(
    name: "KarstStatus",
    platforms: [.macOS(.v13)],
    targets: [
        .executableTarget(
            name: "KarstStatus",
            path: "Sources/KarstStatus"
        )
    ]
)
