// swift-tools-version:5.9
// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.
//
// KarstStatus — the macOS menu-bar status indicator.
// plans/phase-6/13-macos-status-indicators.md.
//
// UNBUILT AND UNVERIFIED. Written on a Linux machine with no Xcode and no
// macOS to run `swift build` against — there is no CI job and no local run
// that has ever compiled this target. Treat every file under `Sources/` as a
// first draft to review line by line, not as working code, until someone
// with a Mac has actually built and run it. `.github/workflows/ci.yml`'s
// `macos` job does not build this package; that is real remaining work, not
// an oversight — see the plan doc §2 item 1.
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
