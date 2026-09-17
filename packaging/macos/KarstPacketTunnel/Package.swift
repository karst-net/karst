// swift-tools-version:5.9
// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.
//
// KarstPacketTunnel — the macOS NEPacketTunnelProvider System Extension.
// docs/adr/0026-macos-network-extension-backend.md,
// docs/adr/0027-macos-system-extension-host-app-ipc.md,
// docs/adr/0028-macos-network-extension-enrollment.md,
// docs/adr/0029-ffi-boundary-uniffi.md, docs/adr/0030-embedded-engine-lifecycle.md.
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
//
// ## Linking `karst-ffi`
//
// `CKarstFFI` and `KarstFFI` below wrap the compiled `karst-ffi` Rust crate
// (ADR-0029) rather than re-deriving an FFI surface by hand: `CKarstFFI` is
// a header-only target providing the `karst_ffiFFI` C module
// `Sources/KarstFFI/karst_ffi.swift` conditionally imports (both files
// generated — see that Swift file's own header comment for exactly how and
// why one committed copy is missing `EngineHandle`), and `KarstFFI` is
// where the actual link to `libkarst_ffi.a` happens.
//
// The library's location varies by build (native `cargo build` for local
// development vs. `scripts/build-macos-pkg.sh`'s explicit
// `--target <arch>-apple-darwin`), so it is read from `KARST_FFI_LIB_DIR` at
// manifest-evaluation time rather than hardcoded — that script sets it
// explicitly; a plain local `swift build` falls back to the native-target
// path a bare `cargo build -p karst-ffi --release` from the repo root
// produces. Resolved from `#filePath` (this file's own absolute path)
// rather than a bare relative string: `unsafeFlags` paths are documented to
// resolve relative to the package root, but an absolute path computed once
// here removes that as a variable entirely.
//
// **The exact archive file, not `-L`/`-l`.** `karst-ffi`'s `[lib]` produces
// `lib`/`cdylib`/`staticlib` from one build (ADR-0029, for `uniffi-bindgen`'s
// own need of a `cdylib` to introspect), so both `libkarst_ffi.a` and
// `libkarst_ffi.dylib` sit in the same directory. A plain `-lkarst_ffi`
// leaves the linker's own dylib-over-archive preference to decide which one
// wins, and finding the dynamic one would leave this binary needing a
// runtime search path to a `.dylib` nothing here embeds or signs — a
// failure that would only surface the first time the extension actually
// launches, not at build time. Passing the archive's exact path removes the
// ambiguity instead of hoping the default resolves the way this needs.
//
// **System libraries `cargo` would normally add for you, listed by hand.**
// `karst-ffi` pulls in `karstd`'s whole dependency graph (`rustls`/
// `aws-lc-rs` for the control channel, `quinn`/`tonic` over HTTP/2, and
// more) — a `cargo build` producing a `bin`/`cdylib` passes the system
// libraries that graph needs straight to the linker itself, but a bare
// `staticlib` carries none of that forward to a foreign (non-cargo) build
// consuming it. `Security`/`CoreFoundation` (the system trust store
// `aws-lc-rs`/`rustls-native-certs` read), `libresolv` (system DNS
// resolution) and `libc++` (`aws-lc-sys` compiles C++ under its own
// `BoringSSL`-derived internals) are the ones this specific dependency
// graph is known to need when linked outside `cargo`'s own final link
// step. This is the one part of this file least verifiable without a real
// Mac to link against — expect this list to need a correction the first
// time a real build actually reaches this step, not to be complete on
// the first attempt.

import Foundation
import PackageDescription

let packageRoot = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
let defaultFfiLibDir = packageRoot
    .appendingPathComponent("../../../target/release")
    .standardizedFileURL.path
let ffiLibDir = ProcessInfo.processInfo.environment["KARST_FFI_LIB_DIR"] ?? defaultFfiLibDir

let package = Package(
    name: "KarstPacketTunnel",
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
        .executableTarget(
            name: "KarstPacketTunnel",
            dependencies: ["KarstFFI"],
            path: "Sources/KarstPacketTunnel"
        ),
    ]
)
