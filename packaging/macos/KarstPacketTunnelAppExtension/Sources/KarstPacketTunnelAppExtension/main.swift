// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

// Deliberately empty — the real entry point is set at link time
// (`Package.swift`'s `-e _NSExtensionMain`, not Swift source), the same
// way an App Extension's actual lifecycle is driven entirely by the system
// loading `Info.plist`'s `NSExtensionPrincipalClass`, never by this file's
// own code running. This file exists only so SwiftPM has an unambiguous
// `main.swift` to treat as this executable target's entry point at all:
// with more than one source file and none literally named `main.swift`,
// SwiftPM emits no implicit main symbol for the target, which is exactly
// what broke `swift test` once a second file (`ExitConsent.swift`, #499)
// joined `PacketTunnelProvider.swift` — the build failed linking with an
// undefined `_KarstPacketTunnelAppExtension_main` symbol. A single file
// avoided that ambiguity by accident, not by design.
