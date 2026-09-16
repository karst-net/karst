// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

import NetworkExtension

// The entry point a `NEPacketTunnelProvider` packaged as a System Extension
// (not an app extension — docs/adr/0026-macos-network-extension-backend.md
// "Decision" item 5) needs, per Apple's own guidance for exactly this shape:
// `NEProvider.startSystemExtensionMode()` hands control to the
// NetworkExtension framework's own extension-hosting machinery, which
// instantiates `PacketTunnelProvider` (named by `Info.plist`'s
// `NSExtensionPrincipalClass`) when the system activates or connects this
// extension. `dispatchMain()` keeps the process alive afterward — this
// executable does not return the way `KarstStatus`'s `main.swift` does,
// because there is no `NSApplication.run()` equivalent here to block on.
autoreleasepool {
    NEProvider.startSystemExtensionMode()
}
dispatchMain()
