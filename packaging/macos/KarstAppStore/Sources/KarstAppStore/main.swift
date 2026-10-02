// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

import AppKit

// `.accessory`: no Dock icon, no Cmd-Tab entry — mirrors
// packaging/macos/KarstStatus/Sources/KarstStatus/main.swift exactly.
let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.accessory)
app.run()
