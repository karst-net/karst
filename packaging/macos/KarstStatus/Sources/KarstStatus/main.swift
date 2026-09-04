// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

import AppKit

// `.accessory`: no Dock icon, no entry in the Cmd-Tab switcher — the
// `LSUIElement` behavior, set here rather than via an Info.plist key so this
// stays true however the executable ends up bundled.
let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.accessory)
app.run()
