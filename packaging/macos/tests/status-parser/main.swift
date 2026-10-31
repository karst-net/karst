// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

// Compile with either app's StatusParser.swift. Neither parser needs AppKit.
import Foundation

let current = StatusParser.parseJSON(#"{"interface":"karst0","version":"v0.1.0-rc.31","revision":"abc123","peers":[]}"#)
precondition(current.version == "v0.1.0-rc.31")
precondition(current.revision == "abc123")
precondition(current.refusal == nil)

let older = StatusParser.parseJSON(#"{"interface":"karst0","peers":[]}"#)
precondition(older.version == "Unknown")
precondition(older.revision == "Unknown")
precondition(older.interface == "karst0")

let invalid = StatusParser.parseJSON(#"{"version":42,"revision":"  "}"#)
precondition(invalid.version == "Unknown")
precondition(invalid.revision == "Unknown")

let stopped = StatusParser.parseJSON(#"{"error":"tunnel not running","version":"stale"}"#)
precondition(stopped.refusal == "tunnel not running")
precondition(stopped.version == "Unknown")
precondition(stopped.revision == "Unknown")

let malformed = StatusParser.parseJSON("not JSON")
precondition(malformed.refusal != nil)
precondition(malformed.version == "Unknown")
print("Status parser build identity checks passed")
