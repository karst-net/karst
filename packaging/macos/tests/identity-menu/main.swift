// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

import AppKit
import Foundation

// Compile against KarstStatus's production `IdentityMenu` — #481's four
// enrollment states must each draw different menu text, and a failed
// recheck must never erase an already-confirmed identity.

// A dedicated, unambiguous `@objc` selector — these items are never
// clicked in this harness, only inspected, so any method will do as long
// as the compiler can resolve it without reaching into AppKit internals.
final class DummyMenuTarget: NSObject {
    @objc func doNothing() {}
}

try MainActor.assumeIsolated {
    func titles(_ identity: IdentityStatus, managerOwnership: NetworkExtensionEnrollment.ManagerOwnership? = nil) -> [String] {
        let menu = NSMenu()
        IdentityMenu.addItems(
            to: menu,
            identity: identity,
            managerOwnership: managerOwnership,
            target: nil,
            enrollAction: #selector(DummyMenuTarget.doNothing),
            reEnrollAction: #selector(DummyMenuTarget.doNothing)
        )
        return menu.items.map(\.title)
    }

    let neverChecked = titles(.unknown)
    precondition(neverChecked.contains("Enroll…"), "an unknown identity still offers enrollment")
    precondition(
        neverChecked.contains("Enrollment status could not be checked yet"),
        "a never-checked device must not be told it is unenrolled"
    )
    precondition(!neverChecked.contains(where: { $0.hasPrefix("Enrolled as") }))

    let confirmedUnenrolled = titles(.notEnrolled)
    precondition(confirmedUnenrolled.contains("Enroll…"))
    precondition(
        !confirmedUnenrolled.contains("Enrollment status could not be checked yet"),
        "a confirmed-unenrolled device must read differently from an unchecked one"
    )
    precondition(!confirmedUnenrolled.contains(where: { $0.hasPrefix("Enrolled as") }))

    let enrolled = titles(.enrolled(handle: "0123456789abcdef0123456789abcdef", name: "alice.example.karst"))
    precondition(enrolled.contains("Enrolled as alice.example.karst"))
    precondition(enrolled.contains("Re-enroll…"))
    precondition(!enrolled.contains("Enroll…"), "an enrolled device must not also be offered first-time enrollment")

    let enrolledNoName = titles(.enrolled(handle: "0123456789abcdef0123456789abcdef", name: nil))
    precondition(
        enrolledNoName.contains(where: { $0.hasPrefix("Enrolled as 01234567") }),
        "a device enrolled before #163 shipped still shows a real identity, truncated"
    )

    // A failed recheck of a previously-enrolled device: #481's actual bug.
    // It must keep showing the last known identity, not revert to
    // "Enroll…" on a guess.
    let stale = titles(.stale(handle: "0123456789abcdef0123456789abcdef", name: "bob.example.karst"))
    precondition(stale.contains("Enrolled as bob.example.karst"), "a transient failure must not erase a known identity")
    precondition(stale.contains("Re-enroll…"))
    precondition(!stale.contains("Enroll…"))
    precondition(stale.contains(where: { $0.contains("could not be rechecked") }), "stale state must be disclosed, not silent")

    // `IdentityStatus.afterFailedCheck` itself: the state machine a failed
    // check feeds through.
    precondition(IdentityStatus.unknown.afterFailedCheck == .unknown)
    precondition(IdentityStatus.notEnrolled.afterFailedCheck == .unknown, "a confirmed-unenrolled read is not re-asserted on a later failure, but it is not kept either — it has nothing to go stale from")
    precondition(
        IdentityStatus.enrolled(handle: "h", name: "n").afterFailedCheck == .stale(handle: "h", name: "n"),
        "an enrolled device's identity survives a failed recheck as stale, not unknown"
    )
    precondition(IdentityStatus.stale(handle: "h", name: "n").afterFailedCheck == .stale(handle: "h", name: "n"))

    let managed = titles(.notEnrolled, managerOwnership: .unknownOrForeign)
    precondition(managed.contains("VPN configuration managed by your organization"))

    print("identity menu distinguishes unchecked, unenrolled, enrolled, and stale states")
}
