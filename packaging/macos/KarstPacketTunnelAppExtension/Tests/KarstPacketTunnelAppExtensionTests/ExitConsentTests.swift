// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

import XCTest
@testable import KarstPacketTunnelAppExtension

/// `ExitConsent.isPlausibleRouteID` — the one check standing between
/// `handleAppMessage`'s `"exit-use"` verb and the engine's line-oriented
/// control socket (#499). A route ID carrying a newline must never reach
/// `engineCommand`: it would smuggle a second command line past the one the
/// caller actually asked for.
final class ExitConsentTests: XCTestCase {
    func testRouteIDsArePlainTokens() {
        XCTAssertTrue(ExitConsent.isPlausibleRouteID("daq8pdmbcinc73anc320"))
        XCTAssertFalse(ExitConsent.isPlausibleRouteID(""))
        XCTAssertFalse(ExitConsent.isPlausibleRouteID("a b"))
        XCTAssertFalse(ExitConsent.isPlausibleRouteID("a\nexit-disable"))
    }

    func testRouteIDLengthIsBounded() {
        XCTAssertTrue(ExitConsent.isPlausibleRouteID(String(repeating: "a", count: 128)))
        XCTAssertFalse(ExitConsent.isPlausibleRouteID(String(repeating: "a", count: 129)))
    }
}
