import XCTest
@testable import KarstPacketTunnel

/// `ExitNodeAutoConsent`'s decision (ADR-0036 §4).
final class ManagedExitTests: XCTestCase {
    func testTheSingleOfferedExitIsChosen() {
        XCTAssertEqual(ExitConsent.managedDecision(offers: ["route-a"], selected: nil), .use("route-a"))
    }

    func testAnAlreadyChosenOfferIsLeftAlone() {
        XCTAssertEqual(ExitConsent.managedDecision(offers: ["route-a"], selected: "route-a"), .none)
        XCTAssertEqual(ExitConsent.managedDecision(offers: ["route-a", "route-b"], selected: "route-b"), .none)
    }

    func testSeveralOffersWithNoChoiceAreAConflictNotAGuess() {
        XCTAssertEqual(ExitConsent.managedDecision(offers: ["route-a", "route-b"], selected: nil), .conflict)
    }

    func testAChoiceThatIsNoLongerOfferedMovesToTheSingleNewOffer() {
        // The server recreated the route under a new ID: the profile names no
        // ID, so it follows the offer.
        XCTAssertEqual(ExitConsent.managedDecision(offers: ["route-b"], selected: "route-a"), .use("route-b"))
    }

    func testNoOfferChangesNothingAndLeavesConsentDormant() {
        XCTAssertEqual(ExitConsent.managedDecision(offers: [], selected: "route-a"), .none)
        XCTAssertEqual(ExitConsent.managedDecision(offers: [], selected: nil), .none)
    }

    func testRouteIDsArePlainTokens() {
        XCTAssertTrue(ExitConsent.isPlausibleRouteID("daq8pdmbcinc73anc320"))
        XCTAssertFalse(ExitConsent.isPlausibleRouteID(""))
        XCTAssertFalse(ExitConsent.isPlausibleRouteID("a b"))
        XCTAssertFalse(ExitConsent.isPlausibleRouteID("a\nexit-disable"))
    }
}
