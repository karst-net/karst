// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

import AppKit
import Foundation

// Compile against KarstStatus's production `StatusParser`/`ExitNodeMenu` —
// #481's third and fourth requirements: a confirmed-empty exit-offer list
// must read differently from one the control-plane has not yet
// synchronized, and the section must render even when there is nothing to
// offer (the "shannon-exit absence" bug this issue names).

final class DummyMenuTarget: NSObject {
    @objc func doNothing() {}
}

try MainActor.assumeIsolated {
    func titles(_ status: DaemonStatus, exitManaged: Bool = false) -> [String] {
        let menu = NSMenu()
        ExitNodeMenu.addItems(
            to: menu,
            status: status,
            exitManaged: exitManaged,
            target: nil,
            useAction: #selector(DummyMenuTarget.doNothing),
            disableAction: #selector(DummyMenuTarget.doNothing)
        )
        return menu.items.flatMap { item -> [String] in
            var all = [item.title]
            if let submenu = item.submenu { all += submenu.items.map(\.title) }
            return all
        }
    }

    // Parsing: `control_synchronized` defaults `true` for an older agent
    // or the unprivileged status socket, neither of which should read as
    // "stale" on a guess.
    let legacy = StatusParser.parseJSON(#"{"interface":"karst0","peers":[]}"#)
    precondition(legacy.controlSynchronized, "a reply with no control section must not be treated as unsynchronized")

    let synced = StatusParser.parseJSON(#"""
    {"interface":"karst0","peers":[],"control":{"control_synchronized":true,"control_peers":0,
     "routing":{"offers":0,"selected_exit":null,"exit_route_active":false,"gateway_active":false,
     "gateway_forwarding":false,"gateway_error":null,"routes":[]}}}
    """#)
    precondition(synced.controlSynchronized)
    precondition(synced.exitOffers.isEmpty)

    let unsynced = StatusParser.parseJSON(#"""
    {"interface":"karst0","peers":[],"control":{"control_synchronized":false,"control_peers":0,
     "routing":{"offers":0,"selected_exit":null,"exit_route_active":false,"gateway_active":false,
     "gateway_forwarding":false,"gateway_error":null,"routes":[]}}}
    """#)
    precondition(!unsynced.controlSynchronized, "a real control_synchronized=false must parse through, not default away")

    // Menu rendering: the four states this issue distinguishes.
    let noOffersTitles = titles(synced)
    precondition(noOffersTitles.contains(ExitNodeMenu.emptyMessage(controlSynchronized: true)))
    precondition(noOffersTitles.contains("Exit node: Off"), "the section still renders with nothing offered (#481)")

    let staleTitles = titles(unsynced)
    precondition(staleTitles.contains(ExitNodeMenu.emptyMessage(controlSynchronized: false)))
    precondition(
        !staleTitles.contains(ExitNodeMenu.emptyMessage(controlSynchronized: true)),
        "a confirmed-empty list and an unsynchronized one must not share their text"
    )

    var offered = DaemonStatus()
    offered.interface = "karst0"
    offered.exitOffers = [ExitOffer(routeID: "internet", prefix: "0.0.0.0/0", active: true, gatewayName: "gatewayA")]
    offered.selectedExit = "internet"
    let offeredTitles = titles(offered)
    precondition(offeredTitles.contains("Via gatewayA (0.0.0.0/0)"))
    precondition(offeredTitles.contains("Exit node: gatewayA"))
    precondition(!offeredTitles.contains(ExitNodeMenu.emptyMessage(controlSynchronized: true)))

    var managedNoOffers = DaemonStatus()
    managedNoOffers.interface = "karst0"
    let managedTitles = titles(managedNoOffers, exitManaged: true)
    precondition(managedTitles.contains("Managed by your organization"))
    precondition(
        managedTitles.contains(ExitNodeMenu.emptyMessage(controlSynchronized: true)),
        "a managed device with nothing offered still gets the explanatory line, not silence"
    )

    precondition(ExitNodeMenu.emptyMessage(controlSynchronized: true) != ExitNodeMenu.emptyMessage(controlSynchronized: false))

    print("exit-node menu distinguishes confirmed-empty, unsynchronized, and offered states")
}
