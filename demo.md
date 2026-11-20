January Karst Demo

To be presented from company office (not from local home network)

* Recap previous demo where we were able to ping, ssh, and tunnel using PQ algorithms
* Name was Moria, but we want to avoid the Nazgul lawyers came up with name of Karst
* Login to Admin UI from external IP (https://204.57.25.202:33073)
* Download the mac installer 
* Install the Karst client
* Generate an invitation
* Enroll the client on the vm
* Call out that PQ encryption takes longer, but we can trick physics by pushing exit nodes (estavelle) closer to users
* Bring up NOC view which starts with a single estavelle in Oregon
* Set up the scenario of pinging external servers physically located near Oregon, Denver, and (far away, east coast) Virginia:
  * Oregon: University of Oregon, Eugene (`ntp.uoregon.edu`)
  * Denver: NIST atomic-clock time servers, Boulder (`time-a-b.nist.gov`) — alt: `time-c-b.nist.gov`
  * East coast / Virginia: Virginia Tech, Blacksburg (`ntp-1.vt.edu`) — alt: `ntp-2.vt.edu`, `vt.edu`
  * Chosen because each is hosted on the institution's own network (UO AS3582, NIST AS49, VT AS1312), not behind a CDN, so RTT tracks real geography. Commercial sites (nike.com, flyfrontier.com, capitalone.com) were dropped: their CDN edges answer from wherever you ask (e.g. nike.com was 0.6 ms from Virginia), so adding an estavelle wouldn't visibly change anything.
  * Measured 2026-11-20 from temporary EC2 hosts (avg RTT, ms):

    | Target | Oregon (us-west-2) | Denver (us-west-2-den-1) | Virginia (us-east-1) |
    |---|---|---|---|
    | `ntp.uoregon.edu` | **8.2** | 53.2 | 63.9 |
    | `time-a-b.nist.gov` | 30.5 | **3.8** | 39.0 |
    | `ntp-1.vt.edu` | 81.7 | 39.8 | **7.0** |

  * Avoid: `uoregon.edu` (didn't answer ping from Denver), `ftp.osuosl.org` (resolves to different hosts depending on where you ask), and NIST Gaithersburg `time-*-g.nist.gov` (doesn't answer ping). Re-verify from the office network before the demo.
* Show adding an estavelle in Denver
* Show ping times between servers change
* Show routing configuration where can control different domains routing to different estavelle
  * This is the **Aven** route config (ADR-0068), already shipped: Groups & access → route edit → "DNS zone" + "Pinned egress IP" fields (`web/console/src/views/routes.tsx`)
* Perform an upgrade to a new software version of an estavelle without having downtime
  * **Shipped** in [#563](https://github.com/karst-net/karst/pull/563) (closes [#560](https://github.com/karst-net/karst/issues/560)): Estavelle allocations table → **Change version** (`web/console/src/views/estavelle-services.tsx`). The server brings up a replacement instance on the new image, waits until it is genuinely admitting clients (fresh self-reported telemetry), then drains and destroys the old one (provisioning → admitting → draining → destroying). If the replacement fails, the old instance keeps running; use **Retry replacement**.
  * Demo it live: keep a ping running through the estavelle while the version changes, and show it never drops.
  * Known gaps: the version picker lists karst-net/karst GitHub release tags directly, with no admin-approved image registry yet ([#561](https://github.com/karst-net/karst/issues/561)), and nothing checks that the chosen version is compatible with the running control software ([#562](https://github.com/karst-net/karst/issues/562)). Pick a version you've already tested.
  * Rehearse it once against the demo estavelle before January.
