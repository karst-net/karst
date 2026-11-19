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
* Set up the scenario of pinging external commercial servers near Oregon, Denver, and (far away, anywhere east coast) Virginia:
  * Oregon: Nike (nike.com) — alt: Columbia Sportswear
  * Denver: Frontier Airlines (flyfrontier.com) — alt: Molson Coors
  * East coast / Virginia: Capital One (capitalone.com) — alt: Delta
  * All three confirmed to respond to ICMP ping; re-verify live from the office network and from each estavelle's actual location before the demo, since all three resolve through a CDN edge (CloudFront/Fastly/Akamai) and exact RTT depends on vantage point
* Show adding an estavelle in Denver
* Show ping times between servers change
* Show routing configuration where can control different domains routing to different estavelle
  * This is the **Aven** route config (ADR-0068), already shipped: Groups & access → route edit → "DNS zone" + "Pinned egress IP" fields (`web/console/src/views/routes.tsx`)
* Perform an upgrade to a new software version of an estavelle without having downtime
  * **Not implemented yet** — `estavellealloc` tracks no image/version per allocation today. Tracked as [#560](https://github.com/karst-net/karst/issues/560). Narrate against the existing, already-verified failover mechanism (draining relay signals before closing; direct path takes over without disturbing the session) rather than a live orchestrated upgrade, unless #560 lands before January.
