<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# SLA vocabulary operator-validation readiness

This page is an instrument to run, not a result. [ADR-0045](../adr/0045-cost-aware-geographic-scaling-across-providers.md)
§3's constraint vocabulary (Latency, Residency, Availability, Headroom,
Budget) is implemented — Latency and Residency shipped in #309 — but Open
Question #3 states plainly that it "should be validated against real
operators before it is frozen," and that has not happened. Nothing below is
operator feedback. It is the question set and the reasoning for asking it,
prepared so that whoever next talks to a real operator has a concrete
instrument instead of an open-ended "does this seem right?"

**This document does not and cannot substitute for that conversation.**
Closing Open Question #3 requires an actual operator's actual answer; this
page's job ends at making that conversation efficient and well-targeted.

## What is implemented today (ground truth, not aspiration)

- **Latency** (`bins/karst-scaler/src/advise_loop.rs`, `cost_model.rs`):
  `region_p95_rtt_ms` estimates each region's p95 RTT-to-nearest-relay from a
  **4-bucket** histogram (`RTT_BUCKET_BOUNDS_MS`) clients report per ADR-0021.
  Compared against an operator-declared `[latency_thresholds]` table, one
  value per region, in milliseconds. The open-ended last bucket has no upper
  bound — a region whose p95 falls there is reported as `f64::INFINITY`
  rather than a fabricated number.
- **Residency** (`cost_model.rs`'s `account_residency`/`Pool::residency_tags`):
  a hard, binary tag match — an account's demand may only land in a pool
  whose tags are a superset of what that account's entry requires. No partial
  credit, no soft/penalized variant.
- **Availability**: "survive loss of any one pool / any one region" (N+1,
  N+region) — a structural property the planner enforces, not a measured,
  contracted percentage.
- **Headroom**: provisioned ≥ demand × (1 + h) at the 95th percentile of the
  last window — a sizing input, not something an operator states as an SLA
  to their own customers.

## Why Latency is the highest-risk item to validate

Residency's tag-match model maps fairly directly onto how data-residency
requirements are usually stated ("EU customer data stays in EU jurisdictions")
— lower risk of a surprising gap. Latency is where ADR-0045's own doubt is
concentrated ("p95 RTT to nearest relay is measurable by clients but is not
the same as an application SLA"), and a short look at how the wider industry
states SLAs sharpens exactly where that gap is likely to be:

- **Latency, jitter, and packet loss are usually three separate first-class
  metrics, not one.** SonicOS, Juniper CSO, and FortiGate SD-WAN "performance
  class" / "SLA profile" objects all check latency, jitter, and packet loss
  as independent thresholds a path must clear — not a single RTT percentile.
  Karst's vocabulary today has only the first of the three.
- **Jitter can matter more than the RTT number operators are used to
  reading.** A documented site-to-site case: ~36 ms average RTT, "fine" by
  most thresholds, but swings up to 144 ms that users actually noticed as
  degraded. A p95-RTT-only SLA can look green while the experience an
  operator's own customers report is not.
- **Packet loss compounds with TCP window size to cap throughput
  independently of RTT.** AWS's own troubleshooting guidance for Site-to-Site
  VPN latency complaints walks through exactly this: a fine RTT, a capped
  real throughput, because loss (not delay) is the actual bottleneck. A
  vocabulary with no packet-loss term cannot represent this failure mode at
  all, only mis-attribute it to "latency" if an operator reports it as one.
- **"Availability" as a contracted percentage hides a lot of fine print.**
  Two providers can both say "99.9%" and deliver differently, depending on
  whether planned maintenance counts, whether partial degradation counts as
  downtime, and whether the average is per-site or network-wide. Karst's
  "survive loss of any one pool/region" is a structural guarantee, which is a
  *different kind of claim* than a measured percentage — worth surfacing to
  an operator explicitly rather than assuming they read it the way we do.
- **Complaints often trace to the path taken, not the raw link.** A reported
  VPN latency jump turned out to be a routing/path change, not the tunnel
  itself degrading. Karst's p95 is measured to the *nearest* relay — it is
  silent on whether that is also the relay the client's actual sessions used.

(Sources, non-authoritative — vendor documentation and field reports, not a
standard: [SonicOS SD-WAN performance class objects](https://sonicwall.com/support/technical-documentation/docs/sonicos-7-1-sdwan/Content/Topics/Performance_Class_Objects/about-performace-class-objects.htm),
[Juniper CSO SD-WAN SLA profiles](https://juniper.net/documentation/en_US/cso3.1/topics/task/operational/cp-config-sdwan-app-sla-profile-creating.html),
[FortiGate performance SLA monitoring](https://docs.fortinet.com/document/fortigate/7.0.8/administration-guide/943037),
[WAN-SLA and MTTR contract notes](https://www.savecall.de/en/wan-sla-mttr-worauf-achten/),
[AWS Site-to-Site VPN application latency guidance](https://www.repost.aws/knowledge-center/vpn-application-latency-issues),
a [Cisco Community site-to-site jitter report](https://community.cisco.com/t5/vpn/site-tosite-2801-vpn-with-aims-why-the-jitter/m-p/473131),
[ThousandEyes on VPNs and performance](https://www.thousandeyes.com/blog/how-virtual-private-networks-impact-performance).)

## The question set

Put to an operator who would actually configure `[latency_thresholds]` and
`[account_residency]` for their own deployment — not a hypothetical, an
operator with a real account and real downstream users.

1. When you say you need a "latency SLA" for your users, what are you
   actually promising *them* — a number you measured, or a number a contract
   states, or neither? Is it ever expressed as anything other than RTT (page
   load time, call setup time, a specific application's own response time)?
2. Would a p95 RTT-to-nearest-relay number, by itself, have told you about an
   incident your users actually noticed in the last year? If not, what would
   have — and was it jitter, loss, throughput, or something else entirely?
3. Does "nearest relay" match what you'd expect "the relay path my users'
   sessions actually took" to mean, or could those differ in your deployment
   (multiple pools per region, asymmetric routing, etc.)?
4. Do the four fixed RTT buckets (`RTT_BUCKET_BOUNDS_MS`) land close enough to
   the threshold you'd actually want to set, or does your real threshold fall
   inside a bucket wide enough that the estimate is too coarse to act on?
5. If Karst added a jitter or packet-loss threshold alongside latency, would
   you set one? What value, and measured over what window?
6. When you think about "availability," do you think in a contracted
   percentage (and if so, what counts as downtime — any degradation, or only
   total loss? per-site or fleet-wide?), or in the structural terms Karst
   uses today ("survives losing a region")? Which would you actually act on
   if it were reported to you on a dashboard?
7. Is the Residency tag model (hard, binary, per-account) sufficient for your
   actual compliance requirements, or do you have a residency requirement
   that is itself graduated (preferred-but-not-required jurisdictions, or
   different rules for different data classes within one account)?
8. Of everything above, which gap — if any — would actually change whether
   you adopt this feature, versus which is interesting but not
   decision-relevant for you?

## What to do with the answers

Record them against this question list (dated, attributed to the
conversation, not anonymized into a summary that loses who said what) and
feed the result back into ADR-0045's Open Question #3. Two outcomes are both
valid closes, and neither is assumed here:

- **The vocabulary is validated as sufficient as-is** — Open Question #3
  closes with "~~resolved~~", the same convention the ADR already uses for
  #2 and #8, and §3's table is frozen.
- **A real gap is confirmed** (most likely around jitter/packet-loss, per the
  hypotheses above) — that becomes new work: an amendment to ADR-0045 §3
  adding the missing constraint(s), not a silent vocabulary change, following
  the same "state what was decided and why" discipline every other ADR here
  uses.

Either way, this page's job is done once a real conversation happened and its
answer is recorded — not before.
