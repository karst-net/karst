# AWS Local Zone RTT vs. parent region — 2026-10-18

Measured from `shannon`, one host, one short session. Candidate zones:
Denver (`us-west-2-den-1a`), Boston (`us-east-1-bos-1a`), Houston
(`us-east-1-iah-2a`) — see [#348](https://github.com/karst-net/karst/issues/348).

| Zone | Parent region | n | min (ms) | median (ms) | max (ms) | Parent median (ms) | Δ vs. parent |
|---|---|---:|---:|---:|---:|---:|---:|
| Denver (`us-west-2-den-1a`) | us-west-2 | 20 | 3.9 | **6.3** | 96.8 | 25.7 | **-19.4 ms (better)** |
| Boston (`us-east-1-bos-1a`) | us-east-1 | 20 | 72.7 | **106.1** | 123.7 | 46.3 | **+59.8 ms (worse)** |
| Houston (`us-east-1-iah-2a`) | us-east-1 | 20 | 31.6 | **79.2** | 109.0 | 46.3 | **+32.9 ms (worse)** |

Parent-region medians are from
[`anchor-rtt-us-2026-10-08`](../anchor-rtt-us-2026-10-08/summary.csv),
measured from the same host.

## Result: no uniform win — real, zone-dependent, and surprising

Denver's Local Zone beats its parent region's anchor by a wide margin
(4x lower median RTT). Boston and Houston's Local Zones are *worse* than
their own parent region's anchor, not just by a little — Boston's median
is more than double its parent's.

**Not a measurement artifact; a plausible real cause.** A Local Zone's
internet-bound traffic commonly backhauls through its parent AWS Region
before reaching the public internet (unless the specific zone has direct
internet egress provisioned), so a path to a Local Zone instance's public
IP can genuinely be longer than a path to the parent region's own
heavily-peered edge service (`s3.{region}.amazonaws.com`, the existing
anchor). Zone-by-zone backhaul quality is apparently not uniform.

**Houston's samples are bimodal** — two distinct clusters around
~32–45ms and ~79–109ms (`raw.csv`), not noise scattered around one
center. Left as observed, not smoothed over; a real routing/path
difference (e.g. ECMP flapping) is the likely cause but wasn't
investigated further here.

**This is one host's result, not a general verdict.** Per #348's own
framing and per the prior `anchor-rtt-us-2026-10-08` run's own caveat:
single vantage point, short session, no claim about any other client's
experience. `shannon`'s own network position is not representative of
Karst's actual (or future) user base, and this report deliberately does
not weight candidate-zone selection by it for that reason.

## Cost

Real on-demand pricing, confirmed via the AWS Pricing API (not assumed):

| Zone | Instance type (zone's real floor — no nano-class type exists in any of the three) | Local Zone on-demand rate | Parent-region rate (same type) | Premium |
|---|---|---:|---:|---:|
| Denver | `t3.medium` | $0.0520/hr | $0.0416/hr (us-west-2) | +25% |
| Boston | `t3.medium` | $0.0520/hr | $0.0416/hr (us-east-1) | +25% |
| Houston | `c6gn.medium` (no `t3` family offered at all in this zone) | $0.0540/hr | — (no us-east-1 `c6gn.medium` on-demand comparison pulled) | — |

Three instances, each run for a few minutes end-to-end (launch, boot,
20 TCP-handshake samples, terminate), fully torn down after — total
spend was a few cents. No EIPs, no persistent subnets, nothing left
running (verified via `describe-instances`/`describe-subnets`/
`describe-security-groups` after cleanup).

## Method

- Opt-in: Denver was already opted in on the account; Boston and
  Houston were opted in for this run (`modify-availability-zone-group`).
- Each zone: a dedicated `/20` subnet in the parent region's existing
  default VPC (map-public-ip-on-launch enabled, inherits the default
  VPC's existing internet-gateway route), a security group allowing
  inbound TCP 22 from `shannon`'s own public IP only, one instance of
  the smallest type `describe-instance-type-offerings` reported for
  that zone (**no zone offered a nano-class type** — confirmed, not
  assumed; see [#348](https://github.com/karst-net/karst/issues/348)
  and [#352](https://github.com/karst-net/karst/issues/352), both
  corrected to stop assuming "nano" after this).
- RTT: 20 serial TCP-connect-timing samples per zone against the
  instance's public IP on port 22 (reusing the instance's own default
  `sshd` as the only thing listening — no `karst-relay`, no custom
  listener), 1s connect timeout, 200ms between samples. Every sample
  retained, including outliers, same convention as
  `anchor-rtt-us-2026-10-08`.
- Full teardown after each zone's measurement: instance terminated,
  security group and subnet deleted. Nothing left running.

## Artifacts

- [Raw observations](raw.csv)
- [Per-zone summary](summary.csv)
