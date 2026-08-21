<!--
SPDX-License-Identifier: MIT OR Apache-2.0
Copyright the Karst contributors.
-->

# Measurements

Raw data behind performance and stability claims in `PLAN.md`. Committed
because a claim like "no leak over 12 hours" is only worth as much as the
series behind it, and lab machines get reimaged.

Produced by `scripts/soak.sh`; see that file for the sampling method.

`userspace-cost-2026-08-21.md` is ADR-0012's gate 1: what userspace mode costs
against the privileged baseline, measured with one instrument
(`scripts/userspace-cost.sh` and `bins/karstd/examples/tcpload.rs`) over one
topology. Committed because the ADR requires the numbers before the mode is
accepted as implemented, and because taking them found two defects.

`hard-easy-2026-08-19.md` is a different kind of entry: a NAT-traversal
experiment with its harness beside it (`hard-easy-birthday.py`), committed
because it decided a design question — whether the birthday technique is worth
its architectural cost — and because the two fixture defects it turned up on the
way are worth more than the number it produced.

## Runs

| File | Result |
|---|---|
| `soak-2026-08-12-rekey-race.tsv` | **FAIL** — 459 samples, 7.9 h. Found the simultaneous-rekey race |
| `soak-2026-08-12-pass.tsv` | **PASS** — 700 samples, 12.0 h, against the fix |
| `userspace-cost-2026-08-21.md` | userspace mode at **37%** of the privileged path's throughput and 3× its RTT — after the measurement found a 71× window bug |

Both ran between `turing` and `lovelace` (48-core Xeon, Ubuntu 24.04) over a
3×1G bonded link, under continuous `iperf3` load so that every rekey happened
during traffic rather than in a quiet moment.

## Schema

Tab-separated, one row per minute.

| Column | Meaning |
|---|---|
| `elapsed_s` | seconds since sampling began |
| `state` | session state reported by `karst status` |
| `tx`, `rx` | cumulative packet counters |
| `malformed` | datagrams that failed to parse |
| `decrypt_fail` | transport messages that failed AEAD **(second run only)** |
| `mac_fail` | fragment MAC failures (spec §9.2) |
| `src_viol` | inbound packets whose source was not permitted by `allowed_ips` |
| `unroutable` | outbound packets with no matching peer prefix |
| `rss_kb` | daemon resident set size |
| `ping_ms` | RTT, or `LOSS` |

**The two files have different column counts.** The first run predates the
`decrypt_failures` counter, so it has 10 columns and the second has 11 —
`decrypt_fail` is absent, not zero. Offsets after `malformed` shift by one.
Any script reading both must key on the header rather than a fixed index.

That missing column is the point of the first run. The race it found produced
sessions derived from mismatched handshakes, so every inbound packet failed to
decrypt — and the daemon dropped them silently. `state` read `established`
throughout and all ten columns sat at zero while 13.3% of samples lost their
ping. The counter was added *because* of this run, which is why only the
second one has it.

## Reproducing

```sh
scripts/soak.sh turing lovelace --addr-a 10.10.10.1 --addr-b 10.10.10.2
sudo scripts/userspace-cost.sh --seconds 10 --rtt-count 300
```

The second needs only one host: it builds its own two namespaces, and its
three scenarios all run inside them.

Launch it from one of the machines under test, so the run outlives the session
that started it. Start with `--hours 0.25` — every code path in the harness is
exercised in fifteen minutes, and finding a harness bug twelve hours in is an
expensive way to learn about it.
