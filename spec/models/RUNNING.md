<!-- SPDX-License-Identifier: CC-BY-4.0 -->

> Historical log: the DH-bearing PHREATIC models were retired on 2026-09-05 by [ADR-0018](../../docs/adr/0018-cnsa-2-0-as-the-sole-suite.md). Current model results are in [README.md](README.md).
# In-flight verification runs

Launched 2026-08-10 on **lovelace** (48 cores, 251 GB, x86-64), detached under
`nohup`.

| Model | Result |
|---|---|
| `phreatic.pv` | ✅ **4/4** — complete |
| `phreatic-dh-broken.pv` | ✅ **4/4** — complete |
| `phreatic-kem-broken-nounif.pv` | ❌ experiment D — diverged with byte-identical traces to the control; run retired |
| `phreatic-kem-broken.pv` | ⏳ still running, to establish a longer divergence bound |

The first two are the results of record: base and X25519-broken both verify
under unbounded sessions on durable hardware.

## Check the remaining run

    ssh lovelace 'cd ~/karst-verify-20260810-195857 &&
      tail -1 phreatic-kem-broken.out'

**Record whatever is observed**, including "still running". A killed run and a
non-terminating one look identical — which is what `check-proverif.sh` exists to
distinguish, and why it counts `is true` inside the summary rather than grepping
the whole file (ProVerif prints each result twice: inline, then in the summary).
