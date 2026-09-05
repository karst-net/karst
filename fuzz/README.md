<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# Fuzzing

Four targets, all on the **pre-authentication path** — the only code that
processes attacker-controlled bytes before anything is verified.

| Target | Surface |
|---|---|
| `fragment_header` | Fragment codec (spec §5) |
| `reassembly` | Reassembler (§9.1) — asserts the DoS invariants continuously |
| `handshake_respond` | `respond()` (§6.1) — ML-KEM decap and AEAD on unauthenticated bytes |
| `dns_message` | KarstDNS client and upstream DNS wire decoder |

## Seed the corpus first

```sh
cargo run -p karst-noise --example dump_corpus -- fuzz/corpus/handshake_respond
```

**Not optional.** Random mutation will never produce a structurally valid
2378-byte `HandshakeInit`, so unseeded the target stalls at the length check.
Measured: **380 covered edges unseeded, 1038 seeded.** A clean fuzz run that
tests nothing is worse than none, because it reads as assurance.

## Long runs

```sh
for t in fragment_header reassembly handshake_respond dns_message; do
    cargo +nightly fuzz run "$t" -- -max_total_time=1920 -workers=15 -jobs=15 -max_len=4096 &
done
```

**Give each target its own working directory.** With `-jobs`, libFuzzer writes
`fuzz-N.log` into the *current* directory, so parallel targets overwrite each
other's logs. The fuzzing is unaffected — separate processes — but per-target
execution counts become unattributable. Take the totals from each `cargo fuzz
run`'s own redirect instead.

## Result of record

**2026-08-10 — 24.01 core-hours, zero crash artifacts.** 3 targets × 15 workers
× 1921 s on a 48-core host; roughly 6.7 billion executions. This satisfies the
Phase 1 exit criterion in PLAN.md §10.

Count crash **files**, never directory listings: `find fuzz/artifacts -type f`.
`ls fuzz/artifacts/*/ | grep -c .` counts the directory headers and reports
crashes that do not exist.
