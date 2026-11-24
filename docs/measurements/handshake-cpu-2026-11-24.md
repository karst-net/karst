<!--
SPDX-License-Identifier: CC-BY-4.0
Copyright the Karst contributors.
-->

# PHREATIC vs. WireGuard handshake CPU cost

**2026-11-24.** Harness: [`../../bins/karstd/tests/handshake_rate_bench.rs`](../../bins/karstd/tests/handshake_rate_bench.rs)
(karst-net/karst#119, already in-repo) and
[`../../scripts/wg-handshake-bench/`](../../scripts/wg-handshake-bench/) (new
with this entry).

## The question

`vpn-comparison-2026-09-30.md` measured steady-state throughput and idle
cost; it says nothing about the one place PHREATIC is doing categorically
more work than every classical-crypto alternative — the handshake itself,
where ML-KEM-1024 decapsulation replaces a Curve25519 scalar multiplication.
`performance.html`'s "A little more cryptography. A lot less distance."
section made that tradeoff with illustrative, explicitly-labeled placeholder
numbers (a hypothetical "2 ms" PQ setup cost). This entry replaces the
placeholder with a real measurement of what that cost actually is.

## Method

Both harnesses call their real production handshake code **directly, in
one process, with no network socket in the loop** — not a wall-clock
measurement of two daemons talking over a wire, a measurement of the CPU
the responder-side handshake math itself costs:

- **PHREATIC**: one server `Engine` with 2,000 pre-registered peer
  identities (a closed roster, same as any real karst deployment), 2,000
  distinct client `Engine`s. Only `Engine::inbound` calls on the server side
  are timed — a client's own cost runs on a different machine's core in any
  real deployment. The server is held under cookie-validated load (§9.1) for
  the whole run, so this number already includes the mac1/mac2 cookie-check
  overhead on top of the ML-KEM-1024 decapsulation; it is not the cheapest
  case.
- **WireGuard**: the real `golang.zx2c4.com/wireguard` `device` package —
  the same library wireguard-go, and so Tailscale's userspace engine, ships —
  driven through its own exported handshake primitives
  (`CreateMessageInitiation`/`ConsumeMessageInitiation`/
  `CreateMessageResponse`/`ConsumeMessageResponse`/`BeginSymmetricSession`),
  which is exactly what `device/receive.go`'s `RoutineHandshake` calls in a
  real running `wireguard-go`. Same shape: one responder `Device` with 2,000
  registered peers, 2,000 distinct initiator `Device`s, only the responder
  side timed. No cookie/DoS-mitigation path is exercised (WireGuard's under
  this scale of synthetic load wouldn't trigger one) — so this number is the
  *cheaper*, unloaded case, which if anything understates PHREATIC's relative
  premium less than an apples-to-apples loaded comparison would.

```sh
cargo test --release -p karstd --test handshake_rate_bench -- --ignored --nocapture
cd scripts/wg-handshake-bench && go run .
```

### Host

**Not `turing`/`lovelace`.** Run on a development laptop, not the lab pair
used elsewhere in this directory — call this out before citing these numbers
anywhere the two might get compared against `vpn-comparison-2026-09-30.md`'s
figures.

| | |
|---|---|
| host | AMD Ryzen 7 7735HS, 16 threads |
| kernel | 6.8.0-147-generic, Ubuntu 24.04.3 LTS |
| karst | commit `96b5e0a` (origin/main) |
| rustc | 1.89.0 |
| go | 1.23.1 |
| `golang.zx2c4.com/wireguard` | `v0.0.0-20261024220952-b3bc704ef0ee` |

## Results

Four runs each, release/optimized builds, nothing else running:

| | Karst (PHREATIC) | WireGuard |
|---|---|---|
| handshakes/sec/core | 2,916 / 2,978 | 4,766 / 4,780 / 4,995 / 5,091¹ |
| server CPU per handshake | **~340 µs** | **~205 µs** |

¹ A fifth, cold-start run returned 4,216/sec (237 µs) — Go's first-run JIT
and allocator warmup, not a real outlier; excluded as noise rather than kept
to shade the average favorably.

**The PQ premium is ~135 µs of CPU time per handshake — a fraction of a
millisecond, not the "2 ms" placeholder `performance.html` used to
illustrate the tradeoff.** In relative terms PHREATIC costs ~1.7× WireGuard's
CPU per handshake; in absolute terms it is noise next to any real network
RTT, including the fastest same-metro hop measured in
`vpn-comparison-2026-09-30.md` (0.57 ms WireGuard ping avg on a bonded LAN —
larger than the entire PQ premium by itself).

## Why this comparison is fair, and where it isn't

Same framing `performance.html` already uses for the throughput table:
WireGuard does none of PHREATIC's post-quantum work, and this isolates
exactly the CPU cost of that difference, with both measurements using the
same methodology (direct in-process calls to real production code, server
side only, setup excluded). Where it tilts against PHREATIC: the loaded
cookie-check path is on for Karst's number and off for WireGuard's, discussed
above. Where it tilts in PHREATIC's favor: this is one core's cost for one
handshake in isolation — it says nothing about concurrent-handshake
throughput under a real connection storm, which is a different, unmeasured
question.

## Scope cuts

- **Not measured on `turing`/`lovelace`.** Numbers here aren't directly
  comparable to `vpn-comparison-2026-09-30.md`'s until re-run on the same
  hosts.
- **Wall-clock, end-to-end daemon setup time** (process spawn, interface
  creation, the ~1 s scale `vpn-comparison-2026-09-30.md`'s "Setup (s)"
  column measures) is a different, larger number than the CPU cost measured
  here and is not what this entry is about — don't conflate the two.
- **Concurrent-handshake throughput** (many handshakes landing at once,
  across cores, under a real connection-storm) is not measured — this is a
  single core's serial cost for isolated handshakes.
- **OpenVPN** was also measured in the course of this work (a real RSA-2048
  TLS 1.3 session, ~15 ms wall-clock to complete) but isn't included in the
  table above: that number is daemon wall-clock including OpenVPN's own
  multi-round-trip reliability layer, not an isolated CPU cost, so it isn't
  the same kind of measurement as the two above and would mislead side by
  side with them.

## Reproducing

```sh
cargo test --release -p karstd --test handshake_rate_bench -- --ignored --nocapture
cd scripts/wg-handshake-bench && go run .
```

`scripts/wg-handshake-bench/` is a standalone Go module (its own `go.mod`),
not part of any Rust workspace build — `go run .` fetches its one dependency
on first run.
