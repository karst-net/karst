<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Formal models

Two tools, deliberately. **Verifpal** gives fast feedback on design blunders and
runs in seconds. **ProVerif** reasons over unbounded sessions with an explicit
equational theory and is the release gate (PLAN.md §2.5).

```sh
just verify        # Verifpal ×3 + every ProVerif model, including the must-fail ones
just verify-slow   # long-running broken-primitive variants (nightly)
./gen-variants.sh  # regenerate the generated .pv variants
```

## Status

Karst has four protocols and each has its own model. They are not variants of
one another: PHREATIC is the UDP data plane, KARST-CONTROL the node↔server
channel, Ponor the node↔relay one, AVEN the peer↔peer path discovery that runs
on the same socket as PHREATIC.

### Verifpal 0.80.0 — seconds

| Model | Assumption | Status |
|---|---|---|
| `phreatic.vp` | All primitives sound | ✅ 6/6, active attacker |
| `phreatic-kem-broken.vp` | `KEM_ENCAP[weak]` — ML-KEM broken | ✅ 6/6 |
| `phreatic-dh-broken.vp` | `PUBKEY[weak]` — X25519 keys recovered | ✅ 6/6 |

### ProVerif 2.05 — unbounded sessions

| Model | Assumption | Status |
|---|---|---|
| `phreatic.pv` | All primitives sound | ✅ **4/4**, seconds |
| `karst-control.pv` | All primitives sound | ✅ **4/4**, seconds |
| `ponor.pv` | All primitives sound, and a relay the client uses is hostile | ✅ **4/4**, seconds |
| `aven.pv` | All primitives sound, and a peer of A's is compromised | ✅ **4/4**, seconds |
| `phreatic-dh-broken.pv` | public `dlog` destructor | ✅ **4/4**, ~15 min |
| `phreatic-kem-broken.pv` | public `break_kem` destructor | ❌ **does not terminate** — see below |

Queries, per model:

- **PHREATIC** — transport confidentiality, PSK secrecy, **injective** agreement
  on the transport message, session-key agreement.
- **KARST-CONTROL** — netmap secrecy and request secrecy under post-session
  compromise of the server's static key, **injective** agreement on
  `ChannelInit`, channel-key agreement.
- **Ponor** — **injective** authentication in both directions for both roles: a
  relay admitting a client, a client authenticating the relay, and the same
  pair for a mesh peer. No secrecy query, because Ponor derives no keys; see
  `ponor.pv`'s header for what that means and does not mean.
- **AVEN** — **injective** and non-injective agreement that a node confirms a
  path only if the peer answered, no forgery of probes, and disco-key secrecy.
  The attacker holds a *different* peer's disco key throughout, because a
  aquifer is not a trust boundary.

### Models that must fail

These exist to demonstrate that a specific design decision is load-bearing.
They are gated on the *number of failing queries*, not on the absence of
passing ones — a change that quietly stopped them failing would turn each
demonstration into a decoration, and nothing else would notice.

| Model | Drops | Expected |
|---|---|---|
| `karst-control-nofs.pv` | `ss_eph` from the key schedule | ❌ 2 secrecy, ✅ 2 authentication |
| `ponor-norelayid.pv` | `relay_id` from the client's signature | ❌ 2 relay-authenticates-peer, ✅ 2 peer-authenticates-relay |
| `aven-headeronly.pv` | `tx_id` and `observed` from the MAC | ❌ 2 agreement, ✅ 2 forgery and secrecy |

`aven-headeronly.pv` is not a hypothetical. `phreatic-v1.md` §13.8 made exactly
that trade on the data path — deliberately, after profiling showed the fragment
MAC costing five times the AEAD it gated — and this variant is why the same
optimization must not be carried across to AVEN. With `tx_id` outside the MAC,
an attacker rewrites it on a captured `Pong` and confirms a path the peer never
answered from.

Getting it to fail took two goes, and the first result is worth recording: the
generator's `sed` stopped matching after an unrelated edit changed the
indentation, so only the *verifier* side was weakened. The prober then rejected
every genuine `Pong`, nothing was ever confirmed, and all four queries passed —
**vacuously**. A must-fail model that passes is the signal to go and look, not
to move on.

`ponor-norelayid.pv` is worth reading the trace of. The attack ProVerif finds
is that a **rogue relay copies an honest relay's `relay_random` into its own
hello**, so a client that connects to the rogue — legitimately, with the
rogue's key pinned — produces a signature the honest relay accepts. The rogue
then impersonates its own clients elsewhere. The client checks the relay's
identity locally in both versions; what the variant removes is the *binding* of
that identity into what the client signs, and the two are not the same thing.

## `phreatic-kem-broken.pv` does not terminate

Killed at 50 minutes CPU with no verification summary. Dropping the two
correspondence queries did not help within 30 minutes either.

This is a **limitation of the analysis, not a known weakness in the protocol**.
The `break_kem` destructor lets the attacker recover a shared secret from any
ciphertext, which makes almost every term attacker-derivable and explodes
ProVerif's saturation. Non-termination on rich equational theories is a normal
ProVerif outcome and says nothing about security either way.

What we do have for that direction:

- **Verifpal verifies it** (`phreatic-kem-broken.vp`, 6/6) — a weaker
  guarantee, bounded rather than unbounded, but not nothing.
- **The symmetric direction is proved.** `phreatic-dh-broken.pv` passes 4/4
  under a total X25519 break, which is the *harvest-now-decrypt-later*
  case — the threat this project exists to address.

**Do not report ADR-0002's "secure if either family holds" as fully proved.**
It is proved for a classical break and verified only symbolically-and-bounded
for a lattice break.

### Why it diverges

Not a protocol problem. ProVerif saturates Horn clauses; non-termination means
saturation keeps producing non-subsumed clauses.

In the base model `encap_ss(p, r)` is `[private]`, so the attacker cannot build
those terms and the seven-deep chaining key is closed to it. Adding
`break_kem(encap_ct(p,r)) = encap_ss(p,r)` gives an **infinite derivable
family**: pick any `p`, `r`, build the ciphertext with the public constructor,
apply `break_kem`. `phreatic-dh-broken.pv` terminates because `dlog` yields
*exponents*, which re-enter only through `exp` under ProVerif's special-cased DH
equation — bounded.

### What was measured, not guessed

Three restructures were tried. **All three still diverged**, which is more
useful than any of them working.

| # | Change | Result |
|---|---|---|
| A | Nested schedule, **secrecy query only** — both correspondence queries dropped | **Did not terminate — 2409 s** |
| B | **Flattened key schedule**: one n-ary KDF instead of 7 nested `mixck` | Diverging — 20 000 rules inserted, queue 18 963 vs base 2 072 |
| C | Break as **targeted leakage** (`out(c, ss)`) instead of a universal destructor | Diverging — 22 000 rules inserted, queue 21 962 vs base 3 240 |
| D | **`nounif` declarations** — guide clause *selection*, not the term space | **Diverged with byte-identical traces to the control** — see `experiments/expD-nounif.md` |

In B and C the resolution queue grows far faster than the base is consumed —
the signature of non-convergent saturation, not a slow-but-finite run.

**This revises the diagnosis.** Query complexity is not the cause (A); nor KDF
nesting alone (B); nor the universally-quantified destructor alone (C); nor
clause selection (D). A–C attacked the term space from three directions and D
attacked selection strategy — the divergence survives all four, so it comes from
their *combination* with unbounded sessions and the large unification space of
AEAD-with-transcript-as-AAD.

Run on 48 cores, the queue reached **51 468 against a base of 4 123** and was
still widening after 28 minutes. This is divergence, not slowness.

### Remaining options

| Option | Cost | What it buys | What it loses |
|---|---|---|---|
| ~~`nounif` declarations~~ | — | **Tried (D) — no effect whatsoever** | — |
| **Bounded sessions** (`P \| P`, not `!P`) | minutes | Guaranteed termination | Bounded-session only — Verifpal already gives this |
| **`set attacker = passive`** | minutes | Terminates easily | Much weaker claim |
| **Tamarin** | weeks | Backward search with user-supplied lemmas and induction; built for the case where forward saturation will not converge. Used for the WireGuard and TLS 1.3 mechanised proofs | Steep; usually needs an oracle script to steer heuristics |
| **CryptoVerif** | expert | Computational bounds rather than symbolic | realiztically needs its authors; complements rather than replaces |

**Recommendation — now evidence-backed rather than a judgment call.** Four
independent approaches have failed, including ProVerif's own canonical
anti-divergence mechanism, which had *literally zero* effect. Further ProVerif
work is not a good use of anyone's time.

Tamarin's backward search with user-supplied lemmas and induction is built for
precisely the case where forward saturation will not converge, and it is what
the WireGuard and TLS 1.3 mechanised proofs used. **Scope it as Tamarin work in
the Phase 6 external-review brief.**

### Verification environment

The base and `dh-broken` results were re-confirmed on `lovelace` (48 cores,
251 GB, x86-64) rather than a transient VM, so they are not artifacts of a
truncated run. ProVerif 2.05 built from source there — the Ubuntu package is
not in the enabled repositories, and the opam package pulls in `lablgtk` →
`libgtk2.0-dev`, which is needed only for the GUI.

### Do not run these on a transient machine

A killed run produces no summary, which is indistinguishable from
non-termination. Use `run-remote.sh` / `collect-remote.sh`, which launch
detached via `nohup` and report the three outcomes separately.

## `check-proverif.sh` — why the obvious CI check is wrong

Gate on **positive confirmation**, never on the absence of failure:

```sh
./check-proverif.sh <model.pv> <timeout_seconds> <expected_passing_queries>
```

The tempting check is `grep "is false" && fail`. It is dangerously wrong: a
model that **times out or errors produces no output at all**, so "no failures
found" passes a run that verified nothing. That is precisely the failure mode
`phreatic-kem-broken.pv` exhibits, and an earlier version of our CI would have
reported it green.

The script therefore checks proverif's own exit status (not a pipeline's),
requires a verification summary to exist, and counts `is true` **inside the
summary only** — ProVerif also prints each result inline while working, so
counting the whole file double-counts every query.

## Two properties the models pinned down

Both are in `../phreatic-v1.md` §12.5–12.6 and are easy to implement wrongly:

1. **HandshakeInit is unauthenticated by design.** Anyone holding the
   responder's public keys can fabricate one, which is why the cookie mechanism
   is load-bearing rather than defense in depth.
2. **The responder has no assurance until the first transport message.** The
   agreement query is *false* if the responder claims completion on sending
   HandshakeResponse and *true* if it waits.

## Licensing

Verifpal is **GPL-3.0-only**, ProVerif is **GPL-2.0**. Both are used strictly as
external binaries — never vendored, linked, or added as dependencies. The
`deny.toml` allowlist would reject them, correctly. See ADR-0007.

## Not covered

- Fragmentation, cookies, the fragment MAC — resource-exhaustion defenses.
  Neither tool reasons about DoS; the spoofed-source test suite and the
  `reassembly` fuzz target cover those.
- Anything computational: concrete margins, side channels, implementation
  behavior.

## Running the long models

**Do not run the broken-primitive variants on a transient machine.** A killed
run produces no summary, which is indistinguishable from a model that does not
terminate — precisely the confusion that cost us a day.

```sh
./run-remote.sh lovelace      # launches detached via nohup
./collect-remote.sh lovelace karst-verify-YYYYMMDD-HHMMSS
```

`collect-remote.sh` distinguishes the three outcomes explicitly: all queries
true, a query false, or **no summary** (still running or non-terminating). CI
must make the same distinction — treating "no output" as success is the failure
mode to design against.

## Why `phreatic-kem-broken.pv` does not terminate

Not a protocol problem. `ProVerif` saturates Horn clauses; non-termination means
saturation keeps producing non-subsumed clauses.

In the base model `encap_ss(p, r)` is `[private]`, so the attacker cannot build
those terms, and the seven-deep chaining key
`mixck(mixck(...(H(LBL), ss_s)..., psk))` is closed to it — the clause set stays
finite.

Adding `break_kem(encap_ct(p,r)) = encap_ss(p,r)` gives the attacker an
**infinite derivable family**: pick any `p`, `r`, build the ciphertext with the
public constructor, apply `break_kem`. Since `mixck` is a free binary symbol
over `bitstring`, resolution can then assemble `mixck(mixck(mixck(...)))` to
arbitrary depth with attacker-controlled slots at every level.

`phreatic-dh-broken.pv` terminates because `dlog(exp(g,x)) = x` yields
*exponents*, which re-enter only through `exp` under `ProVerif`'s special-cased
DH equation — bounded, with no unbounded nesting into the key schedule.

**The cause is the nested free-function key schedule meeting an unbounded
attacker-derivable secret family.**

### Options, cheapest first

| Option | Cost | What it buys | What it loses |
|---|---|---|---|
| **Flatten the key schedule** — one n-ary KDF instead of 7 nested `mixck` | hours | Removes the nesting outright | Cannot express "PSK mixed last"; use the nested model for ordering |
| **`nounif` declarations** | hours | `ProVerif`'s canonical anti-divergence tool; guides clause selection | May still fail to prove; sound either way |
| **One query per file** | minutes | Isolates the expensive injective query so cheap ones land | Nothing |
| **Bound sessions** (`P \| P` not `!P`) | minutes | Guaranteed termination | Bounded-session only — `Verifpal` already gives this |
| **`set attacker = passive`** | minutes | Terminates easily | Much weaker claim |
| **Tamarin** | weeks | Backward search with user-supplied lemmas and induction; the tool used for WireGuard and TLS 1.3 | Steep; usually needs an oracle script to steer heuristics |
| **CryptoVerif** | expert | Computational bounds, not just symbolic | realiztically needs its authors; complements rather than replaces |

**Recommended split:** the nested model proves ordering and agreement; a
flattened model proves the broken-primitive claims. Two models, two purposes,
each stating what it does not cover. Tamarin belongs in the Phase 6 external
review budget, not Phase 1.

Until then the honest position — stated in the README and `THREAT-MODEL.md` —
is that ADR-0002's "secure if either family holds" is **proved in the classical
direction and bounded-verified in the lattice direction**.
