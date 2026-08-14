<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Formal models

Two tools, deliberately. **Verifpal** gives fast feedback on design blunders and
runs in seconds. **ProVerif** reasons over unbounded sessions with an explicit
equational theory and is the release gate (PLAN.md §2.5).

```sh
just verify        # Verifpal ×3 + ProVerif base model
just verify-slow   # long-running ProVerif variants (nightly)
./gen-variants.sh  # regenerate the .pv variants from phreatic.pv
```

## Status

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
| `phreatic-dh-broken.pv` | public `dlog` destructor | ✅ **4/4**, ~15 min |
| `phreatic-kem-broken.pv` | public `break_kem` destructor | ❌ **does not terminate** — see below |

Queries: transport confidentiality, PSK secrecy, **injective** agreement on the
transport message, and session-key agreement.

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
| **CryptoVerif** | expert | Computational bounds rather than symbolic | Realistically needs its authors; complements rather than replaces |

**Recommendation — now evidence-backed rather than a judgement call.** Four
independent approaches have failed, including ProVerif's own canonical
anti-divergence mechanism, which had *literally zero* effect. Further ProVerif
work is not a good use of anyone's time.

Tamarin's backward search with user-supplied lemmas and induction is built for
precisely the case where forward saturation will not converge, and it is what
the WireGuard and TLS 1.3 mechanised proofs used. **Scope it as Tamarin work in
the Phase 6 external-review brief.**

### Verification environment

The base and `dh-broken` results were re-confirmed on `lovelace` (48 cores,
251 GB, x86-64) rather than a transient VM, so they are not artefacts of a
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
   is load-bearing rather than defence in depth.
2. **The responder has no assurance until the first transport message.** The
   agreement query is *false* if the responder claims completion on sending
   HandshakeResponse and *true* if it waits.

## Licensing

Verifpal is **GPL-3.0-only**, ProVerif is **GPL-2.0**. Both are used strictly as
external binaries — never vendored, linked, or added as dependencies. The
`deny.toml` allowlist would reject them, correctly. See ADR-0007.

## Not covered

- Fragmentation, cookies, the fragment MAC — resource-exhaustion defences.
  Neither tool reasons about DoS; the spoofed-source test suite and the
  `reassembly` fuzz target cover those.
- Anything computational: concrete margins, side channels, implementation
  behaviour.

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
| **CryptoVerif** | expert | Computational bounds, not just symbolic | Realistically needs its authors; complements rather than replaces |

**Recommended split:** the nested model proves ordering and agreement; a
flattened model proves the broken-primitive claims. Two models, two purposes,
each stating what it does not cover. Tamarin belongs in the Phase 6 external
review budget, not Phase 1.

Until then the honest position — stated in the README and `THREAT-MODEL.md` —
is that ADR-0002's "secure if either family holds" is **proved in the classical
direction and bounded-verified in the lattice direction**.
