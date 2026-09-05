<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Formal models

Verifpal checks design properties quickly. ProVerif checks unbounded sessions
with explicit equational theories. These are symbolic models, not proofs of
implementation correctness, constant-time behavior, or computational security.

```sh
just verify        # two Verifpal models and the ProVerif release gates
just verify-slow   # the deliberately broken KEM ProVerif model
./gen-variants.sh  # regenerate broken-primitive and missing-binding variants
```

## Sole PHREATIC model

[ADR-0018](../../docs/adr/0018-cnsa-2-0-as-the-sole-suite.md) makes CNSA 2.0
the only PHREATIC suite. The former `phreatic-nodh` models were promoted to
`phreatic.pv` and `phreatic.vp` with Git renames. There is no DH primitive left
in this schedule, so there is no DH-broken variant to verify. The separate
control-channel, Ponor, and AVEN models retain their respective scopes.

The KEM-broken variant exposes all encapsulated shared secrets. Its remaining
confidentiality contribution is the private per-pair PSK. It cannot establish
the retired claim of security from either a classical or a lattice family.
The Verifpal variant is maintained from the sole schedule with weak KEM
encapsulation; the ProVerif variant adds the public `break_kem` destructor
through `gen-variants.sh`.

## Verification status

Verifpal 0.80.1 was run on 2026-09-05 after promotion:

| Model | Assumption | Result |
|---|---|---|
| `phreatic.vp` | Sound KEM and private PSK | 6/6 queries pass |
| `phreatic-kem-broken.vp` | KEM secrets exposed; private PSK | 6/6 queries pass |

ProVerif 2.05 passed all four queries on the promoted `phreatic.pv` on
2026-09-05 through `just verify`, along with the independent protocol gates
and expected-failure variants. A fresh `timeout 300 just verify-slow` run
against the regenerated KEM-broken model reached the 300-second limit with
exit 124 and no verification summary. That model remains **unverified**. The historical divergence investigation
below concerns the retired hybrid schedule and does not prove divergence
of the new model.

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

## Historical KEM-broken nontermination investigation

Before ADR-0018, the hybrid KEM-broken ProVerif model was killed after 50
minutes CPU without a verification summary; dropping correspondence queries
did not resolve it. The classical-broken model passed 4/4 and the bounded
Verifpal KEM-broken model passed 6/6. Those results never proved the hybrid's
full either-family claim. The models that produced them are retained in Git
history; [RUNNING.md](RUNNING.md) is the historical run log.

ProVerif's public `break_kem(encap_ct(p,r)) = encap_ss(p,r)` destructor
creates an unbounded attacker-derivable family of shared-secret terms.
Combined with the former seven-deep free-function key schedule, saturation
continued generating non-subsumed clauses. Nontermination proves neither an
attack nor security. Removing DH shortens the schedule but does not justify
assuming the destructor now terminates.

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

The experiments in this section remain historical evidence. Their references
to seven key mixes and the DH-broken comparison describe the retired model.

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

## Running long models

Run the actual model under a durable process and retain its output. Poll that
process rather than starting another copy when an observation times out.
`check-proverif.sh` requires the expected true and false query counts and
rejects missing summaries, errors, and timeouts. A KEM-broken run without a
summary must be reported as unverified, even when the fast path passes.
