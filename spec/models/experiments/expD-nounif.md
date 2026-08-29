<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Experiment D — `nounif` declarations

**Status: FAILED — conclusively.** Run on `lovelace` (48 cores, 251 GB),
2026-08-10, alongside the unmodified model as a control.

## Result: zero effect, exactly

The `nounif` variant and the unmodified model produced **byte-identical
saturation traces** at every checkpoint:

```
                          rules   base   queue
phreatic-kem-broken       16400   4035   51221
phreatic-kem-broken-nounif 16400  4035   51221
phreatic-kem-broken       16800   4123   51468
phreatic-kem-broken-nounif 16800  4123   51468
```

Not "similar" — identical. The declarations changed nothing about how ProVerif
explored the space. Either they did not match the facts actually driving queue
growth, or clause selection was never the bottleneck. Both readings point the
same way.

Note the shape of the divergence: **queue 51 468 against base 4 123**, a factor
of twelve and widening. That is not a slow run.

## Syntax constraint found along the way

`nounif` may not reference a destructor:

```
nounif ct: bitstring; attacker(break_kem(ct)).
    Error: function break_kem is defined by "reduc". Such a function ...
```

It applies to facts over *constructors* only, so the break itself cannot be
de-prioritized — only the terms it produces. The three surviving declarations
were on `encap_ss`, `mixck` and `mixk`.

## What this settles

All four ProVerif avenues are now exhausted:

| # | Change | Mechanism attacked | Result |
|---|---|---|---|
| A | Secrecy query only | Query complexity | Diverged (2409 s) |
| B | Flattened key schedule | Term depth | Diverged |
| C | Targeted leakage, not a destructor | Derivable-term family | Diverged |
| D | `nounif` | Clause selection | **Diverged — identically** |

A–C attacked the term space from three angles; D attacked selection strategy.
Nothing moved. **The recommendation to take this to Tamarin now rests on
measurement rather than judgment.**

## Why this is the remaining option

Experiments A–C (see `../README.md`) each removed one suspected cause of
divergence and each still diverged:

- **A** — dropped the correspondence queries → not query complexity.
- **B** — flattened the key schedule → not KDF nesting.
- **C** — replaced the universal destructor with targeted leakage → not the
  destructor alone.

All three shrink the **term space**. `nounif` is different in kind: it guides
ProVerif's **clause selection strategy** without changing the term space at all.
That is why it is worth one attempt after three term-space fixes failed — it
attacks a different mechanism.

`nounif` is sound in one direction only: it can cause ProVerif to fail to prove
something true, but it cannot cause it to prove something false. A pass under
`nounif` is therefore still a valid result; a failure is inconclusive.

## What to add

Append to `phreatic-kem-broken.pv`, after the declarations and before the
processes:

```proverif
(* Do not select attacker-derivability of arbitrary KEM shared secrets as a
   resolution goal. The attacker genuinely can derive these under break_kem, but
   letting resolution chase every (p, r) instantiation is what prevents
   saturation from converging. *)
nounif p: pkem, r: rnd; attacker(encap_ss(p, r)).

(* Likewise for chaining values built from them. *)
nounif ck: bitstring, x: bitstring; attacker(mixck(ck, x)).
nounif ck: bitstring, x: bitstring; attacker(mixk(ck, x)).
```

Then, in order of increasing aggression if the first has no effect:

1. Add `nounif ct: bitstring; attacker(break_kem(ct)).`
2. Add a selection weight: `nounif p: pkem, r: rnd; attacker(encap_ss(p,r)) / -5000.`
3. Combine with experiment B's flattened schedule — the two attack different
   mechanisms and may only work together.

## How to run it

**Not on a transient machine.** A killed run is indistinguishable from
non-termination.

```sh
cd spec/models
./run-remote.sh <durable-host>
./collect-remote.sh <durable-host> karst-verify-YYYYMMDD-HHMMSS
```

## How to record the outcome

Whatever happens, write it into `../README.md`'s measurement table in the same
form as A–C: the change, and the observed result with numbers. If it diverges,
record the rule-insertion and queue figures — the queue growing faster than the
base is the signature, and it is what distinguishes divergence from slowness.

If `nounif` also fails, the recommendation in `../README.md` stands: stop
investing in ProVerif and scope this as Tamarin work in the Phase 6 external
review brief.
