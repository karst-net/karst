<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Karst security whitepaper

- **Scope:** Karst v1, pre-alpha
- **Derived threat-model revision:** `99ba57f24cb4dc63755e19968f99168d12364215`
- **Review status:** internal cryptographic review complete; external review pending

This document summarizes Karst's security posture for an evaluator. It does
not replace the normative protocol specifications or the
[threat model](THREAT-MODEL.md). Source annotations identify the primary
record for each factual claim.

## 1. Protection goals

Karst is a self-hosted mesh VPN designed first for traffic confidentiality,
including against harvest-now-decrypt-later collection. It treats a passive
global recorder, an active classical network attacker, malicious enrolled
peers, compromised relays, and a compromised coordination server as in-scope
adversaries. Root compromise of an endpoint and an active adversary with a
real-time cryptographically relevant quantum computer are outside v1's claim.
([Threat model §§2–3](THREAT-MODEL.md#2-assets))

Peer traffic is end-to-end encrypted. A relay carries ciphertext and learns
metadata; the coordination server distributes topology, policy, and per-pair
secrets but has no node KEM secret with which to decrypt ordinary traffic.
The combined event of a coordination-server compromise and a full lattice
break is explicitly a total break. ([Threat model §§4–5](THREAT-MODEL.md#4-trust-boundaries))

## 2. Cryptographic design

PHREATIC is Karst's UDP dataplane protocol. Its sole suite is `0x0002`
(`KARST_2`): ML-KEM-1024, ML-DSA-87, AES-256-GCM, and SHA-384.
The suite identifier and PSK epoch are transcript-bound, unknown suites
are rejected, and per-pair PSKs are mixed last. A responder accepts only the
current and immediately previous PSK epoch. ([PHREATIC §§3, 7](../spec/phreatic-v1.md#3-cryptographic-suites))

Each node identity comprises an ML-DSA-87 identity key and a static
ML-KEM-1024 key. Bedrock authorizes those node keys by
an append-only, hash-chained, quorum-signed log. Its capability-scoped anchor
tier can bind that chain to the independently hash-chained administrative
audit log without giving an online anchor key node-authorization power.
([PHREATIC §4](../spec/phreatic-v1.md#4-node-identity);
[ADR-0016](adr/0016-capability-scoped-anchor-authorities.md))

The node-to-control protocol is a separate record layer using ML-KEM-768,
ML-DSA-87, ChaCha20-Poly1305, and SHA-512. Nodes pin the server's static KEM
and identity keys; the server signs a per-connection ephemeral KEM key, and
both static and ephemeral KEM shared secrets enter the key schedule. The
inner protocol provides authentication and confidentiality independently of
its transport.
([KARST-CONTROL §§1.2, 3–7](../spec/karst-control-v1.md#3-cryptographic-suite))

PHREATIC bounds unauthenticated reassembly, caps a handshake at four
fragments, and uses an address-validation cookie above its load threshold.
The first handshake message is larger than the response, preventing protocol
amplification. ([PHREATIC §§6.4, 9](../spec/phreatic-v1.md#9-denial-of-service-mitigation))

## 3. Internal review findings and remediation

The Phase 6 internal cryptographic review was a source/spec/model review, not
an external assessment. It reported eight findings; every high and medium
finding below is recorded as fixed or closed in the review record:

| # | Finding | Resolution |
|---|---|---|
| 1 / [#76](https://github.com/karst-net/karst/issues/76) | Cookie code existed but the daemon bypassed address validation. | Wired rotating cookie secrets, challenge/retry, and live amplification coverage end to end. |
| 2 / [#77](https://github.com/karst-net/karst/issues/77) | The daemon ignored the requested PSK epoch. | Preserved previous PSKs and enforced accept-*n*/*n−1*, reject all others. |
| 3 / [#78](https://github.com/karst-net/karst/issues/78) | Formal models omitted the no-DH suite. | Added Verifpal and ProVerif `phreatic-nodh` models and CI coverage. |
| 4 / [#79](https://github.com/karst-net/karst/issues/79) | Secret-bearing dependencies did not enable zeroize-on-drop features. | Enabled them and added compile-time regression assertions. |
| 5 / [#80](https://github.com/karst-net/karst/issues/80) | Handshake reassembly IDs were predictable counters. | Replaced them with per-call CSPRNG-derived IDs. |
| 6 / [#81](https://github.com/karst-net/karst/issues/81) | Handshake `mac2` did not cover payload bytes. | Bound handshake payloads into the fragment MAC. |
| 7 / [#82](https://github.com/karst-net/karst/issues/82) | Six X25519 call sites omitted the contributory check. | Applied the constant-time check uniformly; ADR-0018 later retired application DH entirely. |
| 8 / [#83](https://github.com/karst-net/karst/issues/83) | Simultaneous open retained two sessions indefinitely. | Added the specified static-key tie-break and authenticated convergence. |

The details, affected call paths, tests, and issue references are in
[`phreatic-review-findings.md`](../phreatic-review-findings.md). The review
also re-confirmed low risks rather than relabeling them as new findings.

The `formal` CI job runs the bounded PHREATIC, KARST-CONTROL, Ponor, and AVEN
ProVerif models plus deliberately broken models that must fail. Parser and
protocol tests cover KATs, cookies, fragmentation, epoch rollover, and
simultaneous open. Formal models validate stated symbolic properties; they do
not establish implementation security or replace external review.
([Review findings §§1–8](../phreatic-review-findings.md);
[`just verify`](../justfile))

## 4. Accepted risks and non-goals

- Traffic metadata is not hidden from relays, TURN providers, or on-path
  observers; traffic-analysis resistance is not a v1 goal.
- Endpoint root compromise exposes that endpoint's keys and plaintext.
- A coordination-server compromise plus a full lattice break is total.
- The IdP is a trusted root for user enrollment, and a malicious administrator
  is audited rather than prevented from changing policy.
- Karst has no FIPS 140-3 validated boundary.
- Karst is not wire-compatible with WireGuard. Its handshake exceeds
  WireGuard's framing and migration requires a clean cutover.

These are restatements of the [threat model §7](THREAT-MODEL.md#7-accepted-risks-and-non-goals),
not newly derived assurances.

## 5. Review status and limitations

No external cryptographic review and no external penetration test have
happened. Both are Phase 8 work. Phase 6 performed an internal cryptographic
review and an internal penetration test; neither is represented here as a
substitute for independent assessment. Wire formats remain pre-alpha and may
change without compatibility guarantees. ([Phase 6 overview §6](../plans/phase-6/00-overview.md#6-what-this-phase-does-not-do))

PHREATIC no longer claims a classical/lattice hybrid hedge. Verifpal verifies
the KEM-broken model with a private PSK, while unbounded ProVerif verification
of that variant must be reported separately from the sound-KEM base model.
The historical hybrid KEM-broken model did not terminate.
([Model record](../spec/models/README.md), [ADR-0018](adr/0018-cnsa-2-0-as-the-sole-suite.md))

## 6. Sign-off

The sign-off must bind review to the exact source revision above.

- **Crypto lead:** pending independent end-to-end review
- **Date:** pending
- **Threat-model commit reviewed:** `99ba57f24cb4dc63755e19968f99168d12364215`
- **Whitepaper commit reviewed:** pending
- **Disposition:** not signed off; publication exit gate remains open

No name is inserted here until the crypto lead has checked every source-linked
claim and records that approval in the reviewed commit.
