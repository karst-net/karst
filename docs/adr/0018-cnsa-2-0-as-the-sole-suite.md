<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-0018: CNSA 2.0 as the sole PHREATIC suite

- **Status:** Accepted
- **Date:** 2026-09-05
- **Deciders:** Project owner
- **Related:** ADR-0002 (superseded), ADR-0005 (amended), ADR-0006 (agility layer), ADR-0015 (amended)

---

## Context

CNSA 2.0 is now the only deployment target. ADR-0002's classical hybrid bought
assumption diversity: authentication and confidentiality could survive a break
of either ML-KEM or X25519. That hedge required a static DH identity key per
node, 32 bytes in each handshake message, three DH operations, and a second
reachable protocol path. It is no longer a hedge the deployment can use.

The DH path also required its own contributory-behavior defense. During Phase
6's internal cryptographic review, every DH leg was found to omit the check
for a non-contributory shared secret. A small-order public key could force a
publicly predictable DH contribution. ML-KEM still protected session keys
while it held, but the classical half no longer justified the claim that the
hybrid survived a break of either family against an attacker active at capture
time. This concerned accepting non-contributory static keys from the netmap;
substituting an ephemeral key on the wire already invalidated the transcript.
The subsequent `mix_dh` helper checked every DH result using the
constant-time `was_contributory` operation. Deleting that helper retires the
primitive; it does not invalidate the lesson that every enabled primitive's
required input and output checks must actually be enforced.

## Decision

PHREATIC uses only ML-KEM-1024, ML-DSA-87 identities, AES-256-GCM, and SHA-384.
Its sole wire suite identifier remains **0x0002**. Identifier 0x0001 is retired
and rejected; no identifier is renumbered or reused. The suite identifier stays
in the authenticated header, but is checked against a fixed constant.

Delete KARST_1, the suite registry, `SuiteId`, `Suite`, `Profile`, and
`SuitePolicy`. Flat parameters replace the registry and there is no suite
selection, policy floor, or fallback. Keep the length-checking `KemKind`
wrapper with its sole ML-KEM-1024 variant. SHA-512 remains for peer identity
hints and fragment MAC derivation, independently of the SHA-384 transcript.

Remove all static and ephemeral application X25519 keys from PHREATIC, the
control-plane enrollment and netmap protobuf, and the Bedrock signed body.
Private key files contain a 64-byte KEM seed. This is a hard wire and key-file
break without a migration or dual-decoding path. Regenerate both Go/Rust
cross-implementation vector files, including signatures and rejected cases.

Bedrock continues to bind the ML-DSA identity to its handle and to bind the
static KEM key that PHREATIC uses. The old warning that omitting DH would leave
session keys unconstrained assumed DH session keys existed. They no longer
exist anywhere in the application protocol. Covering the remaining static
KEM input preserves the kind of authorization Bedrock provided; its scope is
narrower because the protocol itself has fewer inputs.

Promote the former no-DH ProVerif and Verifpal models to `phreatic.pv` and
`phreatic.vp`. Remove the DH-broken models, and regenerate or update the
KEM-broken variants against the sole key schedule. A complete KEM break leaves
the per-pair PSK as the remaining confidentiality contribution; it does not
retain the former classical authentication hedge.

The relay/control TLS transport's `rustls::NamedGroup::X25519MLKEM768` is
unchanged. The independent control-channel suite remains ML-KEM-768; its
implementation belongs to the control client rather than the PHREATIC crypto
API. This decision concerns application session identities and PHREATIC,
not the separate transport protocols.

### Alternatives rejected

- **Keep both suites and default to CNSA.** A reachable unused KARST_1 path
  preserves another implementation and downgrade surface with no deployment
  that needs it.
- **Keep vestigial DH fields set to `None`.** Future agility requires another
  design decision and protocol change. Dead identity fields do not supply it.
- **Shrink suite policy to one entry.** A policy whose only possible answer
  is a constant hides the absence of negotiation and makes adding another
  suite look like a routine registry edit.
- **Renumber the sole suite to 0x0001.** ADR-0015's earlier reuse was justified
  as a one-time pre-deployment change. Repeating it for appearance provides
  no benefit and obscures the historical wire mapping.

---

## Consequences

### Positive

There is no downgrade to KARST_1 and no DH identity confusion. The handshake,
configuration, authorization predicates, and formal models have fewer paths.
Message sizes are fixed at 3210 and 3164 bytes, each requiring three fragments
of at most 1208 payload bytes. The response is 46 bytes smaller than the init.

### Negative

The classical assumption-diversity hedge is gone. Security still depends on
correct ML-KEM implementation and the configured per-pair PSK assumptions.
Three fragments in each direction have a measurable availability cost under
loss. With the existing retry window and the node simulation's 25 fixed seeds
at 40% per-datagram loss, 20 connections complete, compared with 25 for the
retired two-fragment suite. The retry policy is unchanged.

The change is irreversible for mixed-fleet interoperability: supporting a
future non-CNSA node alongside these nodes requires another wire-format break
and a new design decision. Existing key files, netmaps, and signed logs are
not migrated. Adding another suite requires superseding this ADR.

The historical ADRs remain useful records but need their amendments to be
read correctly. In particular, ADR-0002 and ADR-0005 no longer describe the
current application identity model without this decision.

### Reconsider if

A deployment target needs non-PQ-only operation, or cryptanalytic advances
make a classical hybrid necessary. Either warrants superseding this decision,
not silently restoring a second registry entry or unused DH field.
