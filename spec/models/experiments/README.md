<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Divergence experiments

Failed attempts to make `phreatic-kem-broken.pv` terminate, kept so nobody
repeats them. Measurements and analysis in `../README.md`.

| File | Change | Result |
|---|---|---|
| `expB-flat-kdf.pv` | Flattened key schedule — one n-ary KDF | Diverges |
| `expC-kem-leak.pv` | Break as targeted leakage, not a universal destructor | Diverges |
| `expD-nounif.md` | `nounif` — guides clause *selection*, not the term space | **Prepared, not yet run** |

Experiment A needed no file: it was `phreatic-kem-broken.pv` with the two
correspondence queries deleted. It also diverged, after 2409 s.

A–C all shrink the **term space** and all failed. D is worth trying because it
attacks a different mechanism — resolution strategy — which is why it is the one
remaining ProVerif option rather than a fourth variation on the same idea.

**Neither of the .pv files here is a shipping model.** `expB` in particular cannot express
"PSK mixed last", since flattening discards the ordering.
