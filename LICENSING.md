# Licensing

Karst is open source throughout. Different parts of the tree carry different
licenses; the rationale is recorded in
[ADR-0007](docs/adr/0007-licensing.md).

## What applies where

| Path | License | SPDX |
|---|---|---|
| `crates/**` | MIT **or** Apache-2.0, at your option | `MIT OR Apache-2.0` |
| `bins/karstd`, `bins/karst`, `bins/karst-relay` | MIT **or** Apache-2.0, at your option | `MIT OR Apache-2.0` |
| `server/**` (`karst-control`) | GNU Affero General Public License v3.0 or later | `AGPL-3.0-or-later` |
| `web/console`, `web/portal` | GNU Affero General Public License v3.0 or later | `AGPL-3.0-or-later` |
| `spec/**`, `docs/**` | Creative Commons Attribution 4.0 | `CC-BY-4.0` |

Every source file carries an SPDX identifier. When the file header and this
table disagree, the file header wins.

## The protocol is free to implement

The PHREATIC protocol specification in `spec/` is published under CC-BY-4.0, and
we grant an irrevocable, royalty-free right to implement it in software under
any license, open or proprietary. Independent implementations are welcome and
actively wanted — a protocol with one implementation has not been meaningfully
reviewed.

## The AGPL on the server does not affect your use of the client

This is the most common misreading, so to be explicit:

- `karstd`, `karst`, and the relay are MIT/Apache-2.0. Running, embedding,
  packaging, modifying, or shipping them in a proprietary product imposes no
  copyleft obligation.
- The node agent and the coordination server are **separate programs
  communicating over a network protocol**. Running an AGPL server does not make
  your client, your infrastructure, or anything else you run a derivative work.
- The AGPL obligation is narrow and specific: **if you modify the coordination
  server or console and let others use it over a network, you must offer those
  users the modified source.** Running an unmodified server obliges you to
  nothing beyond preserving notices.

The reason for that obligation is stated plainly in ADR-0007: the coordination
server holds per-pair PSKs and computes every node's packet filter. If your
operator runs a modified server you cannot inspect, you cannot verify the most
security-critical component in the system. AGPL turns "trust your operator"
into "verify your operator."

## Contributing

All repositories use the **Developer Certificate of Origin**. There is no CLA
and no copyright assignment. Sign off your commits:

```
git commit -s
```

which appends `Signed-off-by: Your Name <you@example.com>`, certifying you have
the right to submit the work under the file's existing license. That is the
whole process.

We do not ask contributors to sign over rights, and as a consequence the
project cannot unilaterally relicense. That constraint is intentional.

## Dependency policy

CI enforces a license allowlist via `cargo deny` and `go-licenses`.

- **Permitted:** MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, Zlib,
  Unicode-DFS-2016, CC0-1.0.
- **Permitted in `server/` and `web/` only:** MPL-2.0, LGPL-3.0.
- **Rejected everywhere:** GPL-2.0, GPL-3.0, AGPL, SSPL, BUSL, CC-BY-NC, and
  any source-available or non-commercial license.

A GPL dependency reaching the MIT/Apache crates would compromise both App Store
and kernel-datapath viability, which is why this is a CI gate rather than a
review convention.

## Adding license texts

Canonical texts belong in `LICENSES/` and must be fetched from
[SPDX](https://spdx.org/licenses/) or gnu.org, never transcribed by hand:

```sh
mkdir -p LICENSES
curl -o LICENSES/MIT.txt         https://spdx.org/licenses/MIT.txt
curl -o LICENSES/Apache-2.0.txt  https://spdx.org/licenses/Apache-2.0.txt
curl -o LICENSES/AGPL-3.0.txt    https://www.gnu.org/licenses/agpl-3.0.txt
curl -o LICENSES/CC-BY-4.0.txt   https://spdx.org/licenses/CC-BY-4.0.txt
```

## Trademark

The Karst name and logo are held separately from the copyright license.
Anyone may fork the code; nobody may call their fork Karst. A trademark
usage policy will accompany the first public release.

> **Unresolved:** the project name is subject to a pending trademark search and
> at least one apparent collision in this product category. Assume a rename
> before public launch. See PLAN.md §13 Q5.

## Export and import

Publishing cryptographic source code requires a notification to BIS and NSA
under EAR 740.13(e). Separately, VPN software faces import or use restrictions
in some jurisdictions, including France, China, and Russia. Neither affects the
license; both are release-checklist items.
