<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Contributing to Karst

## Sign off your commits

Karst uses the **Developer Certificate of Origin**. There is no CLA and no
copyright assignment.

```sh
git commit -s
```

That appends `Signed-off-by: Your Name <you@example.com>`, certifying you have
the right to submit the work under the file's existing license. CI enforces it
on every commit in a pull request.

We do not ask contributors to sign over rights, and as a consequence the
project cannot unilaterally relicense. That constraint is intentional —
[ADR-0007](docs/adr/0007-licensing.md).

## Before you start

- Read [PLAN.md](PLAN.md) for where the work is going, and
  [docs/adr/](docs/adr/) for why things are the way they are.
- Significant changes need an ADR. Copy `docs/adr/TEMPLATE.md`. An ADR that
  lists only benefits is not finished — record the costs and what you rejected.
- **Do not open a public issue for a security bug.** See [SECURITY.md](SECURITY.md).

## Checks

```sh
just check
```

Runs formatting, clippy with `-D warnings`, tests, the dependency license
allowlist, and SPDX header verification. CI additionally runs secret scanning,
`govulncheck`, and the formal models.

## Editing the deployment walkthrough

[docs/GETTING-STARTED.md](docs/GETTING-STARTED.md) is executed, not just read:
CI extracts its commands and runs paths A, B and C against a real deployment
(`just walkthrough-a`, `-b`, `-c`). So every fenced block in that file carries
a tag saying which path it belongs to, and CI rejects one that does not:

````
```sh walkthrough=A step=genkey
```toml walkthrough=B,C step=node-config file=/etc/karst/karstd.toml
```sh walkthrough=none reason="needs an identity provider"
````

If a block cannot run — a diagram, a prerequisite the runner already has, a
command that waits for Ctrl-C — tag it `walkthrough=none` with a reason. That
is not a way out; it is the record of what the walkthrough does not cover,
kept next to the thing it does not cover. `just walkthrough-tags` checks this
in a second, and `scripts/getting-started-blocks.py` documents the grammar.

Values a reader has to paste in are written as ellipses (`server_kem_pin =
"…2368 hex characters…"`). The runner resolves each from the step that
produces it, so a *new* field written that way fails loudly, naming the field,
rather than being written into a config file as a literal `…`.

## Things CI will reject

- A commit without `Signed-off-by`.
- A source file without an `SPDX-License-Identifier` in its first three lines.
- A fenced block in `docs/GETTING-STARTED.md` with no `walkthrough=` tag.
- A dependency outside the license allowlist in `deny.toml`. A GPL dependency
  in the Rust crates would break both iOS App Store and kernel-datapath
  viability — this is a hard gate, not a preference.
- Anything gitleaks flags. Netmaps carry per-pair PSKs and TURN credentials;
  secret leakage into logs and diagnostics is a tracked residual risk
  (THREAT-MODEL.md R5), which is why the scan runs on every commit rather
  than once.

## Licenses by path

`crates/` and `bins/` are `MIT OR Apache-2.0`. `server/` and `web/` are
`AGPL-3.0-or-later`. `spec/` and `docs/` are `CC-BY-4.0`. Match the file you
are editing.
