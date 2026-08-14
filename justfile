# Karst — task runner.  `just` with no arguments lists targets.

default:
    @just --list

# ── everything CI runs, locally ─────────────────────────────────────────────
check: fmt-check lint test deny licenses-check
    @echo "All checks passed."

# ── Rust ────────────────────────────────────────────────────────────────────
fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all -- --check

lint:
    cargo clippy --workspace --all-targets --all-features -- -D warnings

test:
    cargo test --workspace --all-features

# Tests needing CAP_NET_ADMIN: TUN devices and two-daemon network namespaces.
# Build unprivileged, then run the test binary under sudo — `sudo cargo` would
# not find the rustup toolchain, and building as root would leave root-owned
# artefacts in target/.
#
# Single-threaded: these create interfaces and namespaces with fixed names.
test-privileged: test-tun test-karstd

test-tun:
    @just _privileged karst-tun device

test-karstd:
    @just _privileged karstd two_nodes

_privileged package target:
    #!/usr/bin/env bash
    set -euo pipefail
    # The whole workspace, not just the package under test: `two_nodes` drives
    # the `karst` CLI, which lives in a *different* package and which
    # `cargo test -p karstd` therefore never builds. Cargo has no stable way to
    # express "this test needs that binary", so the build is widened here.
    cargo build --workspace
    bin=$(cargo test -p {{package}} --test {{target}} --no-run --message-format=json 2>/dev/null \
          | grep -o "\"executable\":\"[^\"]*{{target}}[^\"]*\"" | head -1 | cut -d'"' -f4)
    [ -n "$bin" ] || { echo "could not locate the {{target}} test binary"; exit 1; }
    sudo "$bin" --ignored --test-threads=1

# Dependency licence allowlist + advisories (LICENSING.md, ADR-0007).
#
# Install cargo-deny with the *stable* toolchain, not the pinned one:
#   cargo +stable install cargo-deny --locked
# The advisory database now carries CVSS 4.0 scores, which older cargo-deny
# cannot parse — it fails to load the database entirely rather than skipping the
# entry, so an out-of-date tool silently stops checking advisories at all.
deny:
    cargo deny check

fuzz target:
    cargo +nightly fuzz run {{target}}

# ── Go control plane ────────────────────────────────────────────────────────
go-lint:
    cd server && go vet ./... && staticcheck ./...

go-test:
    cd server && go test ./...

go-vuln:
    cd server && govulncheck ./...

# ── Web ─────────────────────────────────────────────────────────────────────
web-install:
    cd web && pnpm install --frozen-lockfile

web-check:
    cd web && pnpm -r exec tsc --noEmit && pnpm -r lint

# ── Licences ────────────────────────────────────────────────────────────────
licenses:
    ./scripts/fetch-licenses.sh

# Every source file must carry an SPDX identifier (ADR-0007).
licenses-check:
    #!/usr/bin/env bash
    set -euo pipefail
    missing=0
    while IFS= read -r f; do
        head -3 "$f" | grep -q 'SPDX-License-Identifier' || { echo "missing SPDX: $f"; missing=1; }
    done < <(find crates bins server web -type f \( -name '*.rs' -o -name '*.go' -o -name '*.ts' -o -name '*.tsx' \) -not -path '*/node_modules/*' 2>/dev/null)
    [ "$missing" -eq 0 ] && echo "SPDX headers OK"

# ── Secrets ─────────────────────────────────────────────────────────────────
# Netmaps carry per-pair PSKs and TURN credentials (§2.6, THREAT-MODEL R5).
# This runs continuously, not once — leaks are reintroduced by ordinary
# debugging changes.
secrets-scan:
    gitleaks detect --no-banner --redact --verbose

# ── Formal models (PLAN.md §2.5) ────────────────────────────────────────────
verify:
    #!/usr/bin/env bash
    set -euo pipefail
    for m in phreatic phreatic-kem-broken phreatic-dh-broken; do
        echo "── $m ──"
        verifpal verify "spec/models/$m.vp" | tail -12
    done
    ./spec/models/gen-variants.sh
    echo "── ProVerif (PHREATIC data plane) ──"
    ./spec/models/check-proverif.sh spec/models/phreatic.pv 1500 4
    echo "── ProVerif (KARST-CONTROL control channel, ADR-0011) ──"
    ./spec/models/check-proverif.sh spec/models/karst-control.pv 600 4
    echo "── ProVerif (Ponor relay, spec/ponor-v1.md §5) ──"
    ./spec/models/check-proverif.sh spec/models/ponor.pv 600 4
    echo "── ProVerif (AVEN path discovery, spec/aven-v1.md §7) ──"
    ./spec/models/check-proverif.sh spec/models/aven.pv 600 4
    echo "── ProVerif (models that must FAIL) ──"
    ./spec/models/check-proverif.sh spec/models/karst-control-nofs.pv 600 2 2
    ./spec/models/check-proverif.sh spec/models/ponor-norelayid.pv 600 2 2
    ./spec/models/check-proverif.sh spec/models/aven-headeronly.pv 600 2 2

# Broken-primitive ProVerif variants: minutes to hours. Nightly, not per-commit.
verify-slow:
    #!/usr/bin/env bash
    set -euo pipefail
    ./spec/models/gen-variants.sh
    for m in phreatic-kem-broken phreatic-dh-broken; do
        echo "── $m ──"
        proverif "spec/models/$m.pv" | sed -n '/Verification summary/,$p'
    done
    # The must-fail variants moved to `just verify`: both run in seconds, and
    # a demonstration nobody runs per-commit is one that rots.
