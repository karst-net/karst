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
test-privileged: test-tun test-karstd test-userspace test-dns test-nat-matrix test-portmap test-aquifer

test-tun:
    @just _privileged karst-tun device

# ── macOS ───────────────────────────────────────────────────────────────────
#
# The macOS client, from a Mac. Nothing here runs on Linux: `utun`, `ifconfig`,
# `lipo` and `pkgbuild` have no counterparts, and CI's `macos` job is the only
# other place these run.

# Everything the `macos` CI job does, minus the privileged suite.
macos-check:
    cargo clippy --workspace --all-targets --all-features --target aarch64-apple-darwin -- -D warnings
    cargo check --workspace --all-targets --all-features --target x86_64-apple-darwin
    cargo test --workspace --all-features

# Real utun devices. Needs root, and takes one interface per test.
macos-test-utun:
    @just _privileged karst-tun utun

# The universal .pkg. Signed and notarized only if the credentials are in the
# environment — see the script's header for which ones.
macos-package:
    ./scripts/build-macos-pkg.sh

test-karstd:
    @just _privileged karstd two_nodes

# ADR-0012's release gate. Root is for the *peer's* TUN device; the node under
# test is launched with a non-root uid and an empty capability bounding set, and
# the suite reads /proc back to prove it.
test-userspace:
    @just _privileged karstd userspace

# KarstDNS's real-host integration suite. It is ignored by default because it
# changes a temporary network namespace's resolver state and requires the
# platform resolver services to be installed there.
test-dns:
    @just _privileged karstd dns_host

# The whole stack: coordination server, relay, and two daemons in namespaces,
# from first enrolment to a direct path carrying TCP under an ACL.
#
# Needs a Go toolchain as well as CAP_NET_ADMIN, and `sudo` resets PATH, so the
# environment is passed through explicitly rather than relying on it surviving.
test-aquifer:
    #!/usr/bin/env bash
    set -euo pipefail
    cargo build --workspace
    bin=$(cargo test -p karstd --test aquifer --no-run --message-format=json 2>/dev/null \
          | grep -o "\"executable\":\"[^\"]*aquifer[^\"]*\"" | head -1 | cut -d'"' -f4)
    [ -n "$bin" ] || { echo "could not locate the aquifer test binary"; exit 1; }
    sudo env "PATH=$PATH" "$bin" --ignored --test-threads=1 --nocapture

# The port-mapping codec against miniupnpd, an implementation we did not write
# (PLAN.md §6). A round-trip test proves the encoder and decoder agree with each
# other; this proves they agree with RFC 6886 and RFC 6887. Needs `miniupnpd`.
test-portmap:
    cargo build -p karst-portmap --example pmprobe
    @just _privileged karst-portmap gateway

# The NAT matrix (PLAN.md §6). These validate the *instrument*: that each
# topology behaves the way its name says, using examples/natprobe.rs and no
# Karst code. A matrix whose "symmetric" NAT is quietly endpoint-independent
# would produce a confident direct-connection rate that means nothing.
test-nat-matrix:
    cargo build -p karst-disco --example natprobe
    @just _privileged karst-disco nat_matrix

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

# Regenerate Karst's isolated API models from its contract. The generated
# package intentionally does not share the fork's api package: both documents
# define common names such as User and bearer-auth helpers.
api-generate-karst:
    cd server/shared/management/http/api && ./generate-karst.sh

# Contract mock with a fifty-node account, mixed posture, two relay states,
# Bedrock data, and a deliberately broken audit-chain verification result.
api-mock:
    node web/tools/karst-api-mock.mjs

api-client-check:
    cd web/packages/api-client && npm run check

# ── Web ─────────────────────────────────────────────────────────────────────
web-install:
    cd web && corepack pnpm install --frozen-lockfile

web-check:
    cd web && corepack pnpm -r exec tsc --noEmit && corepack pnpm -r lint

# ── Licences ────────────────────────────────────────────────────────────────
licenses:
    ./scripts/fetch-licenses.sh

# Every source file Karst *writes* must carry an SPDX identifier (ADR-0007).
#
# `server/` is 586 files of vendored NetBird and they are deliberately not
# checked. Two reasons, either sufficient:
#
#   - Those files are BSD-3-Clause and somebody else's copyright. Stamping
#     `AGPL-3.0-or-later` on them would be a false licence claim on code we did
#     not write; stamping BSD-3 on them would be editing it to say what it
#     already says. What BSD-3 actually requires is notice retention, and that
#     lives in server/LICENSE-NETBIRD-BSD-3 and server/LICENSES/.
#   - Editing 586 forked files would forfeit the property the fork is kept for.
#     Spike 0001 §5.3 measured 28% of upstream commits landing on the files we
#     would then be diverging on, every one of them a future conflict on a
#     cherry-picked security fix. server/README.md's "no forked .go file has
#     been modified" is worth more than a header on a file nobody here wrote.
#
# Karst's own server code all lives under a `karst` path — that is the point of
# the layout described in server/README.md — so that is the include rule here.
# Code Karst adds elsewhere under server/ has already broken that invariant and
# wants moving, not stamping.
licenses-check:
    #!/usr/bin/env bash
    set -euo pipefail
    missing=0
    while IFS= read -r f; do
        head -3 "$f" | grep -q 'SPDX-License-Identifier' || { echo "missing SPDX: $f"; missing=1; }
    done < <(
        find crates bins web -type f \( -name '*.rs' -o -name '*.go' -o -name '*.ts' -o -name '*.tsx' \) -not -path '*/node_modules/*' 2>/dev/null
        find server -type f -path '*karst*' \( -name '*.go' -o -name '*.proto' \) 2>/dev/null
    )
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
