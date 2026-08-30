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
# artifacts in target/.
#
# Single-threaded: these create interfaces and namespaces with fixed names.
test-privileged: test-tun test-karstd test-userspace test-dns test-nat-matrix test-portmap test-aquifer

test-tun:
    @just _privileged karst-tun device

# ── Linux packaging ─────────────────────────────────────────────────────────
#
# The gate in plans/phase-5/09-exit-criteria.md §2 is an install on each
# documented distribution, not a package that builds. These recipes are the
# same checks CI runs, so a packaging change can be tried without a push.
#
# Both need Docker and `nfpm`; `packages` builds into dist/ and leaves the
# result there for the two verifiers.

# Build .deb and .rpm for this machine's architecture, plus the upgrade fixture.
packages version="0.0.1":
    #!/usr/bin/env bash
    set -euo pipefail
    arch=$(dpkg --print-architecture 2>/dev/null || rpm --eval '%{_arch}')
    mkdir -p dist/packages/old dist/packages/new
    for binary in karstd karst karst-relay; do
        install -m 0755 "target/release/$binary" "dist/$binary"
    done
    # The upgrade target is the same build under a higher version — "0.0.1.1"
    # sorts above "0.0.1" for both dpkg and rpm — because what is being tested
    # is the packaging's upgrade path, not a difference between two builds.
    for packager in deb rpm; do
        VERSION={{ version }} ARCH="$arch" nfpm package --packager "$packager" \
            --target dist/packages/old/ --config packaging/nfpm/karst-client.yaml
        VERSION={{ version }}.1 ARCH="$arch" nfpm package --packager "$packager" \
            --target dist/packages/new/ --config packaging/nfpm/karst-client.yaml
    done
    # Advisory here, fatal in CI. A developer on a current distribution cannot
    # produce a 2.34-floor binary without the release container, and refusing
    # to package theirs would only stop them testing the packaging — but the
    # older rows of `just packages-verify` are then going to fail on a glibc
    # symbol, and that is worth predicting rather than debugging (finding 59).
    if ! ./scripts/glibc-floor.sh 2.34 dist/karstd dist/karst dist/karst-relay; then
        echo
        echo "note: these binaries carry this machine's glibc, so 'just packages-verify'"
        echo "      will fail its Debian 12 and RHEL 9 rows on a missing symbol version."
        echo "      That is the local build showing, not the packaging. CI builds in"
        echo "      rockylinux:9 for exactly this reason."
    fi

# Install, upgrade and uninstall on every distribution the docs will claim.
packages-verify:
    #!/usr/bin/env bash
    set -euo pipefail
    # Every distribution runs even when an earlier one fails. One broken row
    # hiding the three behind it is how a packaging change gets fixed twice.
    failed=""
    for distro in debian:12 ubuntu:24.04 fedora:41 redhat/ubi9; do
        printf '\n──── %s\n' "$distro"
        docker run --rm -v "$PWD:/karst:ro" "$distro" \
            bash /karst/scripts/package-verify.sh \
                /karst/dist/packages/old /karst/dist/packages/new \
            || failed="$failed $distro"
    done
    if [ -n "$failed" ]; then
        printf '\nfailed on:%s\n' "$failed"
        exit 1
    fi
    printf '\nevery documented distribution installs, upgrades and uninstalls\n'

# Runs in a privileged container booted on systemd, rather than on this
# machine, because the check replaces /etc/resolv.conf and killing it half way
# through should not cost the developer their resolver.

# The packaged unit under a real systemd: start, SIGKILL, prove DNS recovered.
packages-verify-systemd:
    ./scripts/package-systemd-container.sh dist/packages/old

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

# Two daemons, one Mac, a real utun carrying TCP between them.
#
# macOS has no network namespaces, so this is not `two_nodes` — the pair is one
# utun node and one userspace node, which is the only two-daemon shape on a
# single host where the traffic cannot take a shortcut. The file explains why.
macos-test-pair:
    @just _privileged karstd macos_pair

# The same rows against *this* host's TUN device, wherever this host is.
#
# Everything the pair drives above the interface is the same code on every
# platform, so a Linux box with root can run it in half a second. That is how
# FINDINGS.md 69 was localised: the row passed here and failed on the macOS
# runner, which said the fault was the platform rather than the arrangement.
# Not the gate — `macos-test-pair` is.
macos-test-pair-here:
    #!/usr/bin/env bash
    set -euo pipefail
    cargo build --workspace
    bin=$(cargo test -p karstd --test macos_pair --no-run --message-format=json 2>/dev/null \
          | grep -o "\"executable\":\"[^\"]*macos_pair[^\"]*\"" | head -1 | cut -d'"' -f4)
    [ -n "$bin" ] || { echo "could not locate the macos_pair test binary"; exit 1; }
    sudo env "PATH=$PATH" KARST_PAIR_ON_HOST=1 "$bin" --ignored --test-threads=1 --nocapture

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
# from first enrollment to a direct path carrying TCP under an ACL.
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

# Dependency license allowlist + advisories (LICENSING.md, ADR-0007).
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

# ── The deployment walkthrough (docs/GETTING-STARTED.md) ────────────────────
#
# These run the *document's* commands, extracted from its tagged fenced blocks
# rather than copied here. Every other suite in this file tests the code; these
# test the surface a self-hoster touches, which until now nothing did — the
# aquifer fixture runs the Karst test server rather than `karst-control`, and
# no test has ever invoked `karstd genkey`, `bootstrap.sh`, or a systemd unit.
#
# `walkthrough-tags` is the anti-drift mechanism and costs seconds: a fenced
# block added to the walkthrough without a `walkthrough=` tag fails it, so a
# new step cannot quietly fall outside all of the below.
walkthrough-tags:
    ./scripts/getting-started-walkthrough.sh tags

# Two namespaces on a veth pair, standing in for §4's two hosts. Needs root.
walkthrough-a:
    sudo -E env "PATH=$PATH" ./scripts/getting-started-walkthrough.sh path-a

# **Destructive to the host.** Paths B and C install binaries into
# /usr/local/bin, write /etc/karst and /etc/netbird, and enable systemd units,
# because that is what the document tells a reader to do and running something
# adjacent to it would test something adjacent to it. Run them on a throwaway
# machine or a VM; CI runs them on a fresh runner.
walkthrough-b:
    sudo -E env "PATH=$PATH" ./scripts/getting-started-walkthrough.sh path-b

walkthrough-c:
    sudo -E env "PATH=$PATH" ./scripts/getting-started-walkthrough.sh path-c

# ── Licenses ────────────────────────────────────────────────────────────────
licenses:
    ./scripts/fetch-licenses.sh

# Every source file Karst *writes* must carry an SPDX identifier (ADR-0007).
#
# `server/` is 586 files of vendored NetBird and they are deliberately not
# checked. Two reasons, either sufficient:
#
#   - Those files are BSD-3-Clause and somebody else's copyright. Stamping
#     `AGPL-3.0-or-later` on them would be a false license claim on code we did
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
