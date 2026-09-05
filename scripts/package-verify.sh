#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright the Karst contributors.
#
# Install, upgrade and uninstall the Linux node package on the distribution
# this script is running on, asserting the whole way through.
#
# plans/phase-5/09-exit-criteria.md §2 is explicit that package *definitions*
# are not a published installer experience: the gate is "produce packages in
# CI, install/upgrade/uninstall them on each documented distribution". This is
# that check, written once and run per-distribution from a container, because
# the things it catches — a binary that will not start under an older glibc, a
# daemon that survives its own package, an upgrade that disables a service the
# admin enabled — are invisible to the build that produced the package.
#
#   scripts/package-verify.sh OLD_DIR NEW_DIR
#
# where each directory holds one karst-client-linux package (.deb or .rpm) and NEW is
# a higher version than OLD. Run it as root, in a throwaway machine or
# container: it installs packages and writes under /etc and /var.
#
# Deliberately driven by `dpkg`/`rpm` and not by `apt`/`dnf`. The packages
# declare no dependencies, so a local install needs no repository, and reaching
# for a package manager that wants the network turns a packaging test into a
# mirror-availability test.

set -euo pipefail

old_dir=${1:?usage: scripts/package-verify.sh OLD_DIR NEW_DIR}
new_dir=${2:?usage: scripts/package-verify.sh OLD_DIR NEW_DIR}

distro=$( (. /etc/os-release && echo "$PRETTY_NAME") 2>/dev/null || echo "unknown")
failures=0
checks=0

pass() { checks=$((checks + 1)); printf '  ok    %s\n' "$1"; }
fail() { checks=$((checks + 1)); failures=$((failures + 1)); printf '  FAIL  %s\n' "$1"; }

# An assertion helper rather than `set -e` on each check: one broken
# expectation should not hide the twelve after it. The script's exit status is
# the count of failures, so CI still goes red.
want() {
  local description=$1
  shift
  if "$@" >/dev/null 2>&1; then pass "$description"; else fail "$description"; fi
}

want_not() {
  local description=$1
  shift
  if "$@" >/dev/null 2>&1; then fail "$description"; else pass "$description"; fi
}

want_mode() {
  local path=$1 expected=$2
  local actual
  actual=$(stat -c '%a' "$path" 2>/dev/null || echo missing)
  if [ "$actual" = "$expected" ]; then
    pass "$path is mode $expected"
  else
    fail "$path is mode $actual, expected $expected"
  fi
}

section() { printf '\n== %s\n' "$1"; }

if [ "$(id -u)" -ne 0 ]; then
  echo "package-verify: must run as root" >&2
  exit 2
fi

# ── Which package manager, and the one package under test ───────────────────

if command -v dpkg >/dev/null 2>&1; then
  family=deb
elif command -v rpm >/dev/null 2>&1; then
  family=rpm
else
  echo "package-verify: neither dpkg nor rpm on PATH" >&2
  exit 2
fi

find_package() {
  local dir=$1 found
  found=$(find "$dir" -maxdepth 1 -name "karst-client-linux*.$family" | head -1)
  [ -n "$found" ] || { echo "package-verify: no karst-client-linux .$family in $dir" >&2; exit 2; }
  echo "$found"
}

old_package=$(find_package "$old_dir")
new_package=$(find_package "$new_dir")

install_package() {
  case $family in
    deb) dpkg --install "$1" ;;
    # -U rather than -i so the same call serves install and upgrade, which is
    # what an operator following the docs would run either way.
    rpm) rpm --upgrade --verbose "$1" ;;
  esac
}

remove_package() {
  case $family in
    deb) dpkg --remove karst-client-linux ;;
    rpm) rpm --erase karst-client-linux ;;
  esac
}

installed_version() {
  case $family in
    deb) dpkg-query --showformat='${Version}' --show karst-client-linux ;;
    rpm) rpm --query --queryformat '%{VERSION}-%{RELEASE}' karst-client-linux ;;
  esac
}

echo "package-verify: $distro ($family)"
echo "  old: $(basename "$old_package")"
echo "  new: $(basename "$new_package")"

# ── 1. A clean install ──────────────────────────────────────────────────────

section "install"
if ! install_package "$old_package"; then
  echo "package-verify: the install itself failed; nothing after this is meaningful" >&2
  exit 1
fi
pass "the package installs"

want "karstd is installed"        test -x /usr/bin/karstd
want "karst is installed"         test -x /usr/bin/karst
want "the systemd unit ships"     test -f /usr/lib/systemd/system/karstd.service
want "/etc/karst exists"          test -d /etc/karst
want "/var/lib/karst exists"      test -d /var/lib/karst

# The netmap cache lives here and it holds a pre-shared key per peer
# (THREAT-MODEL R5), so this directory being group- or world-readable is a
# disclosure, not an untidiness.
want_mode /var/lib/karst 700

# ── 2. The binaries actually run on this distribution ───────────────────────
#
# The check that a build machine cannot make for itself. A release binary
# linked against the builder's glibc fails here with "version `GLIBC_2.39' not
# found" on every distribution older than the builder, and the package installs
# perfectly first.

section "the binaries run here"
want "karstd --help runs"         /usr/bin/karstd --help
want "karst --help runs"          /usr/bin/karst --help

key=$(/usr/bin/karstd genkey 2>/dev/null || true)
# 64 bytes of hex seed for ML-KEM-1024. Measured with
# ${#key} rather than `wc -c`, which right-pads on some userlands and would
# match a zero-length key against a naive pattern.
if [ "${#key}" -eq 128 ]; then
  pass "karstd genkey produces a ${#key}-character key"
else
  fail "karstd genkey produced ${#key} characters, expected 128"
fi

# ── 3. The service is not started for an unconfigured machine ───────────────
#
# Asserted through the enablement symlink rather than `systemctl is-enabled`,
# so it means the same thing in a container with no PID 1 as it does on a
# running system. A package that enables a daemon with no configuration gives
# the admin a restart loop as their first impression of the product.

section "not enabled without a configuration"
wants=/etc/systemd/system/multi-user.target.wants/karstd.service
want_not "the unit is not enabled"      test -L "$wants"
want_not "karstd check fails with no configuration" \
  /usr/bin/karstd check --config /etc/karst/karstd.toml

# ── 4. A configured node validates ──────────────────────────────────────────

section "a configured node validates"
umask 077
# `|| true` because a binary that cannot start on this distribution has already
# been reported above, and aborting here would hide the upgrade and removal
# results — which are the parts of the run that are still meaningful when the
# binary is the thing that is broken.
/usr/bin/karstd genkey > /etc/karst/node.key 2>/dev/null || true
chmod 600 /etc/karst/node.key
cat > /etc/karst/karstd.toml <<'CONFIG'
[node]
listen = "0.0.0.0:51820"
interface = "karst0"
addresses = ["10.77.0.1/24"]
private_key_file = "/etc/karst/node.key"
CONFIG
want "karstd check accepts the configuration" \
  /usr/bin/karstd check --config /etc/karst/karstd.toml

config_before=$(sha256sum /etc/karst/karstd.toml | cut -d' ' -f1)
key_before=$(sha256sum /etc/karst/node.key | cut -d' ' -f1)

# Enable it by hand, the way an admin would, so the upgrade below is tested
# against a machine that is actually running the service rather than a fresh
# one. `systemctl enable` needs a live PID 1; the symlink is what it writes.
mkdir -p "$(dirname "$wants")"
ln -sf /usr/lib/systemd/system/karstd.service "$wants"

# ── 5. Upgrade ──────────────────────────────────────────────────────────────

section "upgrade"
before=$(installed_version)
if ! install_package "$new_package"; then
  echo "package-verify: the upgrade failed" >&2
  exit 1
fi
after=$(installed_version)
if [ "$before" != "$after" ]; then
  pass "version moved $before -> $after"
else
  fail "version did not change: still $before"
fi

want "karstd still runs after the upgrade"  /usr/bin/karstd --help
want_mode /var/lib/karst 700

if [ "$(sha256sum /etc/karst/karstd.toml | cut -d' ' -f1)" = "$config_before" ]; then
  pass "the upgrade left karstd.toml untouched"
else
  fail "the upgrade rewrote karstd.toml"
fi
if [ "$(sha256sum /etc/karst/node.key | cut -d' ' -f1)" = "$key_before" ]; then
  pass "the upgrade left the node key untouched"
else
  fail "the upgrade rewrote the node key"
fi
want_mode /etc/karst/node.key 600

# The regression that bites real deployments: an upgrade that quietly disables
# a service the admin turned on, so the node comes back after the next reboot
# and not before.
want "the upgrade kept the service enabled" test -L "$wants"

# ── 6. Removal ──────────────────────────────────────────────────────────────

section "removal"
if ! remove_package; then
  echo "package-verify: removal failed" >&2
  exit 1
fi
pass "the package removes"

want_not "karstd is gone"          test -e /usr/bin/karstd
want_not "karst is gone"           test -e /usr/bin/karst
want_not "the unit file is gone"   test -e /usr/lib/systemd/system/karstd.service
want_not "the unit is no longer enabled" test -L "$wants"

# Removal is not purge. An operator who removes the package to reinstall it
# must not lose the node identity — re-enrolling every machine is a far worse
# outcome than a directory left behind.
want "the configuration survives removal"  test -f /etc/karst/karstd.toml
want "the node key survives removal"       test -f /etc/karst/node.key

# ── Result ──────────────────────────────────────────────────────────────────

printf '\n%s: %d checks, %d failed\n' "$distro" "$checks" "$failures"
[ "$failures" -eq 0 ]
