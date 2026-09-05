#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright the Karst contributors.
#
# Run the packaged node agent under a real systemd: start it, kill it the way a
# crash would, and prove the unit's DNS recovery hook fired from the paths the
# package actually installed to.
#
#   scripts/package-systemd-verify.sh PACKAGE_DIR
#
# Needs PID 1 to be systemd and root to install. In CI this runs on the runner
# itself; locally, a privileged container booted on /lib/systemd/systemd does
# the same job without touching the developer's resolver.
#
# ## What this proves, and what it does not
#
# It does **not** re-test host DNS apply and revert. That mechanism has its own
# coverage: `bins/karstd/tests/dns_host.rs` SIGKILLs a daemon and asserts the
# host file comes back, and the aquifer suite drives the whole path from a real
# netmap. Host integration only engages when the control plane turns MagicDNS
# on, so a package test with no coordination server cannot reach it at all —
# and a test that asserts "DNS reverted" where DNS was never applied is one
# that cannot fail, which is finding 47 all over again.
#
# What it proves is the wiring that only exists once the package is installed:
#
#   - `ExecStopPost=` names a binary that the package actually put there.
#     `deploy/systemd/karstd.service` and `packaging/systemd/karstd.service`
#     differ by exactly this — /usr/local/bin against /usr/bin — and the unit
#     swallows the difference, because the leading `-` makes a failed revert
#     non-fatal by design. A wrong path here is silent forever, and its symptom
#     is a machine whose DNS stays broken after a crash.
#   - systemd runs that hook on an unclean exit, not just a clean stop.
#   - The documented manual recovery, `karst dns revert --config …`, works
#     against the installed layout.
#   - The revert record outlives a stop whose hook failed, which is the only
#     stop it exists for. GitHub issue [#67](https://github.com/karst-net/karst/issues/67): under `RuntimeDirectory=karst` it did
#     not, and every assertion about it here was one that could not fail.

set -euo pipefail

package_dir=${1:?usage: scripts/package-systemd-verify.sh PACKAGE_DIR}

failures=0
checks=0
pass() { checks=$((checks + 1)); printf '  ok    %s\n' "$1"; }
fail() { checks=$((checks + 1)); failures=$((failures + 1)); printf '  FAIL  %s\n' "$1"; }
want() { local d=$1; shift; if "$@" >/dev/null 2>&1; then pass "$d"; else fail "$d"; fi; }
section() { printf '\n== %s\n' "$1"; }

[ "$(id -u)" -eq 0 ] || { echo "package-systemd-verify: must run as root" >&2; exit 2; }
[ -d /run/systemd/system ] || { echo "package-systemd-verify: systemd is not the running init" >&2; exit 2; }

# Refused, not skipped, and with the reason.
#
# The DNS section below writes a known original to /etc/resolv.conf and asserts
# those exact bytes come back. Where /etc/resolv.conf is a symlink into
# systemd-resolved's own run directory, that write lands in a file resolved
# owns and regenerates, and it puts its own content back before the assertion
# runs — a failure that reads as "the resolver integration is broken" and is
# nothing of the kind. Use scripts/package-systemd-container.sh, which gives
# the check a resolver it owns.
#
# Exit 2, distinct from the 1 an assertion failure produces: this is the
# harness declining to produce a meaningless answer, not a defect in Karst.
if [ -L /etc/resolv.conf ] && case "$(readlink -f /etc/resolv.conf)" in
  /run/systemd/resolve/*) true ;; *) false ;;
esac then
  cat >&2 <<'REFUSED'
package-systemd-verify: /etc/resolv.conf is a symlink into systemd-resolved's
run directory, which resolved regenerates. This check needs a resolver file it
owns, or its DNS assertion reports a failure that is really resolved winning a
race. Run scripts/package-systemd-container.sh instead.
REFUSED
  exit 2
fi

package=$(find "$package_dir" -maxdepth 1 -name 'karst-client-linux*.deb' | head -1)
[ -n "$package" ] || { echo "package-systemd-verify: no karst-client-linux .deb in $package_dir" >&2; exit 2; }

section "install"
dpkg --install "$package"
pass "the package installs"
systemctl daemon-reload
want "systemd can load the unit" systemctl cat karstd.service

# ── The hook points at something that exists ────────────────────────────────

section "ExecStopPost"
unit=/usr/lib/systemd/system/karstd.service
hook=$(sed -n 's/^ExecStopPost=-\{0,1\}\([^ ]*\).*/\1/p' "$unit" | head -1)
if [ -n "$hook" ]; then
  pass "the unit declares ExecStopPost ($hook)"
else
  fail "the unit declares no ExecStopPost"
fi
# The whole point: the package must have installed the binary the unit names.
want "the hook binary is installed and executable" test -x "$hook"

# ── A configured node runs under the unit ───────────────────────────────────

section "start"
umask 077
/usr/bin/karstd genkey > /etc/karst/node.key 2>/dev/null
chmod 600 /etc/karst/node.key
cat > /etc/karst/karstd.toml <<'CONFIG'
[node]
listen = "0.0.0.0:51820"
interface = "karst0"
addresses = ["10.77.0.1/24"]
private_key_file = "/etc/karst/node.key"

[dns]
# Pinned rather than left on "auto". Auto prefers systemd-resolved, whose
# revert is scoped to a link that the kernel deletes along with the interface —
# so there would be nothing on disk for this test to look at afterwards. The
# bare-file mechanism is the one whose recovery is externally visible, and it
# is also the one that has to work on the hosts that have no resolved at all.
host_integration = "resolvconf"
CONFIG

systemctl start karstd.service || true
# `is-active` rather than a sleep: the unit is Type=simple, so systemd reports
# it active immediately and the question is whether it is *still* active a
# moment later, which is what a configuration error would change.
sleep 3
if [ "$(systemctl is-active karstd.service)" = "active" ]; then
  pass "the service is running"
else
  fail "the service is not running"
  journalctl -u karstd.service --no-pager -n 20 || true
fi

# ── The crash ───────────────────────────────────────────────────────────────
#
# SIGKILL, not `systemctl stop`. The daemon installs no signal handler and
# could not survive one here anyway, which is exactly why the recovery lives in
# the unit instead of in the process.

section "unclean exit"

# ## Standing in for the apply step, and why that is honest
#
# Host DNS is only touched once the control plane turns MagicDNS on
# (`bins/karstd/src/dns.rs`: `enabled = config.dns.enabled &&
# config.netmap_dns.magic_dns`), so a package test with no coordination server
# can never get the daemon to write `/etc/resolv.conf` by itself. What it can
# do is put the host into exactly the state a crashed daemon leaves behind —
# a replaced resolv.conf and the durable revert record beside it — and then
# prove the packaged unit cleans it up.
#
# The revert record's format is the one `karst_dns::host::resolvconf` writes:
# an 8-byte big-endian length, the original bytes, then the applied bytes. The
# code refuses to restore if the live file does not match `applied` byte for
# byte — someone else has edited it since, and clobbering that would be worse
# than leaving it — so the seeding below has to be exact.
#
# The half being stood in for is the apply. The half under test is the revert,
# and that is production code reached through the packaged unit's own hook.

state=/var/lib/karst/dns-revert
original=/etc/resolv.conf
mkdir -p /var/lib/karst

# A container runtime bind-mounts /etc/resolv.conf over the image's copy. The
# resolver integration replaces that file by writing a sibling and renaming it
# into place — the only way to swap a resolver configuration without a window
# where it is empty — and `rename(2)` onto a mount point is EBUSY. On a real
# machine the file is an ordinary file or a symlink and the rename is fine, so
# this is an artifact of running the test in a container.
#
# It is detached rather than skipped around. A check that quietly does nothing
# in the environment it usually runs in is finding 48, which reported success
# on every CI run for a fortnight while testing nothing.
if grep -q ' /etc/resolv.conf ' /proc/self/mountinfo 2>/dev/null; then
  echo "  note  /etc/resolv.conf is a bind mount; detaching it for this test"
  umount /etc/resolv.conf || {
    echo "::error::cannot detach the /etc/resolv.conf bind mount; run with --privileged"
    exit 2
  }
fi

# `Restart=on-failure` would bring the daemon back two seconds after the kill,
# and a restarted daemon runs the same recovery at startup that the stop hook
# runs. Both paths are real, but with both in play a passing test cannot say
# which one did the work — and the one under test here is the unit's hook,
# because that is the half that only exists once the package is installed. A
# runtime drop-in takes the restart out of the picture for this check alone; it
# lives under /run, so it evaporates with the machine.
mkdir -p /run/systemd/system/karstd.service.d
printf '[Service]\nRestart=no\n' > /run/systemd/system/karstd.service.d/zz-no-restart.conf
systemctl daemon-reload
systemctl restart karstd.service
sleep 2

# A known original, rather than whatever this machine happens to have. The
# assertion is "these exact bytes came back", and on a container image the
# file underneath the bind mount is frequently empty — which would compare
# equal to a failed restore that left an empty file behind.
printf 'nameserver 192.0.2.53\noptions edns0\n' > "$original"
saved=$(mktemp)
cp "$original" "$saved"

# A resolv.conf that points at a stub which is about to stop listening: the
# thing that makes every lookup on the machine fail if it survives the daemon.
applied=$(mktemp)
printf 'nameserver 100.100.100.100\nsearch karst.test\n' > "$applied"

be64() {
  local value=$1 index byte
  for index in 7 6 5 4 3 2 1 0; do
    byte=$(((value >> (index * 8)) & 255))
    # shellcheck disable=SC2059
    printf "\\$(printf '%03o' "$byte")"
  done
}
{ be64 "$(wc -c < "$saved")"; cat "$saved"; cat "$applied"; } > "$state"
cp "$applied" "$original"

# Restart= would bring the daemon straight back and re-apply, so the unit is
# stopped as a unit after the process is killed under it.
systemctl kill --signal=SIGKILL karstd.service
sleep 2
systemctl stop karstd.service >/dev/null 2>&1 || true

if journalctl -u karstd.service --no-pager -n 50 2>/dev/null | grep -qi 'Main process exited\|Failed with result'; then
  pass "systemd saw the process die"
else
  fail "systemd did not record an unclean exit"
fi

# The assertion the whole script exists for. If ExecStopPost names a binary
# that is not there, this is still the stub address and the machine cannot
# resolve anything.
if cmp -s "$original" "$saved"; then
  pass "the crash left the host resolver restored"
else
  fail "the host resolver was NOT restored after an unclean exit"
  printf '    expected: %s\n    actual:   %s\n' \
    "$(tr '\n' ' ' < "$saved")" "$(tr '\n' ' ' < "$original")"
fi
# This assertion could not fail until finding 62 was fixed. The record used to
# live under /run/karst, which the unit's own `RuntimeDirectory=` deletes on
# every stop — so "the record is gone" was true whether the hook had consumed it
# or never run at all, and it passed identically against a package with a
# deliberately broken hook path. Under StateDirectory= systemd removes nothing,
# so a surviving record now means exactly one thing: the revert did not happen.
want "the revert record was consumed" test ! -e "$state"

cp "$saved" "$original"
rm -f "$saved" "$applied"

# ── The documented manual recovery ──────────────────────────────────────────
#
# docs/GETTING-STARTED.md §6.3 tells an operator to run this by hand. It has to
# work against the installed layout, with no daemon running — which is the
# state a machine is in precisely when someone needs it.

section "manual recovery"
want "karst dns revert succeeds with no daemon running" \
  /usr/bin/karst dns revert --config /etc/karst/karstd.toml

# ── Recovery after the hook itself fails — GitHub issue [#67](https://github.com/karst-net/karst/issues/67) ───────────────────
#
# Every check above assumes ExecStopPost= worked. This one assumes it did not,
# which is the only situation the revert record exists for: a wrong binary path,
# a transient failure, a `systemctl stop` on a daemon that was already SIGKILLed.
# The unit's leading `-` makes all of those silent, so the record is the entire
# remaining description of what the host resolver used to be.
#
# The drop-in reproduces the wrong-path case exactly — an ExecStopPost that
# cannot run. An empty assignment first, because drop-ins append to Exec* lists
# rather than replacing them.

section "recovery after a failed hook"

mkdir -p /run/systemd/system/karstd.service.d
cat > /run/systemd/system/karstd.service.d/zz-broken-hook.conf <<'DROPIN'
[Service]
ExecStopPost=
ExecStopPost=-/nonexistent/karst dns revert --config /etc/karst/karstd.toml
DROPIN
systemctl daemon-reload
systemctl restart karstd.service
sleep 2

saved=$(mktemp)
applied=$(mktemp)
printf 'nameserver 192.0.2.53\noptions edns0\n' > "$saved"
printf 'nameserver 100.100.100.100\nsearch karst.test\n' > "$applied"
{ be64 "$(wc -c < "$saved")"; cat "$saved"; cat "$applied"; } > "$state"
cp "$applied" "$original"

systemctl kill --signal=SIGKILL karstd.service
sleep 2
systemctl stop karstd.service >/dev/null 2>&1 || true

# The finding itself. Under RuntimeDirectory= the record was deleted here, and
# the operator below had nothing left to recover from.
want "the revert record survives a stop whose hook failed" test -e "$state"

# And the record is worth surviving: the documented command has to actually put
# the resolver back, not merely exit 0 with nothing to do.
/usr/bin/karst dns revert --config /etc/karst/karstd.toml >/dev/null 2>&1 || true
if cmp -s "$original" "$saved"; then
  pass "the manual recovery restored the host resolver"
else
  fail "the manual recovery did NOT restore the host resolver"
  printf '    expected: %s\n    actual:   %s\n' \
    "$(tr '\n' ' ' < "$saved")" "$(tr '\n' ' ' < "$original")"
fi
want "the manual recovery consumed the record" test ! -e "$state"

rm -f /run/systemd/system/karstd.service.d/zz-broken-hook.conf
systemctl daemon-reload
cp "$saved" "$original"
rm -f "$saved" "$applied"

# ── Removal leaves nothing running ──────────────────────────────────────────

section "removal"
dpkg --remove karst-client-linux
systemctl daemon-reload
if systemctl is-active karstd.service >/dev/null 2>&1; then
  fail "the service is still running after removal"
else
  pass "no karstd is left running"
fi
want "the unit file is gone" test ! -e "$unit"

printf '\nsystemd: %d checks, %d failed\n' "$checks" "$failures"
[ "$failures" -eq 0 ]
