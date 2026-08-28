#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright the Karst contributors.
#
# Fail if any binary needs a newer glibc than the oldest distribution Karst
# claims to support.
#
#   scripts/glibc-floor.sh 2.34 dist/karstd dist/karst …
#
# ## Why this is a gate and not a comment
#
# A dynamically linked binary records the *highest* symbol version it uses, and
# nothing about building it says which distributions it will refuse to start
# on. The failure appears at `dpkg -i` + first run — on someone else's machine,
# after the release — as:
#
#   /usr/bin/karstd: /lib/../libc.so.6: version `GLIBC_2.39' not found
#
# The packages install cleanly first, so no packaging check catches it either.
# `packages-verify` does catch it, by running the binary on each distribution,
# but that is eight container jobs and a fifteen-minute round trip. This is the
# same fact asserted in one second, next to the compiler that decided it, so a
# change of build image fails in the job that made the change.
#
# The floor is 2.34: RHEL 9 and its rebuilds, which is the oldest of the four
# distributions in plans/phase-5/09-exit-criteria.md §2. Debian 12 is 2.36,
# Ubuntu 24.04 is 2.39, Fedora 41 is 2.40 — all forward-compatible with a
# binary linked against 2.34.

set -euo pipefail

floor=${1:?usage: scripts/glibc-floor.sh FLOOR BINARY...}
shift
[ $# -gt 0 ] || { echo "glibc-floor: no binaries given" >&2; exit 2; }

# `sort -V` orders 2.9 before 2.34, which a lexical compare gets backwards —
# the reason this is a script and not a `grep` in a workflow.
newest_of() { printf '%s\n%s\n' "$1" "$2" | sort -V | tail -1; }

status=0
for binary in "$@"; do
  if [ ! -f "$binary" ]; then
    echo "glibc-floor: $binary: not found" >&2
    status=1
    continue
  fi

  # A statically linked binary has no dynamic symbol table to read, and needs
  # no floor: nothing to report is the correct answer, not an error.
  if ! versions=$(objdump -T "$binary" 2>/dev/null | grep -o 'GLIBC_[0-9.]*' | sed 's/^GLIBC_//' | sort -u -V); then
    versions=""
  fi
  if [ -z "$versions" ]; then
    printf '  %-24s no glibc version references\n' "$(basename "$binary")"
    continue
  fi

  highest=$(printf '%s\n' "$versions" | tail -1)
  if [ "$(newest_of "$floor" "$highest")" = "$floor" ]; then
    printf '  %-24s needs glibc %s (floor %s)\n' "$(basename "$binary")" "$highest" "$floor"
  else
    printf '  %-24s needs glibc %s, ABOVE the %s floor\n' "$(basename "$binary")" "$highest" "$floor"
    echo "::error file=$binary::built against glibc $highest; it will not start on a distribution older than that. Build on the oldest supported base image."
    status=1
  fi
done

exit "$status"
