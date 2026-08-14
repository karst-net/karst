#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright the Karst contributors.
#
# Run govulncheck over the control plane and fail on any vulnerability our code
# actually calls.
#
# The stock action cannot express an exception, and the fork has one that
# cannot be fixed by upgrading: see ALLOWED below. Rather than drop the check
# — in the component that holds every per-pair PSK — this gates on the
# symbol-level findings and names the exceptions individually.
#
# Two properties, both deliberate:
#
#   * Only *called* vulnerabilities fail the build. govulncheck also reports
#     what is merely imported or required; in a 240-line go.mod inherited from
#     upstream that is noise nobody can act on, and a gate that always fails is
#     a gate that gets switched off.
#
#   * A stale exception is itself a failure. When upstream fixes one of these,
#     the entry stops matching and CI says so, instead of carrying a
#     now-pointless exemption forever. An allowlist nobody revisits is how a
#     real vulnerability ends up permanently suppressed.
#
# Usage: scripts/govulncheck.sh [dir]

set -uo pipefail

dir="${1:-server}"

# Vulnerability IDs we accept, each with the reason it cannot be fixed here.
#
# GO-2026-4887  Moby AuthZ plugin bypass on oversized request bodies
# GO-2026-4883  Moby off-by-one in plugin privilege validation
#
#   Both reach us through testcontainers-go -> github.com/docker/docker, and
#   only from management/server/testutil, which spins up a Postgres container
#   for upstream's store tests. They are not on any path the coordination
#   server takes at run time.
#
#   Neither has a fixed version in github.com/docker/docker: the advisories
#   record a fix only in github.com/moby/moby/v2 >= 2.0.0-beta.8, a module
#   rename. Migrating to it is testcontainers-go's change to make, not
#   something a version bump here can reach.
#
#   Both are also flaws in the Docker *daemon's* handling of authz plugins,
#   which requires running a daemon so configured — not a consequence of
#   linking the client library into a test helper.
ALLOWED="GO-2026-4887 GO-2026-4883"

report="$(mktemp)"
trap 'rm -f "$report"' EXIT

( cd "$dir" && govulncheck -format json ./... ) > "$report"
status=$?
if [ "$status" -ne 0 ]; then
    echo "::error::govulncheck exited $status"
    tail -20 "$report"
    exit 1
fi
if [ ! -s "$report" ]; then
    echo "::error::govulncheck produced no output — nothing was scanned"
    exit 1
fi

ALLOWED="$ALLOWED" python3 - "$report" <<'PY'
import json, os, sys

decoder = json.JSONDecoder()
raw = open(sys.argv[1]).read().strip()
objs, i = [], 0
while i < len(raw):
    obj, i = decoder.raw_decode(raw, i)
    objs.append(obj)
    while i < len(raw) and raw[i] in " \n\t\r":
        i += 1

osv = {o["osv"]["id"]: o["osv"] for o in objs if "osv" in o}

# A finding is "called" when its trace names a function in our own build,
# rather than merely recording that the module is in the graph.
called = {}
for o in objs:
    f = o.get("finding")
    if not f:
        continue
    trace = f.get("trace") or []
    if trace and trace[0].get("function"):
        called.setdefault(f["osv"], set()).add(trace[0].get("module", "?"))

allowed = set(os.environ["ALLOWED"].split())
unexpected = sorted(set(called) - allowed)
stale = sorted(allowed - set(called))

def summary(vid):
    return (osv.get(vid, {}).get("summary") or "").strip()

for vid in unexpected:
    print(f"::error::{vid} is called by our code — {summary(vid)}")
    for mod in sorted(called[vid]):
        print(f"    module: {mod}")
    print(f"    https://pkg.go.dev/vuln/{vid}")

for vid in stale:
    print(f"::error::{vid} is allowlisted in scripts/govulncheck.sh but is no "
          "longer reported. Remove the exception.")

if unexpected or stale:
    sys.exit(1)

print(f"govulncheck: no called vulnerabilities outside the "
      f"{len(allowed)} documented exceptions.")
PY
