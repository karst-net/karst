#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright the Karst contributors.
#
# ADR-0045 §4b's own guard, run outside the client: resolve every
# allowlisted region's provider anchor and fail if any two *different*
# regions resolve to the same address. That is the documented signature of
# an anchor moving behind anycast — the one way §4b's whole mechanism (a
# provider endpoint that is "physically inside that region," per the ADR)
# quietly stops being true without any client-side symptom at all, since a
# TCP handshake to a moved anchor still succeeds; it just no longer measures
# what it used to.
#
# Deliberately a standalone script, not a call into karstd: "none of these
# services exist to be probed... each can change," and the hostname
# templates below are **intentionally duplicated** from
# bins/karstd/src/anchor_probe.rs rather than shared with it. The whole
# point of this check is to catch drift regardless of its source, including
# a bug in anchor_probe.rs itself — sharing code with the thing being
# checked would defeat that.
#
# Usage:
#   scripts/check-anchor-addresses.sh [REGIONS_FILE]
#
# REGIONS_FILE is a KARST_ALLOWED_REGIONS_FILE-shaped JSON document (see
# server/management/internals/karst/regionallow/regionallow.go):
#
#   {"allowed_regions": {"aws": ["us-east-1", ...], "azure": [...], ...}}
#
# Defaults to scripts/testdata/anchor-regions-reference.json, a small,
# stable list of long-established region codes per provider — not every
# region either provider has, just enough known-good coverage to catch a
# provider-wide move. A real deployment's own KARST_ALLOWED_REGIONS_FILE can
# be passed instead to check exactly what that deployment actually probes.
#
# A region whose anchor does not resolve at all is logged and skipped, not a
# failure — the same "simply unmeasured" posture anchor_probe.rs itself
# takes, and the reason this script's exit status reports shared addresses
# found, never resolution failures.

set -uo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
regions_file="${1:-$script_dir/testdata/anchor-regions-reference.json}"

if [ ! -r "$regions_file" ]; then
    echo "::error::cannot read regions file: $regions_file" >&2
    exit 1
fi
for tool in jq getent; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "::error::$tool is required" >&2
        exit 1
    fi
done

# This provider's anchor hostname for $1=provider $2=region, echoed to
# stdout, or nothing for a provider this check does not (yet) cover — mirrors
# anchor_probe::anchor_hostname's own arms and its own doc comment on why
# azure-gov-cloud is left out: no independently verified anchor pattern for
# it exists, unlike the four ADR-0045 §4b's table verified against the real
# service.
anchor_hostname() {
    provider="$1"
    region="$2"
    case "$provider" in
        aws | aws-gov-cloud)
            echo "s3.${region}.amazonaws.com"
            ;;
        azure)
            if [ "$region" = "westcentralus" ]; then
                echo "${region}.api.cognitive.microsoft.com"
            else
                echo "${region}.livediagnostics.monitor.azure.com"
            fi
            ;;
        gcp)
            echo "storage.${region}.rep.googleapis.com"
            ;;
        *)
            ;;
    esac
}

# Every resolved address, one per line, for a hostname — both address
# families, since a shared address in either is the same signature.
resolve() {
    getent ahosts "$1" 2>/dev/null | awk '{print $1}' | sort -u
}

targets_file=$(mktemp)
addresses_file=$(mktemp)
trap 'rm -f "$targets_file" "$addresses_file"' EXIT

jq -r '.allowed_regions // {} | to_entries[] | .key as $p | .value[] | "\($p)\t\(.)"' "$regions_file" \
    > "$targets_file"

if [ ! -s "$targets_file" ]; then
    echo "::error::$regions_file names no (provider, region) pairs" >&2
    exit 1
fi

checked=0
unmeasured=0
while IFS=$'\t' read -r provider region; do
    host=$(anchor_hostname "$provider" "$region")
    if [ -z "$host" ]; then
        echo "skip: $provider/$region — no anchor pattern for this provider"
        unmeasured=$((unmeasured + 1))
        continue
    fi
    addrs=$(resolve "$host")
    if [ -z "$addrs" ]; then
        echo "skip: $provider/$region ($host) — did not resolve"
        unmeasured=$((unmeasured + 1))
        continue
    fi
    checked=$((checked + 1))
    while IFS= read -r addr; do
        [ -n "$addr" ] && printf '%s\t%s/%s\t%s\n' "$addr" "$provider" "$region" "$host" >> "$addresses_file"
    done <<< "$addrs"
done < "$targets_file"

echo "checked $checked region(s), $unmeasured unmeasured"

# An address shared by two entries naming the *same* region is a hostname
# with more than one A/AAAA record — ordinary load balancing within a
# region, not the failure this exists to catch. Only an address shared
# across two *different* regions is that signature, so the group-by-address
# step below further groups by region before counting.
shared=$(
    sort "$addresses_file" | awk -F'\t' '
        { region_of[$1][$2] = 1; host_of[$1 SUBSEP $2] = $3 }
        END {
            for (addr in region_of) {
                n = 0
                for (r in region_of[addr]) n++
                if (n > 1) {
                    line = addr ":"
                    for (r in region_of[addr]) line = line " " r "(" host_of[addr SUBSEP r] ")"
                    print line
                }
            }
        }
    '
)

if [ -n "$shared" ]; then
    echo "::error::an anchor address is shared across more than one region" >&2
    echo "$shared" >&2
    exit 1
fi

echo "ok: no address is shared across two different regions"
