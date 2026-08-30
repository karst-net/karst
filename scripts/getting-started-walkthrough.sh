#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright the Karst contributors.
#
# Walk paths A, B and C of docs/GETTING-STARTED.md, running the document's own
# commands.
#
# # What this is for, and what it is not
#
# The suites in bins/karstd/tests and crates/*/tests prove the *code*: the
# datapath, the NAT matrix, the control channel. Not one of them runs a command
# from the walkthrough. two_nodes.rs builds its configuration programmatically
# and never invokes `karstd genkey`; the aquifer fixture starts
# `management/internals/karst/testserver`, not `karst-control`, so
# management.json, the KARST_* variables, the systemd units and the SQLite
# store are exercised by nothing at all. The `compose` job in ci.yml parses the
# compose file and greps it for three variable names; it has never brought the
# deployment up.
#
# So this covers the surface a self-hoster touches and no test did: the
# documented commands, in the documented order, with the documented files.
#
# # Why the steps come out of the document
#
# Every command below is extracted from a tagged fenced block by
# scripts/getting-started-blocks.py rather than written here. A copy of the
# walkthrough kept beside the walkthrough drifts from it at exactly the rate
# the walkthrough drifts from the code, which would leave two things to
# maintain and nothing verified. The tag check — `walkthrough tags`, seconds,
# on every PR — is what keeps a newly added block from silently falling
# outside all of this.
#
# What is *not* extracted are the assertions. Those are test logic, not
# documentation, and they live here: that `genkey` emits 96 bytes, that a key
# file readable by group is refused, that the pins convert to the hex the
# document says they do, that a relay whose roster stops being rewritten
# fails closed at ninety seconds and recovers.
#
# # Usage
#
#     scripts/getting-started-walkthrough.sh tags     # every block is tagged
#     sudo scripts/getting-started-walkthrough.sh path-a
#     sudo scripts/getting-started-walkthrough.sh path-b
#     sudo scripts/getting-started-walkthrough.sh path-c
#
# Paths A and C need root: TUN devices, network namespaces, /etc, systemd.
# Path B needs root and a Docker daemon. All three are destructive to the host
# they run on — they install binaries into /usr/local/bin, write /etc/karst and
# /etc/netbird, and enable systemd units — so they belong on a throwaway
# runner, which is where CI puts them. `WT_KEEP=1` leaves everything running
# for inspection.

set -euo pipefail

REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
BLOCKS="$REPO/scripts/getting-started-blocks.py"

# **Absolute, because the paths change directory.** §5's `up` block ends with
# `cd deploy/compose`, and the steps after it — `docker compose logs`, `cat
# state/bootstrap.key` — are written relative to that, so path B runs from
# there deliberately. With a relative default the extractor then looked for the
# document under deploy/compose and died with a FileNotFoundError traceback
# after the deployment was already up.
export WT_DOC="$REPO/docs/GETTING-STARTED.md"
WORK=${WT_WORK:-/run/karst-walkthrough}
KEEP=${WT_KEEP:-}

cd "$REPO"

# ── output ──────────────────────────────────────────────────────────────────
# A passing run has to be readable, because the thing being tested is a
# document: whoever reads this log is checking that it matches what they would
# have done by hand.

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
say() { printf '\n\033[1m── %s\033[0m\n' "$*"; }
note() { printf '   %s\n' "$*"; }
ok() { printf '   \033[32mok\033[0m  %s\n' "$*"; }

die() {
	printf '\n\033[31mwalkthrough: %s\033[0m\n' "$*" >&2
	[ -n "${GITHUB_ACTIONS:-}" ] && printf '::error::walkthrough: %s\n' "$*" >&2
	exit 1
}

# ── assertions ──────────────────────────────────────────────────────────────
#
# Every one of these prints what it checked on success. A walkthrough that
# skips is a walkthrough that reports success for work it never did, which is
# the failure the privileged suites use KARST_REQUIRE_PREREQUISITES to avoid;
# here the equivalent discipline is that no step is allowed to be a silent
# no-op.

# assert_file_has FILE NEEDLE DESCRIPTION
assert_file_has() {
	grep -qF -- "$2" "$1" || {
		printf '\n--- %s ---\n' "$1" >&2
		sed 's/^/  /' "$1" >&2 || true
		die "$3"
	}
	ok "$3"
}

# assert_file_lacks FILE NEEDLE DESCRIPTION
assert_file_lacks() {
	if grep -qF -- "$2" "$1"; then
		printf '\n--- %s ---\n' "$1" >&2
		sed 's/^/  /' "$1" >&2 || true
		die "$3"
	fi
	ok "$3"
}

# assert_mode PATH MODE DESCRIPTION
assert_mode() {
	local actual
	actual=$(stat -c '%a' "$1")
	[ "$actual" = "$2" ] || die "$3 (mode is $actual, expected $2)"
	ok "$3"
}

# assert_hex_len VALUE LEN DESCRIPTION
assert_hex_len() {
	local n=${#1}
	[ "$n" = "$2" ] || die "$3 (got $n hex characters, expected $2)"
	[[ $1 =~ ^[0-9a-fA-F]+$ ]] || die "$3 (not hexadecimal)"
	ok "$3"
}

# require TOOL...
#
# Named up front and fatal, in the spirit of KARST_REQUIRE_PREREQUISITES in the
# privileged suites: a walkthrough that skips is a walkthrough that reports
# success for work it never did. `xxd` is the one worth listing explicitly —
# §5's base64→hex conversion is a documented pipeline, and on an image without
# vim-common it would fail deep inside a step with an empty pin rather than
# here with a name.
require() {
	local tool missing=()
	for tool in "$@"; do
		command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
	done
	[ ${#missing[@]} -eq 0 ] || die "missing: ${missing[*]}"
	ok "prerequisites present: $*"
}

# wait_for SECONDS DESCRIPTION -- COMMAND...
#
# Polls rather than sleeping a fixed interval, and fails naming what it was
# waiting for. A bare `sleep 30` is both slower on a fast runner and a worse
# diagnostic on a slow one.
wait_for() {
	local limit=$1 what=$2
	shift 3 # limit, description, and the literal `--`
	local deadline=$((SECONDS + limit))
	while [ "$SECONDS" -lt "$deadline" ]; do
		if "$@" >/dev/null 2>&1; then
			ok "$what (after $((limit - (deadline - SECONDS)))s)"
			return 0
		fi
		sleep 2
	done
	die "timed out after ${limit}s waiting for: $what"
}

# ── running a documented step ───────────────────────────────────────────────

# The command prefix each step runs under — `ip netns exec …` for path A, empty
# elsewhere. An array, so an empty prefix is genuinely no argument at all.
WT_CTX=()

# The two pins, in hex, as `karstd` parses them.
#
# Asserted on rather than merely being non-empty: §5's warning box says a pin
# of the wrong length fails with "uses a 1184-byte key", which is only a
# promise worth making if something checks that the right length is what comes
# out of the documented conversion. ML-KEM-768 is 1184 bytes and the server's
# ML-DSA-87 identity is 2592 (identity_test.go pins both).
KEM_PIN_HEX_LEN=2368
VERIFY_PIN_HEX_LEN=5184

# run_step PATH STEP
#
# Reads the block's attributes and body from the document, prints both, and
# then either writes the body to the file the tag names or executes it.
# Captures the step's output in $WORK/.out for the caller to assert on.
run_step() {
	_run_step "$@"
	clear_placeholders
}

_run_step() {
	local path=$1 step=$2
	local body="$WORK/.step" out="$WORK/.out"

	# Checked rather than assumed. `eval "$(cmd)"` swallows the exit status of
	# `cmd`, so an extractor that could not read the document at all reported
	# itself as a Python traceback in the middle of a step's output and left
	# whoever read the log to work out which step it belonged to.
	local WT_FILE WT_APPEND WT_BG WT_LINE attrs
	attrs=$(python3 "$BLOCKS" attrs "$path" "$step") \
		|| die "cannot read path $path step $step from $WT_DOC"
	eval "$attrs"
	python3 "$BLOCKS" emit "$path" "$step" >"$body" \
		|| die "cannot extract path $path step $step from $WT_DOC"

	say "path $path · $step   (GETTING-STARTED.md:$WT_LINE)"
	sed 's/^/   │ /' "$body"

	if [ -n "$WT_FILE" ]; then
		mkdir -p "$(dirname "$WT_FILE")"
		if [ -n "$WT_APPEND" ]; then
			printf '\n' >>"$WT_FILE"
			cat "$body" >>"$WT_FILE"
		else
			cat "$body" >"$WT_FILE"
		fi
		note "→ $WT_FILE"
		: >"$out"
		return
	fi

	if [ -n "$WT_BG" ]; then
		# All but the last line run to completion; the last one is a daemon
		# that never returns. Splitting on the last *line* rather than the last
		# command is a real limitation, and it is why `bg=1` is only on blocks
		# whose final command is a single line.
		local total last
		total=$(wc -l <"$body")
		last=$(tail -n 1 "$body")
		if [ "$total" -gt 1 ]; then
			head -n "$((total - 1))" "$body" >"$body.head"
			"${WT_CTX[@]}" bash -euo pipefail "$body.head" >"$out" 2>&1 || {
				sed 's/^/   > /' "$out" >&2
				die "path $path step $step failed before its daemon line"
			}
			sed 's/^/   > /' "$out"
		fi
		: >"${WT_BG_LOG:-$WORK/daemon.log}"
		"${WT_CTX[@]}" setsid --fork bash -c "$last" \
			</dev/null >"${WT_BG_LOG:-$WORK/daemon.log}" 2>&1
		note "backgrounded: $last"
		note "   log: ${WT_BG_LOG:-$WORK/daemon.log}"
		return
	fi

	"${WT_CTX[@]}" bash -euo pipefail "$body" >"$out" 2>&1 || {
		sed 's/^/   > /' "$out" >&2
		die "path $path step $step (GETTING-STARTED.md:$WT_LINE) exited non-zero"
	}
	sed 's/^/   > /' "$out"
}

# A prefix assignment on a *function* call persists in bash after the call
# returns, unlike one on an external command. Left alone, a `WTP_setup_key`
# set for one step would still be set for the next — so a step that forgot to
# provide a placeholder would silently inherit a stale value instead of
# failing with the name of what is missing, which is the one guarantee the
# placeholder mechanism exists to give. Clearing them after every step is what
# keeps that guarantee true; the `WTP_` prefix exists so this can be precise.
clear_placeholders() {
	local v
	for v in $(compgen -v WTP_ || true); do unset "$v"; done
}

# json_subst KEY VALUE [KEY VALUE …] — build a WT_SUBST map.
json_subst() {
	python3 -c '
import json, sys
print(json.dumps(dict(zip(sys.argv[1::2], sys.argv[2::2]))))
' "$@"
}

# ── path A ──────────────────────────────────────────────────────────────────
#
# Two namespaces on a veth pair stand in for the document's two hosts, and the
# substitution table below is the whole of the adaptation between the two. Each
# entry is there because one host is standing in for two:
#
#   - a private directory per node, where two machines would each have their
#     own `/etc/karst`;
#   - the fixture's addresses in place of the document's examples;
#   - an explicit `--socket`, because the default control socket is a
#     filesystem path and two daemons on one host collide on it;
#   - a count on `ping`, because the document's reader ends it with Ctrl-C and
#     a test process has nobody to press it.
#
# Nothing else is rewritten, and anything that had to be would be a sign that
# the document is describing something other than what it says.

NS_A=wt-alice
NS_B=wt-bob
UNDERLAY_A=10.99.0.1
UNDERLAY_B=10.99.0.2

path_a_cleanup() {
	[ -n "$KEEP" ] && {
		note "WT_KEEP=1: leaving $NS_A and $NS_B running"
		return
	}
	pkill -x karstd 2>/dev/null || true
	ip netns del "$NS_A" 2>/dev/null || true
	ip netns del "$NS_B" 2>/dev/null || true
}

# The substitution map for one path-A node.
a_subst() {
	local dir=$1 self=$2 peer=$3 peer_under=$4 peer_name=$5
	json_subst \
		/etc/karst "$dir" \
		10.77.0.1 "$self" \
		10.77.0.2 "$peer" \
		192.0.2.20 "$peer_under" \
		'name = "bob"' "name = \"$peer_name\"" \
		'karstd --config' "karstd --socket $dir/karstd.sock --config" \
		'karst status' "karst status --socket $dir/karstd.sock" \
		'ping ' 'ping -c4 -W2 '
}

path_a() {
	[ "$(id -u)" = 0 ] || die "path A needs root: it creates network namespaces and TUN devices"
	trap path_a_cleanup EXIT
	path_a_cleanup
	mkdir -p "$WORK"

	bold "Path A — two nodes and nothing else (GETTING-STARTED.md §4)"

	say "fixture: two namespaces on a veth pair"
	ip netns add "$NS_A"
	ip netns add "$NS_B"
	ip link add wt-a type veth peer name wt-b
	ip link set wt-a netns "$NS_A"
	ip link set wt-b netns "$NS_B"
	ip netns exec "$NS_A" ip addr add "$UNDERLAY_A/24" dev wt-a
	ip netns exec "$NS_B" ip addr add "$UNDERLAY_B/24" dev wt-b
	ip netns exec "$NS_A" ip link set wt-a up
	ip netns exec "$NS_B" ip link set wt-b up
	ip netns exec "$NS_A" ip link set lo up
	ip netns exec "$NS_B" ip link set lo up
	ip netns exec "$NS_A" ping -c1 -W2 "$UNDERLAY_B" >/dev/null \
		|| die "the fixture's own veth pair does not carry a packet"
	ok "$NS_A ($UNDERLAY_A) and $NS_B ($UNDERLAY_B) can reach each other"

	WT_CTX=()
	WT_SUBST='{}' run_step A build-rust

	local dir_a="$WORK/alice" dir_b="$WORK/bob"
	local subst_a subst_b
	subst_a=$(a_subst "$dir_a" 10.77.0.1 10.77.0.2 "$UNDERLAY_B" bob)
	subst_b=$(a_subst "$dir_b" 10.77.0.2 10.77.0.1 "$UNDERLAY_A" alice)

	# The document's commands assume the binaries are on PATH, which `install`
	# is what makes true.
	WT_CTX=()
	WT_SUBST=$subst_a run_step A install
	WT_SUBST=$subst_b run_step A install

	# ── keys ────────────────────────────────────────────────────────────────
	local node ns dir subst
	for node in alice bob; do
		[ "$node" = alice ] && { ns=$NS_A; dir=$dir_a; subst=$subst_a; } \
			|| { ns=$NS_B; dir=$dir_b; subst=$subst_b; }
		WT_CTX=(ip netns exec "$ns")
		WT_SUBST=$subst run_step A genkey

		# §4 makes two claims about this file in the same breath. Both are
		# checkable and neither is checked anywhere else.
		assert_mode "$dir/node.key" 600 "$node's data-plane key is mode 600"
		assert_hex_len "$(cat "$dir/node.key")" 192 \
			"$node's key is 96 bytes of hex — 64 for ML-KEM, 32 for X25519"

		WT_SUBST=$subst run_step A node-config
	done

	# ── public keys ─────────────────────────────────────────────────────────
	#
	# `pubkey` runs here, before any peer exists in either file. §4 says it
	# works at this point deliberately — "a new node needs to publish its key
	# precisely in order to be added elsewhere" — and running it in the only
	# order that is useful is the test of that claim.
	local kem_alice dh_alice kem_bob dh_bob
	for node in alice bob; do
		[ "$node" = alice ] && { ns=$NS_A; subst=$subst_a; } || { ns=$NS_B; subst=$subst_b; }
		WT_CTX=(ip netns exec "$ns")
		WT_SUBST=$subst run_step A pubkey
		local kem dh
		kem=$(sed -n 's/^kem_public_key = "\(.*\)"/\1/p' "$WORK/.out")
		dh=$(sed -n 's/^dh_public_key *= "\(.*\)"/\1/p' "$WORK/.out")
		assert_hex_len "$kem" 2368 "$node's ML-KEM public key is 2368 hex characters"
		assert_hex_len "$dh" 64 "$node's X25519 public key is 64 hex characters"
		if [ "$node" = alice ]; then
			kem_alice=$kem
			dh_alice=$dh
		else
			kem_bob=$kem
			dh_bob=$dh
		fi
	done

	# ── peers ───────────────────────────────────────────────────────────────
	# Each node is given the *other* node's printed keys, which is the paste
	# step the document describes in prose.
	WT_CTX=(ip netns exec "$NS_A")
	WT_SUBST=$subst_a WTP_kem_public_key=$kem_bob WTP_dh_public_key=$dh_bob \
		run_step A peer-config
	WT_CTX=(ip netns exec "$NS_B")
	WT_SUBST=$subst_b WTP_kem_public_key=$kem_alice WTP_dh_public_key=$dh_alice \
		run_step A peer-config

	# ── the mode-600 refusal ────────────────────────────────────────────────
	#
	# §12's table promises this failure by name, and an error string is exactly
	# the kind of claim that rots without anyone noticing.
	say "a key readable by group is refused (§12)"
	cp "$dir_a/node.key" "$dir_a/node.key.bak"
	chmod 644 "$dir_a/node.key"
	if ip netns exec "$NS_A" karstd check --config "$dir_a/karstd.toml" >"$WORK/.perm" 2>&1; then
		die "karstd accepted a key file readable by group or other"
	fi
	assert_file_has "$WORK/.perm" "readable by group or other" \
		"a group-readable key is refused with the documented message"
	cp "$dir_a/node.key.bak" "$dir_a/node.key"
	chmod 600 "$dir_a/node.key"

	# ── start ───────────────────────────────────────────────────────────────
	for node in alice bob; do
		[ "$node" = alice ] && { ns=$NS_A; subst=$subst_a; } || { ns=$NS_B; subst=$subst_b; }
		WT_CTX=(ip netns exec "$ns")
		WT_BG_LOG="$WORK/$node.log" WT_SUBST=$subst run_step A start
	done

	# §4: the absence of a PSK "is reported at startup rather than assumed".
	wait_for 30 "both daemons report the missing PSK (spec §7.3)" -- \
		bash -c "grep -q 'has no PSK' '$WORK/alice.log' && grep -q 'has no PSK' '$WORK/bob.log'"

	wait_for 90 "alice's session with bob reaches established" -- \
		bash -c "ip netns exec $NS_A karst status --socket $dir_a/karstd.sock \
			| grep -q 'state = \"established\"'"

	# ── verify ──────────────────────────────────────────────────────────────
	WT_CTX=(ip netns exec "$NS_A")
	WT_SUBST=$subst_a run_step A verify

	assert_file_has "$WORK/.out" 'state = "established"' "the peer is established"
	# §4: "A pair with no relay configured has only one honest answer."
	assert_file_has "$WORK/.out" 'transport = "direct"' \
		"the transport is direct — there is no relay in this path to fall back to"
	# A static roster carries no policy, and §11's own status listing says so.
	# The distinction matters: `enforcing = false` and a filter with no rules
	# are opposite things that look identical from outside.
	assert_file_has "$WORK/.out" 'enforcing = false' \
		"no packet filter is enforced: a static roster distributes no policy"
	assert_file_has "$WORK/.out" '4 packets transmitted, 4 received' \
		"the tunnel carries ICMP between the two overlay addresses"

	bold "Path A: every documented step ran and every claim held."
}

# ── path B ──────────────────────────────────────────────────────────────────

COMPOSE_DIR="$REPO/deploy/compose"

path_b_cleanup() {
	[ -n "$KEEP" ] && {
		note "WT_KEEP=1: leaving the compose deployment up"
		return
	}
	systemctl stop karstd 2>/dev/null || true
	(cd "$COMPOSE_DIR" && docker compose down -v 2>/dev/null) || true
	# **`state/` too, and this is not tidiness.** bootstrap.sh is idempotent by
	# design — every step skips if its output exists — so a leftover state
	# directory from an earlier run would give this one a relay identity, pins
	# and a bootstrap.key it never generated. Every assertion about them would
	# then pass while testing nothing, which is the exact failure the
	# walkthrough exists to catch one layer down.
	rm -rf "$COMPOSE_DIR/state"
	rm -rf /etc/karst /var/lib/karst
}

path_b() {
	[ "$(id -u)" = 0 ] || die "path B needs root: it installs a node agent and a systemd unit"
	require docker openssl xxd base64
	trap path_b_cleanup EXIT
	path_b_cleanup
	mkdir -p "$WORK"

	bold "Path B — a coordination server and a relay, with containers (§5)"

	# `127.0.0.1` is what the document offers for "try it on one machine", and
	# it is the only substitution this path needs: everything else in §5 is
	# already relative to deploy/compose.
	local subst
	subst=$(json_subst 203.0.113.7 127.0.0.1)

	WT_CTX=()
	WT_SUBST='{}' run_step B build-rust
	WT_SUBST=$subst run_step B up

	cd "$COMPOSE_DIR"

	wait_for 180 "the coordination server printed its pins" -- \
		bash -c "docker compose logs control 2>&1 | grep -q 'karst: server KEM pin'"

	WT_SUBST=$subst run_step B pins
	assert_file_has "$WORK/.out" "karst: server KEM pin" "the KEM pin is logged"
	assert_file_has "$WORK/.out" "karst: server sign pin" "the signing pin is logged"

	# ── the enrollment key ──────────────────────────────────────────────────
	wait_for 60 "the server minted a bootstrap enrollment key (§8.1)" -- \
		test -f "$COMPOSE_DIR/state/bootstrap.key"
	assert_mode "$COMPOSE_DIR/state/bootstrap.key" 600 \
		"the enrollment key is mode 600"
	WT_SUBST=$subst run_step B bootstrap-key
	local setup_key
	setup_key=$(tr -d '\r\n' <"$WORK/.out")
	[ -n "$setup_key" ] || die "state/bootstrap.key is empty"
	ok "the key is ${#setup_key} characters and is what a node enrolls with"

	# The file, not the database, is the idempotence rule — the plaintext is
	# recoverable from nowhere else, so a server that minted a fresh key on
	# every boot would leave a trail of live credentials nobody could revoke by
	# name.
	#
	# The wait is on the "keeping it" line rather than on the pins, because the
	# pins from the *previous* run are still in the log: polling for those would
	# succeed instantly and compare the key to itself before the restart had
	# even begun.
	docker compose restart control >/dev/null
	wait_for 180 "the restarted server found the key already there and kept it" -- \
		bash -c "docker compose logs control 2>&1 | grep -q 'an enrollment key is already in'"
	[ "$(tr -d '\r\n' <"$COMPOSE_DIR/state/bootstrap.key")" = "$setup_key" ] \
		|| die "the enrollment key changed across a restart; the first one is now unrevocable"
	ok "the enrollment key survived a restart unchanged"

	# ── the pins are logged base64 and configured in hex ────────────────────
	#
	# §5 gives this its own warning box, and the conversion it prints is run
	# here rather than described.
	WT_SUBST=$subst run_step B pins-hex
	local kem_hex verify_hex
	kem_hex=$(sed -n 1p "$WORK/.out" | tr -d '\r\n')
	verify_hex=$(sed -n 2p "$WORK/.out" | tr -d '\r\n')
	assert_hex_len "$kem_hex" "$KEM_PIN_HEX_LEN" \
		"the KEM pin converts to a 1184-byte ML-KEM-768 key in hex"
	assert_hex_len "$verify_hex" "$VERIFY_PIN_HEX_LEN" \
		"the signing pin converts to a 2592-byte ML-DSA-87 key in hex"

	# ── a node ──────────────────────────────────────────────────────────────
	cd "$REPO"
	WT_SUBST=$subst run_step B node-install
	install -m 0644 "$COMPOSE_DIR/state/tls/relay.crt" /etc/karst/relay.crt
	mkdir -p /var/lib/karst

	WT_CTX=()
	WT_SUBST=$(json_subst karst.example.com 127.0.0.1) \
		WTP_server_kem_pin=$kem_hex \
		WTP_server_verify_pin=$verify_hex \
		WTP_setup_key=$setup_key \
		run_step B node-config

	WT_SUBST='{}' run_step B node-start
	assert_enrolled B

	# ── the base64 pin that the document warns about ────────────────────────
	say "the failures §12 names by message"
	local kem_b64
	kem_b64=$(docker compose -f "$COMPOSE_DIR/docker-compose.yml" --project-directory "$COMPOSE_DIR" \
		logs control 2>&1 | grep 'server KEM pin' | tail -1 | awk '{print $NF}')
	b_reject_pin "$kem_b64" "contains a non-hexadecimal character" \
		"the base64 pin pasted verbatim is refused, naming the field"
	b_reject_pin "aabbcc" "uses a 1184-byte key" \
		"a hex pin of the wrong length is refused, naming the expected size"

	# ── the roster lease ────────────────────────────────────────────────────
	b_roster_lease

	# ── bootstrap.sh is idempotent ──────────────────────────────────────────
	#
	# Its own header calls this out, and the claim is load-bearing:
	# regenerating a relay identity silently invalidates the registry every
	# node has pinned.
	say "bootstrap.sh is idempotent (deploy/compose/bootstrap.sh)"
	local before after
	before=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["relays"][0]["identity_key"])' \
		"$COMPOSE_DIR/state/relays.json")
	(cd "$COMPOSE_DIR" && KARST_RELAY_IP=127.0.0.1 ./bootstrap.sh >"$WORK/.bootstrap" 2>&1) \
		|| { cat "$WORK/.bootstrap" >&2; die "re-running bootstrap.sh failed"; }
	after=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["relays"][0]["identity_key"])' \
		"$COMPOSE_DIR/state/relays.json")
	[ "$before" = "$after" ] \
		|| die "bootstrap.sh regenerated the relay identity; every node's pinned registry is now wrong"
	ok "a second bootstrap.sh kept the relay identity and the registry"

	bold "Path B: the deployment came up, enrolled a node, and failed closed on schedule."
}

# assert_enrolled PATH — the node registered and applied the server's netmap.
#
# Enrollment is not instantaneous: `systemctl enable --now` returns as soon as
# the unit is started, and the netmap arrives a few seconds later. The document
# splits `node-start` from `node-status` for exactly that reason, and this
# waits between them rather than racing — a fixed sleep would be slower on a
# fast runner and flaky on a slow one.
#
# Two lines are checked, and they are the two that fail invisibly. An empty
# address list means the netmap never arrived. `enforcing = false` on a node in
# control mode means it came up with no packet filter rather than the server's,
# which from outside is indistinguishable from a policy that happens to allow
# everything — in opposite directions.
assert_enrolled() {
	local path=$1
	wait_for 120 "the node enrolled and applied a netmap" -- \
		bash -c 'karst status 2>/dev/null | grep -q "^addresses = \[\""'
	WT_CTX=()
	WT_SUBST='{}' run_step "$path" node-status
	assert_file_has "$WORK/.out" "addresses = [\"" \
		"the node received an overlay address from the netmap"
	assert_file_has "$WORK/.out" "enforcing = true" \
		"the node is enforcing the policy the server distributed"
}

# b_reject_pin PIN NEEDLE DESCRIPTION — a node config with a bad pin is refused.
b_reject_pin() {
	local bad=$1 needle=$2 what=$3
	sed "s|^server_kem_pin = .*|server_kem_pin = \"$bad\"|" \
		/etc/karst/karstd.toml >"$WORK/bad-pin.toml"
	if karstd check --config "$WORK/bad-pin.toml" >"$WORK/.badpin" 2>&1; then
		die "karstd accepted a server_kem_pin of \"$bad\""
	fi
	assert_file_has "$WORK/.badpin" "$needle" "$what"
}

# b_roster_lease — the relay treats a roster nobody maintains as untrustworthy.
#
# FINDINGS.md 42, and §5 asks the reader to watch it happen once. The lease is
# ninety seconds and the server rewrites the file three times per lease, so the
# mtime must advance while the bytes stay identical — the property that makes
# "nothing has changed" and "nothing is running" distinguishable.
b_roster_lease() {
	say "the roster lease (§5, FINDINGS.md 42)"
	local roster="$COMPOSE_DIR/state/roster.toml"
	local mtime1 sum1 mtime2 sum2
	mtime1=$(stat -c '%Y' "$roster")
	sum1=$(sha256sum "$roster" | cut -d' ' -f1)
	sleep 30
	mtime2=$(stat -c '%Y' "$roster")
	sum2=$(sha256sum "$roster" | cut -d' ' -f1)
	[ "$mtime2" -gt "$mtime1" ] \
		|| die "roster.toml was not rewritten within 30s; the relay's lease expires at 90s"
	[ "$sum1" = "$sum2" ] \
		|| die "roster.toml's contents changed while no node joined or left"
	ok "the roster's mtime advances while its bytes stay identical"

	(cd "$COMPOSE_DIR" && docker compose stop control >/dev/null)
	wait_for 150 "the relay failed closed once nothing was maintaining the roster" -- \
		bash -c "cd '$COMPOSE_DIR' && docker compose logs relay 2>&1 | grep -qi 'lease expired'"
	(cd "$COMPOSE_DIR" && docker compose start control >/dev/null)
	wait_for 120 "the relay recovered when the roster was rewritten again" -- \
		bash -c "cd '$COMPOSE_DIR' && docker compose logs relay 2>&1 | grep -qi 'roster reloaded'"
}

# ── path C ──────────────────────────────────────────────────────────────────

path_c_cleanup() {
	[ -n "$KEEP" ] && {
		note "WT_KEEP=1: leaving the systemd units running"
		return
	}
	systemctl stop karstd karst-control karst-relay 2>/dev/null || true
	systemctl disable karstd karst-control karst-relay 2>/dev/null || true
	rm -f /etc/systemd/system/{karstd,karst-control,karst-relay}.service
	systemctl daemon-reload 2>/dev/null || true
	# The same argument as path B's: a leftover /etc/karst would supply a relay
	# identity, a registry and a bootstrap key this run never created, and every
	# assertion about them would pass without testing anything. Half-destructive
	# is worse than destructive, because only one of the two is honest about it.
	rm -rf /etc/karst /var/lib/karst /etc/netbird /var/lib/netbird
}

path_c() {
	[ "$(id -u)" = 0 ] || die "path C needs root: it writes /etc and enables systemd units"
	systemctl is-system-running >/dev/null 2>&1 || systemctl --version >/dev/null 2>&1 \
		|| die "path C needs systemd; this host has none"
	require openssl xxd base64 journalctl
	trap path_c_cleanup EXIT
	path_c_cleanup
	mkdir -p "$WORK"

	bold "Path C — bare metal, with systemd (§6)"

	# The document is written for a relay at 203.0.113.7 answering to
	# relay.example.com, and a coordination server at karst.example.com. On one
	# host all three are the loopback, and the certificate's SAN has to agree
	# with the name the node is told to expect — which is why the name is
	# substituted rather than left to resolve.
	local subst
	subst=$(json_subst \
		203.0.113.7 127.0.0.1 \
		relay.example.com localhost \
		karst.example.com 127.0.0.1)

	WT_CTX=()
	WT_SUBST='{}' run_step C build-rust
	WT_SUBST='{}' run_step C build-control
	WT_SUBST=$subst run_step C install

	# ── 6.1 the relay ───────────────────────────────────────────────────────
	WT_SUBST=$subst run_step C relay-install
	WT_SUBST=$subst run_step C relay-cert
	assert_mode /etc/karst/tls/relay.key 600 "the relay's TLS key is mode 600"
	WT_SUBST=$subst run_step C relay-config
	WT_SUBST=$subst run_step C relay-check
	# §6.1 prints this line and it is the whole point of seeding a placeholder:
	# an empty roster is a legitimate state that admits nobody, and the check
	# has to say so rather than call the file valid and stop.
	assert_file_has "$WORK/.out" "no nodes admitted" \
		"the check reports that an empty roster admits nobody"

	WT_SUBST=$subst run_step C relay-pubkey
	local identity_pk
	identity_pk=$(sed -n 's/^identity_pk *//p' "$WORK/.out" | tr -d ' \r\n')
	[ -n "$identity_pk" ] || die "karst-relay pubkey printed no identity_pk"
	ok "the relay's registry entry is ${#identity_pk} base64 characters"

	WT_SUBST=$subst run_step C relay-start
	wait_for 30 "karst-relay is active under systemd" -- \
		systemctl is-active --quiet karst-relay

	# ── 6.2 the coordination server ─────────────────────────────────────────
	WT_SUBST=$subst run_step C control-install

	# §6.2: identity_key is the identity_pk printed above, verbatim and base64.
	# It is the one value in the walkthrough that is *not* converted to hex,
	# and pasting it through unchanged is the property being tested.
	WT_SUBST=$subst WTP_identity_key=$identity_pk run_step C relays-json
	WT_SUBST=$subst run_step C policy
	WT_SUBST=$subst \
		WTP_Secret="$(openssl rand -hex 16)" \
		WTP_DataStoreEncryptionKey="$(openssl rand -base64 32)" \
		run_step C management
	chmod 600 /etc/netbird/management.json
	WT_SUBST=$subst run_step C control-env

	# §6.2 claims relays.json is validated at startup rather than on fetch,
	# "because one malformed entry fails the *whole* netmap and a startup error
	# naming the field beats every node failing to apply a netmap it just
	# authenticated". Checked before the real start, so a regression here is
	# reported as itself rather than as a server that would not come up.
	c_reject_dns_name_in_registry

	WT_SUBST=$subst run_step C control-start
	wait_for 60 "karst-control is active under systemd" -- \
		systemctl is-active --quiet karst-control
	# Generous, and §6.2 says why: the first start downloads GeoLite2 databases
	# before it serves anything, so this is a network fetch and not just a
	# process coming up.
	wait_for 300 "the coordination server printed its pins to the journal" -- \
		bash -c "journalctl -u karst-control --no-pager | grep -q 'karst: server KEM pin'"
	WT_SUBST=$subst run_step C control-pins
	assert_file_has "$WORK/.out" "karst: server KEM pin" "the KEM pin reached the journal"
	assert_file_has "$WORK/.out" "karst: server sign pin" "the signing pin reached the journal"

	local kem_hex verify_hex
	kem_hex=$(journalctl -u karst-control --no-pager | grep 'server KEM pin' | tail -1 \
		| awk '{print $NF}' | base64 -d | xxd -p -c 0)
	verify_hex=$(journalctl -u karst-control --no-pager | grep 'server sign pin' | tail -1 \
		| awk '{print $NF}' | base64 -d | xxd -p -c 0)
	assert_hex_len "$kem_hex" "$KEM_PIN_HEX_LEN" \
		"the journal's KEM pin converts to a 1184-byte ML-KEM-768 key"
	assert_hex_len "$verify_hex" "$VERIFY_PIN_HEX_LEN" \
		"the journal's signing pin converts to a 2592-byte ML-DSA-87 key"

	# ── 8.1 the enrollment key ──────────────────────────────────────────────
	wait_for 60 "the server minted a bootstrap enrollment key (§8.1)" -- \
		test -f /var/lib/karst/bootstrap.key
	assert_mode /var/lib/karst/bootstrap.key 600 "the enrollment key is mode 600"
	WT_SUBST=$subst run_step C bootstrap-key
	local setup_key
	setup_key=$(tr -d '\r\n' <"$WORK/.out")
	[ -n "$setup_key" ] || die "/var/lib/karst/bootstrap.key is empty"
	ok "the enrollment key is ${#setup_key} characters"

	# ── 6.3 the node ────────────────────────────────────────────────────────
	WT_SUBST=$subst run_step C node-install
	assert_mode /etc/karst/node.key 600 "the node's data-plane key is mode 600"
	install -m 0644 /etc/karst/tls/relay.crt /etc/karst/relay.crt

	WT_SUBST=$subst \
		WTP_server_kem_pin=$kem_hex \
		WTP_server_verify_pin=$verify_hex \
		WTP_setup_key=$setup_key \
		run_step C node-config

	WT_SUBST=$subst run_step C node-start
	wait_for 60 "karstd is active under systemd" -- systemctl is-active --quiet karstd
	assert_enrolled C

	# The node's control identity is created on first run and is a *different*
	# file from the data-plane key — phreatic-v1.md §4 is explicit that a leak
	# of one is not the other, and §6.3 tells the reader not to generate it
	# with `karstd genkey`. Two files of two different sizes is that claim.
	[ -f /etc/karst/identity.key ] || die "karstd did not create its control identity on first run"
	assert_mode /etc/karst/identity.key 600 "the control identity is mode 600"
	[ "$(stat -c '%s' /etc/karst/identity.key)" != "$(stat -c '%s' /etc/karst/node.key)" ] \
		|| die "the control identity and the data-plane key are the same size; \
one of them is not what §6.3 says it is"
	ok "the control identity is a separate file from the data-plane key"

	# ── ExecStopPost= ───────────────────────────────────────────────────────
	c_exec_stop_post

	bold "Path C: the whole stack came up under systemd from the document's own commands."
}

# c_reject_dns_name_in_registry — §6.2's startup-validation claim.
c_reject_dns_name_in_registry() {
	say "a DNS name in relays.json is refused at startup, not at fetch (§6.2)"
	cp /etc/karst/relays.json "$WORK/relays.json.bak"
	sed 's|"address": "[^"]*"|"address": "relay.example.com:443"|' \
		"$WORK/relays.json.bak" >/etc/karst/relays.json
	set +e
	# shellcheck disable=SC2046 # the env file is KEY=VALUE lines, split on purpose
	env $(grep -v '^#' /etc/karst/control.env | xargs) \
		timeout 30 karst-control management \
		--config /etc/netbird/management.json --datadir /var/lib/netbird \
		--port 33073 --log-file console >"$WORK/.badrelay" 2>&1
	local status=$?
	set -e
	cp "$WORK/relays.json.bak" /etc/karst/relays.json

	# **124 is `timeout` killing a server that was still running**, and it is
	# non-zero — so a bare `-ne 0` here would read "the server refused to
	# start" off the exact outcome that means it started happily. The whole
	# claim being tested is that this fails *at startup*, so it has to fail
	# fast as well as fail.
	[ "$status" -ne 124 ] \
		|| die "karst-control ran for 30s with a DNS name in relays.json; §6.2 says it must refuse at startup"
	[ "$status" -ne 0 ] \
		|| die "karst-control exited cleanly with a DNS name in relays.json"
	assert_file_has "$WORK/.badrelay" "address" \
		"the startup error names the field rather than failing every node's netmap later"
}

# c_exec_stop_post — §6.3's argument that ExecStopPost= is not decoration.
#
# A host left pointing at a resolver that stopped listening has every lookup
# failing, which is indistinguishable from "the network is broken". The daemon
# installs no signal handler and could not survive SIGKILL if it did, so the
# unit runs the revert from outside on every stop, clean or not.
#
# # What this can and cannot check
#
# §6.3's node configuration has no `[dns]` table, so there is nothing on this
# host for the revert to undo and its *effect* is unobservable — asserting on
# it would be asserting on a no-op. What is checkable is each half of the
# claim separately, and both halves are things that have silently broken
# before:
#
#   - the **installed** unit carries `ExecStopPost=`. This is the half that
#     catches the mistake §3 now warns about, where a reader copies the
#     packaging unit instead and gets a service with no revert hook at all;
#   - `karst dns revert` **runs standalone**, with no daemon, which is the
#     property that makes it usable from a stop hook after the process it is
#     cleaning up after has already exited. It is the document's own
#     `dns-revert` step, run here rather than described.
#
# A SIGKILL is used rather than a clean stop because "clean or not" is the
# part of the claim worth exercising: a hook that only runs on graceful stops
# would leave exactly the crash-restart loop the unit exists to survive.
c_exec_stop_post() {
	say "ExecStopPost= is not decoration (§6.3)"
	assert_file_has /etc/systemd/system/karstd.service \
		"ExecStopPost=-/usr/local/bin/karst dns revert" \
		"the installed unit reverts the host resolver after every stop"

	systemctl kill -s SIGKILL karstd
	wait_for 60 "karstd is gone after a SIGKILL it could not have handled" -- \
		bash -c '! systemctl is-active --quiet karstd'

	# The daemon is dead, which is exactly the state the hook runs in.
	WT_CTX=()
	WT_SUBST='{}' run_step C dns-revert
	ok "karst dns revert works with no daemon to talk to"
}

# ── dispatch ────────────────────────────────────────────────────────────────

case "${1:-}" in
tags)
	python3 "$BLOCKS" check
	;;
path-a) path_a ;;
path-b) path_b ;;
path-c) path_c ;;
*)
	sed -n '3,52p' "${BASH_SOURCE[0]}" | sed 's/^# \?//'
	exit 2
	;;
esac
