<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Aquifer namespace tests in a container

The aquifer integration suite runs real control, Ponor, node, TUN, nftables,
route, NAT and optional coturn processes. On Linux hosts with Docker access,
this runner supplies namespace privileges inside a disposable container:

```sh
./scripts/test-aquifer-container.sh gateway
./scripts/test-aquifer-container.sh exit
# Full suite, serially:
./scripts/test-aquifer-container.sh
```

Arguments are Rust test filters/options. The runner always enables ignored
tests, requires prerequisites, and uses one test thread because fixtures share
namespace names. A missing prerequisite fails rather than reporting a skipped
network scenario as success. Select an exact scenario with its name and
`--exact`. Expect the full suite to take several minutes.

The host needs Cargo, Python 3, a Go toolchain matching `server/go.mod`, a C
compiler for SQLite's CGO driver, Docker, and `/dev/net/tun`. The container image
installs the networking/runtime prerequisites, including real coturn. Docker
must allow network/admin mount capabilities, namespace creation, and the TUN
device. AppArmor and seccomp confinement are disabled for this test container
so `ip netns exec` can create its isolated mount/network namespaces. The runner
remounts `/proc/sys/net` writable inside the container for namespaced network
sysctl setup; other sysctl paths keep Docker's restrictions. This grants
substantial privileges to the fixture; use a trusted build and a disposable
Linux test host/VM when that is your local testing policy.

The runner builds `karstd`, `karst`, `karst-relay`, the aquifer test and a
CGO-enabled `karst-testserver` from the current worktree. It stages those
executables in a temporary directory and mounts only that directory read-only.
It mounts no repository, deployment state, Go module cache, Docker socket or
host network. The container starts with no external network; tests create
virtual underlays entirely inside it. The fixture Go server is an integration
test server, not a substitute for production control deployment verification.
This runner tests current-worktree binaries, not installed packages.

After the test exits Docker removes the container and the shell removes the
staged executables. Namespace, DNS and forwarding changes belong to the test
container. Images remain cached. The optional `KARST_AQUIFER_TEST_IMAGE` sets the
local image tag to build/use; it does not skip the image build. Existing
`just test-aquifer` and root-host execution remain supported.

For other harnesses, `KARST_AQUIFER_TESTSERVER` explicitly supplies a prebuilt
fixture executable. The suite does not require Go in that runtime environment
and fails on a missing executable. Without this variable it retains the
original source-build behavior. `KARST_AQUIFER_BIN_DIR` still requires all three
product executables in one directory.

## IPv6 Gateway and DNS scenarios

```sh
./scripts/test-aquifer-container.sh ipv6_gateway
```

These opt into dual-stack fixture addresses and explicit IPv6 destination/port
policy. The IPv6 TCP row verifies specific-prefix access before default-route
consent, NAT66 default egress after consent, retained subnet access after
withdrawal, and an explicit return route with masquerade disabled while an
overlapping default offer still exists. The DNS row sends real UDP and TCP
queries to KarstDNS's stub, which forwards to a DNS server on the exit-only
IPv6 LAN. Fresh names and zero-TTL answers test withdrawal without cached
success. Host resolver integration is disabled; the host's resolver is untouched.
This is DNS over UDP through an IPv6 upstream, including TCP clients of the
local stub; it does not establish TCP upstream fallback, DoT or native-platform
exit-DNS behavior.

## Real mixed-version binaries

The container runner accepts optional host paths to executable binaries:

- `KARST_AQUIFER_RELAY_BIN`: relay executable, used for every relay in a scenario.
- `KARST_AQUIFER_NODE_A_BIN`: node A (gateway agent for routing scenarios).
- `KARST_AQUIFER_NODE_B_BIN`: node B (recipient agent for routing scenarios).
- `KARST_AQUIFER_TESTSERVER_BIN`: control fixture executable, built from the
  desired revision's `server/management/internals/karst/testserver` package.

Unset overrides use current-worktree binaries. Overrides are copied into the
read-only staging directory; no additional host directories are mounted. Use
separate Cargo target directories for old and current builds to avoid stale
build-script/protobuf output when switching source checkouts. Preserve the old
executables outside either target directory before starting the runner.

```sh
KARST_AQUIFER_RELAY_BIN=/tmp/old-karst-relay \
  ./scripts/test-aquifer-container.sh two_nodes_meet_on_the_relay_and_end_up_direct --exact
KARST_AQUIFER_NODE_A_BIN=/tmp/old-karstd \
  ./scripts/test-aquifer-container.sh a_recipient_reaches_
KARST_AQUIFER_NODE_B_BIN=/tmp/old-karstd \
  ./scripts/test-aquifer-container.sh a_recipient_reaches_
KARST_AQUIFER_NODE_B_BIN=/tmp/old-karstd \
  ./scripts/test-aquifer-container.sh exit_node_consent_survives
KARST_AQUIFER_TESTSERVER_BIN=/tmp/old-karst-testserver \
  ./scripts/test-aquifer-container.sh a_recipient_reaches_
```

The consent-restart scenario always starts the **current** node-B executable
for its final restart. With a legacy node-B override, it therefore tests an
actual client binary upgrade using the same configuration, identity and durable
consent file, without asking for consent again. With no override, it remains
the ordinary crash/restart regression. Old binaries need to support the selected
scenario; a missing flag or unsupported configuration fails the run.

These are real binary combinations against production control-channel code in
a fixture process. They do not replace verification of the production management
deployment, its database upgrade, account authorization or native OS integration.
