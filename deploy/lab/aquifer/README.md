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
