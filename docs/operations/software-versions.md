<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Observed software versions

In the administrative console, open **Machines → Status → Software version**
for an enrolled device, or expand **Agent software** in the Gateway inventory
under network route metrics. The running agent reports its release and source
revision during control synchronization. Gateway agents and desktop/mobile
agents using the shared engine use the same reporting path. Compliance
collection does not need to be enabled.

The receipt time belongs to the software report. A recent peer connection,
enrollment, or compliance report does not refresh it. Reports older than
15 minutes appear stale. Refresh retrieves the latest stored report; it does
not request an immediate device observation. A stale value describes what the
agent last reported, rather than proving what is running now.

An older agent with no software report appears unknown. If it previously
reported a build, a later legacy request leaves that observation and its
original receipt time intact. Upgrade the agent and allow it to synchronize
with control to obtain a new observation. Invalid software fields are ignored
without preventing netmap synchronization or refreshing the old receipt time.

The agent hashes its running executable in the background so observing software
cannot delay control synchronization or local status requests. Artifact identity
is unknown until that observation completes and appears on a later report.

Release, revision, and artifact identity are independent fields. The shared
agent reports release and source revision. On Linux it also reports
`sha256:<digest>` of the running process executable, read through
`/proc/self/exe` and cached for that process. This remains the old executable's
identity if an upgrade replaces its installed pathname while it is running.
It identifies the process executable, not a package, container image, or
separately loaded library. On other platforms, or if the running executable
cannot be read, this identity remains unknown. A source revision is not a
binary or container digest. Missing fields replace previous values with
unknown, preventing an upgraded release from retaining an older build's
identity.

These are self-reported observations, not attestation or configured deployment
targets. Different client/control releases produce an upgrade advisory; equal
release strings do not establish protocol compatibility. Align the agent and
control releases, restart the agent, and refresh after synchronization when
investigating drift. Actual protocol capability checks remain independent of
these version labels.

**Settings → Software versions** also shows the browser's loaded console build,
the control binary answering the request, and any configured deployment
snapshot. The macOS menu shows the installed app release/build separately from
the responding agent's release/revision, which helps identify an extension
that has not yet been replaced after an app upgrade.

Deployment snapshots include release and source revision labels from each
container's observed immutable image ID. They never resolve labels through a
mutable configured tag. Old snapshots or images without labels show unknown
release/revision, even if an image has release-looking tags. Newly built Karst
client, relay, control, and console images carry these OCI labels. Run
`scripts/compose-versions.py --output <snapshot-path>` from the Compose project
directory after deployment to refresh the configured snapshot.

For Nomad's Docker driver, run the same collector on the Docker host with
`--nomad-job <exact-job-id> --nomad-namespace <namespace>`. It selects local
containers by their allocation IDs after querying the exact job/namespace;
it does not copy desired image references from the job definition. The
production Nomad deployment already mounts the snapshot directory. See its
[collection instructions](../../deploy/nomad/prod/README.md#observed-system-versions).

The responding control server also identifies its own process executable on
Linux using the same running-inode SHA-256 observation. This is available even
without a Compose/Nomad deployment snapshot. It is displayed separately from
the container image ID. Non-Linux control servers and read failures retain an
unknown artifact identity; no installed pathname is substituted for a running
image observation.
