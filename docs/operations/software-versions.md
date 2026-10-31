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

Release, revision, and artifact identity are independent fields. The shared
agent currently reports release and source revision; its artifact identity is
unknown. The API can retain an immutable image/artifact identity when an agent
reports one. A source revision is not a binary or container digest. Missing
fields replace previous values with unknown, preventing an upgraded release
from retaining an older build's identity.

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
