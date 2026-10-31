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

## Control capability checks

Machine software details and Gateway inventory also show the last actual
control-server capability evaluation, independently of the software report's
receipt time. Machines with a recorded incompatibility are marked in the
status table; expand their software details for upgrade guidance.

An incompatible result identifies the capability and required/reported schema
that caused control to reject the netmap. Current checks cover live Relay
service lifecycle support and destination-scoped Gateway ingress. Upgrade the
agent to a release supporting the named feature and reconnect it to control.
Software identity is recorded before these checks, so an incompatible agent
can still be identified without SSH or logs.

Accepted means control successfully constructed a netmap at the displayed
time. It does not prove that the agent applied it or that data-plane traffic
works. A later successful netmap clears an earlier rejection. Unrelated
request failures do not erase or refresh that result. An absent check is
unknown, and checks older than 15 minutes are stale. Configuration changes
since the last check may not be reflected until the agent synchronizes again.

Capability evaluations are distinct from release drift advisories. Equal
release strings never imply acceptance; an actual rejection remains visible
even when the agent and control report the same release.

## Observation freshness while a page stays open

Freshness labels update while the console remains open, without contacting a
client, Docker, or Nomad. Aging the display never changes a stored observation's
timestamp. The control response has its own observation time, independently of
the retained deployment snapshot. Refreshing component versions obtains a new
control response while preserving the snapshot's original time. Older control
servers that omit the response timestamp show unknown control freshness.
