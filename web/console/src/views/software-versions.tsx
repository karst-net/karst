// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { Observed } from "@karst-net/ui";
import { api } from "../api";
import { Failure, Rows, useResource } from "../common";

export function SoftwareVersions() {
  const versions = useResource(api.softwareVersions);
  const controlVersion = versions.value?.control.version;
  const drift = controlVersion && controlVersion !== "unknown" && __KARST_UI_BUILD__.version !== "unknown" && controlVersion !== __KARST_UI_BUILD__.version;
  const observedAt = versions.value?.deployment?.observed_at;
  const observedTime = observedAt ? Date.parse(observedAt) : NaN;
  const observationStatus = !Number.isFinite(observedTime) || observedTime > Date.now() + 60_000
    ? "Unknown" : Date.now() - observedTime > 15 * 60_000 ? "Stale" : "Current";
  return <section aria-labelledby="software-versions">
    <h3 id="software-versions">Software versions</h3>
    <p>The UI build is loaded in this browser. The control server identifies the binary answering this request. Its artifact identity is the running executable digest; deployment image IDs are listed separately below.</p>
    <Rows head={<><th>Component</th><th>Version</th><th>Commit</th><th>Artifact identity</th></>}>
      <tr><td>Admin console</td><td>{__KARST_UI_BUILD__.version}</td><td><code>{__KARST_UI_BUILD__.revision}</code></td><td>Unknown</td></tr>
      <tr><td>Control server</td><td>{versions.value?.control.version ?? "Unknown"}</td><td><code>{versions.value?.control.revision ?? "Unknown"}</code></td><td><code>{versions.value?.control.artifact_id || "Unknown"}</code></td></tr>
    </Rows>
    {drift && <p role="status">Console and control releases differ. Compatibility is unverified. Upgrade the control server and console to the same release, then reload this page before retrying failed operations.</p>}
    <button onClick={versions.reload}>Refresh component versions</button>
    {versions.loading && <p>Loading component versions…</p>}
    {versions.error && <Failure message={versions.error} retry={versions.reload} />}
    {versions.value?.deployment ? <>
      <p>Deployment snapshot observed <Observed at={versions.value.deployment.observed_at} />. Changes since this observation may not be reflected here.</p>
      <p>Observation status: {observationStatus}. Snapshots older than 15 minutes are stale. Refresh retrieves the latest available snapshot; it does not collect a new observation. These are observed running artifacts, not desired deployment versions. Releases and revisions come from the observed image’s labels; tags alone do not establish a release.</p>
      <Rows head={<><th>Service</th><th>Observed release / revision</th><th>Image / tags</th><th>Running image ID</th><th>State at observation</th></>}>
        {versions.value.deployment.components.map((component) => <tr key={component.name}>
          <td>{component.name}</td><td>{component.version || "Unknown"}<br /><code>{component.revision || "Unknown"}</code></td><td><code>{component.image}</code><br />{component.tags.join(", ") || "No release tag reported"}</td>
          <td><code>{component.image_id || "Unknown"}</code></td><td>{component.state}</td>
        </tr>)}
      </Rows>
    </> : versions.value && <p>Deployment component versions are {versions.value.deployment_status === "unavailable" ? "unavailable" : "not configured"}.</p>}
  </section>;
}
