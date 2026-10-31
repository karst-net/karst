// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import type { NodeSoftware } from "@karst-net/api-client";
import { Observed } from "@karst-net/ui";
import { api } from "../api";
import { useResource } from "../common";

export function ClientVersion({ software }: { software?: NodeSoftware }) {
  const control = useResource(api.softwareVersions, [software]);
  return <ClientVersionObservation software={software} controlVersion={control.value?.control.version} />;
}

export function ClientVersionObservation({ software, controlVersion }: { software?: NodeSoftware; controlVersion?: string }) {
  const version = software?.version?.trim();
  const known = !!version && !["unknown", "dev", "development"].includes(version.toLowerCase());
  const received = software?.observed_at ? Date.parse(software.observed_at) : NaN;
  const observation = !known || !Number.isFinite(received) || received > Date.now() + 60_000
    ? "Unknown" : Date.now() - received > 15 * 60_000 ? "Stale" : "Current";
  const controlKnown = controlVersion && !["unknown", "dev", "development"].includes(controlVersion.toLowerCase());
  const drift = known && controlKnown && version !== controlVersion;
  return <section aria-label="Agent software version">
    <h3>Agent software version</h3>
    <p>Reported release: <code>{known ? version : "Unknown"}</code>. Observation status: {observation}.</p>
    <p>Last report received: <Observed at={software?.observed_at} />. Reports older than 15 minutes are stale. This is self-reported running software, not a desired version. Agents report during control synchronization, independently of compliance collection. Refresh retrieves the latest retained observation; it does not contact the device.</p>
    <p>Build revision: <code>{software?.revision || "Unknown"}</code>. Artifact identity: <code>{software?.artifact_id || "Unknown"}</code>.</p>
    {drift ? <p role="status">Client and control releases differ (control: {controlVersion}). Compatibility is unverified. Align the device and control server to the same release, restart the device agent, and refresh after it reports again.</p>
      : <p>Compatibility is unverified; release versions alone do not establish protocol compatibility.</p>}
  </section>;
}
