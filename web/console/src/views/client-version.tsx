// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import type { NodeControlCheck, NodeSoftware } from "@karst-net/api-client";
import { Observed } from "@karst-net/ui";
import { api } from "../api";
import { useObservationStatus } from "../observation-status";
import { useResource } from "../common";

export function ClientVersion({ software, controlCheck }: { software?: NodeSoftware; controlCheck?: NodeControlCheck }) {
  const control = useResource(api.softwareVersions, [software]);
  return <ClientVersionObservation software={software} controlCheck={controlCheck} controlVersion={control.value?.control.version} />;
}

export function ClientVersionObservation({ software, controlVersion, controlCheck }: { software?: NodeSoftware; controlVersion?: string; controlCheck?: NodeControlCheck }) {
  const version = software?.version?.trim();
  const known = !!version && !["unknown", "dev", "development"].includes(version.toLowerCase());
  const reportStatus = useObservationStatus(software?.observed_at);
  const observation = known ? reportStatus : "Unknown";
  const controlKnown = controlVersion && !["unknown", "dev", "development"].includes(controlVersion.toLowerCase());
  const drift = known && controlKnown && version !== controlVersion;
  return <section aria-label="Agent software version">
    <h3>Agent software version</h3>
    <p>Reported release: <code>{known ? version : "Unknown"}</code>. Observation status: {observation}.</p>
    <p>Last report received: <Observed at={software?.observed_at} />. Reports older than 15 minutes are stale. This is self-reported running software, not a desired version. Agents report during control synchronization, independently of compliance collection. Refresh retrieves the latest retained observation; it does not contact the device.</p>
    <p>Build revision: <code>{software?.revision || "Unknown"}</code>. Artifact identity: <code>{software?.artifact_id || "Unknown"}</code>.</p>
    <ControlCompatibility check={controlCheck} />
    {controlCheck?.status === "incompatible" ? null : drift ? <p role="status">Client and control releases differ (control: {controlVersion}). Compatibility is unverified. Align the device and control server to the same release, restart the device agent, and refresh after it reports again.</p>
      : <p>Compatibility is unverified; release versions alone do not establish protocol compatibility.</p>}
  </section>;
}

export function ControlCompatibility({ check }: { check?: NodeControlCheck }) {
  const freshness = useObservationStatus(check?.observed_at);
  if (!check) return <p>Last control check: Unknown. No capability check has been observed.</p>;
  return <section aria-label="Control compatibility check">
    <p>Last control check: {check.status === "incompatible" ? "Incompatible" : "Accepted"}. Observation status: {freshness}. Checked <Observed at={check.observed_at} />.</p>
    {check.status === "incompatible" ? <p role="status">
      {check.capability === "relay_lifecycle_schema"
        ? "The control server rejected this agent because its Relay service lifecycle capability does not meet the account’s requirements. Upgrade the agent to a release supporting live Relay service modes, then reconnect it to control."
        : check.capability === "gateway_ingress_schema"
          ? "The control server rejected this gateway because it does not support the configured destination-scoped ingress policy. Upgrade the gateway agent to a release supporting scoped ingress, then reconnect it to control."
          : "The control server rejected this agent’s capabilities. Upgrade the agent to a release supported by control, then reconnect it."}
      {check.capability && <> Required {check.capability}: {check.required_schema ?? "Unknown"}; reported: {check.reported_schema ?? "Unknown"}.</>}
    </p> : <p>The control server built a netmap for this agent at the last check. This does not establish that the agent applied it or that data-plane traffic works.</p>}
    <p>This records the last server capability evaluation. Changes since that check may not be reflected; checks older than 15 minutes are stale.</p>
  </section>;
}
