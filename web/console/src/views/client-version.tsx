// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import type { NodeCompliance } from "@karst-net/api-client";
import { Observed } from "@karst-net/ui";
import { api } from "../api";
import { useResource } from "../common";

export function ClientVersion({ evidence }: { evidence: NodeCompliance }) {
  const control = useResource(api.softwareVersions);
  return <ClientVersionObservation evidence={evidence} controlVersion={control.value?.control.version} />;
}

export function ClientVersionObservation({ evidence, controlVersion }: { evidence: NodeCompliance; controlVersion?: string }) {
  const version = evidence.status === "reported" && evidence.client_version_status === "collected"
    ? evidence.client_version?.trim() : undefined;
  const known = !!version && !["unknown", "dev", "development"].includes(version.toLowerCase());
  const received = evidence.received_at ? Date.parse(evidence.received_at) : NaN;
  const observation = !known || !Number.isFinite(received) || received > Date.now() + 60_000
    ? "Unknown" : Date.now() - received > 15 * 60_000 ? "Stale" : "Current";
  const controlKnown = controlVersion && !["unknown", "dev", "development"].includes(controlVersion.toLowerCase());
  const drift = known && controlKnown && version !== controlVersion;
  return <section aria-label="Client software version">
    <h3>Client software version</h3>
    <p>Reported release: <code>{known ? version : "Unknown"}</code>. Observation status: {observation}.</p>
    {evidence.client_version_status && evidence.client_version_status !== "collected" && <p>Version collection: {evidence.client_version_status.replaceAll("-", " ")}.</p>}
    <p>Last report received: <Observed at={evidence.received_at} />. Reports older than 15 minutes are stale. This is self-reported running software, not a desired version. Refresh retrieves retained evidence; it does not contact the device.</p>
    <p>Build revision: Unknown. Artifact identity: Unknown. This device report does not include these identities.</p>
    {drift ? <p role="status">Client and control releases differ (control: {controlVersion}). Compatibility is unverified. Align the device and control server to the same release, restart the device agent, and refresh after it reports again.</p>
      : <p>Compatibility is unverified; release versions alone do not establish protocol compatibility.</p>}
  </section>;
}
