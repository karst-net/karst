// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { useState } from "react";
import { Dialog } from "@karst-net/ui";
import type { DiscoveredResource } from "@karst-net/api-client";
import { api } from "../api";
import { Failure, useResource } from "../common";
import { GroupPicker } from "./access";

/** Allocate a relay: name a host, pick its infrastructure connection and
 * location, and choose the groups permitted to use it once ready — issue
 * #439's own example, scoped to ADR-0063's v1 (relay transport only;
 * internet egress is not yet supported by this workflow, see
 * relayalloc.Store's own validation). Reuses locations.tsx's own
 * connection/discovery picker shape (not infrastructure-connections.tsx,
 * which is credential CRUD only) and access.tsx's GroupPicker, and follows
 * relay-access.tsx's review/apply dialog shape rather than building a new
 * one.
 *
 * Unlike locations.tsx's own picker, this one offers only resources already
 * in the Authorized Locations registry: an allocation provisions a real
 * host, so (per the operator's own request alongside ADR-0063) it is
 * deliberately coupled to that registry rather than following locationreg's
 * usual "not a foreign key" default. The server enforces this independently
 * (relayalloc.requireAuthorizedLocation) -- this filtering is for a sane
 * picker, not the actual guarantee.
 */
export function AllocateRelay({ onClose, onAllocated }: { onClose: () => void; onAllocated: () => void }) {
  const infraConnections = useResource(api.infrastructureConnections);
  const groups = useResource(api.groups);
  const authorizedLocations = useResource(api.locations);
  const [connectionId, setConnectionId] = useState("");
  const resources = useResource(() => connectionId ? api.infrastructureConnectionResources(connectionId) : Promise.resolve([] as DiscoveredResource[]), [connectionId]);
  const [resourceCode, setResourceCode] = useState("");
  const [name, setName] = useState("");
  const [permittedGroups, setPermittedGroups] = useState<string[]>([]);
  const [review, setReview] = useState(false);
  const [acknowledged, setAcknowledged] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string>();

  const selectedConnection = (infraConnections.value ?? []).find(c => c.id === connectionId);
  // A resource's own coordinates, falling back to its connection's declared
  // ones -- Kubernetes/Nomad/LXD resources never carry their own (see
  // DiscoveredResource's own doc), matching locations.tsx's identical
  // fallback for the same reason.
  const authorizedKeys = new Set((authorizedLocations.value ?? []).map(l => `${l.lat},${l.lon}`));
  const isAuthorized = (r: DiscoveredResource) => {
    const lat = r.lat ?? selectedConnection?.lat;
    const lon = r.lon ?? selectedConnection?.lon;
    return lat !== undefined && lon !== undefined && authorizedKeys.has(`${lat},${lon}`);
  };
  const authorizedResources = (resources.value ?? []).filter(isAuthorized);
  const selectedResource = authorizedResources.find(r => r.code === resourceCode);
  const notEnabled = Boolean(selectedResource && selectedResource.kind === "local_zone" && !selectedResource.enabled);
  const ready = Boolean(name.trim()) && Boolean(selectedConnection) && Boolean(selectedResource) && !notEnabled && permittedGroups.length > 0;

  const apply = async () => {
    setBusy(true); setMessage(undefined);
    try {
      await api.allocateRelay({ name: name.trim(), infra_connection_id: connectionId, location: resourceCode, relay_transport: true, permitted_groups: permittedGroups });
      onAllocated();
    } catch (error) { setMessage((error as Error).message); setReview(false); }
    finally { setBusy(false); }
  };

  return <Dialog open title="Allocate a relay" onClose={() => { if (!busy) onClose(); }}>
    {message && <p role="alert">{message}</p>}
    {infraConnections.error && <Failure message={infraConnections.error} retry={infraConnections.reload} />}
    {groups.error && <Failure message={groups.error} retry={groups.reload} />}
    <p>Provisions a new host through a real infrastructure connection and grants the selected groups access once it registers and is ready. Allocating, provisioning and granting access all happen in the background — this dialog does not wait for them.</p>
    {!review ? <form onSubmit={event => { event.preventDefault(); setReview(true); setAcknowledged(false); }}>
      <label>Name<input required maxLength={63} value={name} onChange={event => setName(event.target.value)} /></label>
      <label>Infrastructure connection<select aria-label="Infrastructure connection" required value={connectionId} onChange={event => { setConnectionId(event.target.value); setResourceCode(""); }}>
        <option value="">Choose one…</option>
        {(infraConnections.value ?? []).map(c => <option key={c.id} value={c.id}>{c.label || c.type} ({c.type.toUpperCase()})</option>)}
      </select></label>
      {!infraConnections.loading && (infraConnections.value ?? []).length === 0 && <p className="lede">Add an infrastructure connection in Settings first.</p>}
      {connectionId && (resources.loading || authorizedLocations.loading
        ? <p>Loading regions/zones/namespaces…</p>
        : resources.error
          ? <Failure message={resources.error} retry={resources.reload} />
          : authorizedLocations.error
            ? <Failure message={authorizedLocations.error} retry={authorizedLocations.reload} />
            : <><label>Location<select aria-label="Location" required value={resourceCode} onChange={event => setResourceCode(event.target.value)}>
              <option value="">Choose one…</option>
              {authorizedResources.map(r => <option key={r.code} value={r.code}>{r.name ? `${r.name} (${r.code})` : r.code}{r.kind === "local_zone" && !r.enabled ? " — not enabled yet" : ""}</option>)}
            </select></label>
            <p className="lede">Only locations already in Authorized Locations are offered. {authorizedResources.length === 0 ? "None of this connection's discovered regions/zones/namespaces are authorized yet — " : "Missing one? "}add it on the Authorized locations page first.</p></>)}
      {notEnabled && selectedResource && <p className="lede">{selectedResource.name || selectedResource.code} is not opted into use yet — enable it on the Authorized locations page first.</p>}
      <fieldset><legend>Capabilities</legend>
        <label><input type="checkbox" checked readOnly disabled />Relay transport</label>
        <p className="lede">Internet egress is not yet available through this workflow — it needs an explicitly bound Gateway identity this form does not collect yet. Configure access to this relay directly once it is ready if egress is needed.</p>
      </fieldset>
      <GroupPicker label="Permitted groups" groups={groups.value ?? []} value={permittedGroups} onChange={setPermittedGroups} />
      <div className="actions"><button type="button" disabled={busy} onClick={onClose}>Cancel</button><button className="primary" type="submit" disabled={!ready || busy || groups.loading}>Review allocation</button></div>
    </form> : <>
      <p>Name: <strong>{name}</strong></p>
      <p>Infrastructure connection: <strong>{selectedConnection?.label || selectedConnection?.type}</strong>. Location: <strong>{selectedResource?.name || resourceCode}</strong>.</p>
      <p>Permitted groups: {permittedGroups.map(id => groups.value?.find(g => g.id === id)?.name ?? "Unavailable group").join(", ")}.</p>
      <p>Provisioning a real host takes time; the new allocation shows as pending until it registers and access is granted. Deprovisioning later withdraws access before the host is destroyed.</p>
      <label><input type="checkbox" checked={acknowledged} onChange={event => setAcknowledged(event.target.checked)} />I reviewed this allocation.</label>
      <div className="actions"><button disabled={busy} onClick={() => setReview(false)}>Back</button><button className="primary" disabled={busy || !acknowledged} onClick={() => void apply()}>Apply allocation</button></div>
    </>}
  </Dialog>;
}
