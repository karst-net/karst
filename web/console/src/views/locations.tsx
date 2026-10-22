// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { useState } from "react";
import { Dialog, EmptyState } from "@karst-net/ui";
import type { DiscoveredResource, Location } from "@karst-net/api-client";
import { api } from "../api";
import { Failure, Notice, Rows, useMutation, useResource } from "../common";
import { TutorialHint } from "../tutorial";

type Draft = { lat: string; lon: string; label: string; kind: string };
const blank: Draft = { lat: "", lon: "", label: "", kind: "" };

type Source = "manual" | "connection";

export function Locations() {
  const resource = useResource(api.locations);
  const { message, setMessage, run } = useMutation(resource.reload);
  const [draft, setDraft] = useState<Draft>();
  const [source, setSource] = useState<Source>("manual");
  const infraConnections = useResource(api.infrastructureConnections);
  const [connectionId, setConnectionId] = useState("");
  const resources = useResource(() => connectionId ? api.infrastructureConnectionResources(connectionId) : Promise.resolve([] as DiscoveredResource[]), [connectionId]);
  const [resourceCode, setResourceCode] = useState("");
  // Local zones enabled this session, ahead of resources.reload() catching up --
  // enabling one should not force the live region/zone list to be re-fetched
  // just to notice. Keyed by code; outlives a single dialog session like
  // connectionId/source below, for the same reason.
  const [enabledOverrides, setEnabledOverrides] = useState<Record<string, true>>({});
  const [enabling, setEnabling] = useState(false);

  if (resource.loading) return <p>Loading authorized locations…</p>;
  if (resource.error) return <Failure message={resource.error} retry={resource.reload} />;
  const locations = resource.value ?? [];
  const connectionsAvailable = (infraConnections.value ?? []).length > 0;
  const selectedConnection = (infraConnections.value ?? []).find((c) => c.id === connectionId);
  const selectedResource = (resources.value ?? []).find((r) => r.code === resourceCode);
  // A read_write AWS connection's not-yet-opted-in local zone --
  // enableInfrastructureConnectionRegion exists for exactly this (ADR-0045
  // §6's second addendum). Only a Local Zone has an opt-in-zone concept at
  // all: a region is always enabled, and a Kubernetes namespace's `enabled`
  // is simply absent (not false), so gating on the resource's own kind
  // rather than a generic falsy check keeps this from misfiring on either.
  const needsEnable = Boolean(selectedResource && selectedResource.kind === "local_zone" && !selectedResource.enabled && !enabledOverrides[selectedResource.code]);

  // Resets only the manual-entry draft -- source/connectionId/resourceCode
  // deliberately survive a reopen (cleared only by picking a different
  // connection, or never, for the life of this view) so that adding several
  // zones/namespaces from the same connection doesn't mean re-fetching that
  // connection's live resource list on every single reopen.
  const openDialog = () => { setDraft(blank); setResourceCode(""); };

  const add = async () => {
    if (!draft) return;
    const lat = Number(draft.lat), lon = Number(draft.lon);
    if (!Number.isFinite(lat) || lat < -90 || lat > 90) { setMessage("Latitude must be a number between -90 and 90."); return; }
    if (!Number.isFinite(lon) || lon < -180 || lon > 180) { setMessage("Longitude must be a number between -180 and 180."); return; }
    const entry = { lat, lon, label: draft.label.trim() || undefined, kind: draft.kind.trim() || undefined };
    if (await run(() => api.addLocation(entry), `${entry.label || `${lat}, ${lon}`} was added to the authorized locations registry.`)) setDraft(undefined);
  };
  const addFromConnection = async () => {
    const connection = selectedConnection;
    const item = selectedResource;
    if (!connection || !item) { setMessage("Choose an infrastructure connection and a region, namespace, or datacenter."); return; }
    if (needsEnable) { setMessage(`${item.name || item.code} is not enabled yet — enable it first.`); return; }
    // A namespace or datacenter has no coordinates of its own -- fall back
    // to the connection's own operator-declared location, if any (see
    // Settings).
    const noCatalogGeography = item.kind === "namespace" || item.kind === "datacenter";
    const lat = item.lat ?? connection.lat;
    const lon = item.lon ?? connection.lon;
    if (lat === undefined || lon === undefined) {
      const subject = noCatalogGeography ? "This connection" : (item.name || item.code);
      setMessage(`${subject} has no known coordinates yet — ${noCatalogGeography ? "declare the connection's location in Settings" : "add it to the cloud catalog"}, or declare it manually.`);
      return;
    }
    const label = item.name ? `${item.name} (${item.code})` : item.code;
    const entry = { lat, lon, label, kind: `${connection.type}-${item.kind}` };
    // Stay open and keep the already-fetched resource list -- adding
    // several zones/namespaces from the same connection used to mean
    // re-fetching that list live from the provider for every single one.
    if (await run(() => api.addLocation(entry), `${label} was added to the authorized locations registry.`)) setResourceCode("");
  };
  const enableZone = async () => {
    const connection = selectedConnection;
    const item = selectedResource;
    if (!connection || !item) return;
    if (!confirm(`Enable ${item.name || item.code} for use on this AWS account?\n\nThis opts the zone into use (AWS's ModifyAvailabilityZoneGroup) and cannot be undone through the API -- AWS Support must be contacted to opt back out. It does not itself create any resource or incur any charge; it only makes launching one there possible going forward.`)) return;
    if (!item.parent_region) { setMessage(`${item.name || item.code} has no known parent region to enable it against.`); return; }
    setEnabling(true);
    try {
      await api.enableInfrastructureConnectionRegion(connection.id, item.code, item.parent_region);
      setEnabledOverrides((current) => ({ ...current, [item.code]: true }));
      setMessage(`${item.name || item.code} is now enabled.`);
    } catch (error) {
      setMessage((error as Error).message);
    } finally {
      setEnabling(false);
    }
  };
  const remove = (location: Location) => {
    if (!confirm(`Remove ${location.label || `${location.lat}, ${location.lon}`} from the authorized locations registry?`)) return;
    void run(() => api.removeLocation(location.id), `${location.label || `${location.lat}, ${location.lon}`} was removed.`);
  };

  return <section>
    <h2>Authorized locations</h2>
    <TutorialHint>Sites this deployment is authorized to place infrastructure at — AWS local zones, datacenters, or anywhere else an operator wants to pre-declare. The NOC map draws every one of these as a hollow marker, whether or not anything is deployed there yet. This registry does not restrict where a relay or other component may actually declare its own location — it is informational, not an enforcement gate. A location is a logical entry here, not a running component: it only becomes "occupied" once something else (a relay) declares the same place.</TutorialHint>
    <div className="actions"><button className="primary" onClick={openDialog}>Add authorized location</button></div>
    <Notice message={message} />
    {locations.length === 0
      ? <EmptyState title="No authorized locations">Add one to see it on the NOC map as an available, unoccupied site.</EmptyState>
      : <Rows head={<><th>Label</th><th>Kind</th><th>Coordinates</th><th>Actions</th></>}>
        {locations.map((location) => <tr key={location.id}>
          <td>{location.label || <span className="lede">—</span>}</td>
          <td>{location.kind || <span className="lede">—</span>}</td>
          <td><code>{location.lat}, {location.lon}</code></td>
          <td><button className="danger" onClick={() => remove(location)}>Remove</button></td>
        </tr>)}
      </Rows>}

    <Dialog open={Boolean(draft)} title="Add authorized location" onClose={() => setDraft(undefined)}>
      <fieldset>
        <label><input type="radio" name="location-source" checked={source === "manual"} onChange={() => setSource("manual")} /> Manual coordinates</label>
        <label>
          <input type="radio" name="location-source" checked={source === "connection"} disabled={!connectionsAvailable} onChange={() => setSource("connection")} /> From an infrastructure connection
          {!connectionsAvailable && <span className="lede"> (add one in Settings first)</span>}
        </label>
      </fieldset>

      {source === "manual"
        ? <form onSubmit={(event) => { event.preventDefault(); void add(); }}>
          <label>Latitude<input aria-label="Location latitude" placeholder="51.5072" value={draft?.lat ?? ""} onChange={(event) => setDraft((current) => current && { ...current, lat: event.target.value })} /></label>
          <label>Longitude<input aria-label="Location longitude" placeholder="-0.1276" value={draft?.lon ?? ""} onChange={(event) => setDraft((current) => current && { ...current, lon: event.target.value })} /></label>
          <label>Label<input aria-label="Location label" placeholder="London" value={draft?.label ?? ""} onChange={(event) => setDraft((current) => current && { ...current, label: event.target.value })} /></label>
          <label>Kind<input aria-label="Location kind" placeholder="aws-local-zone" value={draft?.kind ?? ""} onChange={(event) => setDraft((current) => current && { ...current, kind: event.target.value })} /></label>
          <p className="lede">Kind is a free-text tag for your own reference — "datacenter", "aws-region", "aws-local-zone", or anything else. Not validated against any fixed list.</p>
          <div className="actions"><button type="button" onClick={() => setDraft(undefined)}>Cancel</button><button className="primary" type="submit">Add location</button></div>
        </form>
        : <form onSubmit={(event) => { event.preventDefault(); void addFromConnection(); }}>
          <label>Infrastructure connection<select aria-label="Infrastructure connection" value={connectionId} onChange={(event) => { setConnectionId(event.target.value); setResourceCode(""); }}>
            <option value="">Choose one…</option>
            {(infraConnections.value ?? []).map((c) => <option key={c.id} value={c.id}>{c.label || c.type} ({c.type.toUpperCase()})</option>)}
          </select></label>
          {connectionId && (resources.loading
            ? <p>Loading regions/namespaces…</p>
            : resources.error
              ? <Failure message={resources.error} retry={resources.reload} />
              : <label>Region, zone, namespace, or datacenter<select aria-label="Region, zone, namespace, or datacenter" value={resourceCode} onChange={(event) => setResourceCode(event.target.value)}>
                <option value="">Choose one…</option>
                {(resources.value ?? []).map((r) => <option key={r.code} value={r.code}>
                  {r.name ? `${r.name} (${r.code})` : r.code}
                  {r.lat === undefined ? " — no coordinates yet" : ""}
                  {r.kind === "local_zone" && !r.enabled && !enabledOverrides[r.code] ? " — not enabled yet" : ""}
                </option>)}
              </select></label>)}
          {needsEnable && selectedResource && <p className="lede">
            {selectedResource.name || selectedResource.code} exists on this account but is not opted into use yet. Enabling it is a one-way AWS change (no opt-out API) that makes the zone launchable — it does not by itself create anything or incur a charge.
          </p>}
          <div className="actions">
            <button type="button" onClick={() => setDraft(undefined)}>Cancel</button>
            {needsEnable
              ? <button className="primary" type="button" disabled={!connectionId || !resourceCode || enabling} onClick={() => void enableZone()}>{enabling ? "Enabling…" : "Enable this zone"}</button>
              : <button className="primary" type="submit" disabled={!connectionId || !resourceCode}>Add location</button>}
          </div>
        </form>}
    </Dialog>
  </section>;
}
