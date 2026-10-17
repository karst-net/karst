// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { useState } from "react";
import { Dialog, EmptyState } from "@karst-net/ui";
import type { Location } from "@karst-net/api-client";
import { api } from "../api";
import { Failure, Notice, Rows, useMutation, useResource } from "../common";

type Draft = { lat: string; lon: string; label: string; kind: string };
const blank: Draft = { lat: "", lon: "", label: "", kind: "" };

export function Locations() {
  const resource = useResource(api.locations);
  const { message, setMessage, run } = useMutation(resource.reload);
  const [draft, setDraft] = useState<Draft>();

  if (resource.loading) return <p>Loading authorized locations…</p>;
  if (resource.error) return <Failure message={resource.error} retry={resource.reload} />;
  const locations = resource.value ?? [];

  const add = async () => {
    if (!draft) return;
    const lat = Number(draft.lat), lon = Number(draft.lon);
    if (!Number.isFinite(lat) || lat < -90 || lat > 90) { setMessage("Latitude must be a number between -90 and 90."); return; }
    if (!Number.isFinite(lon) || lon < -180 || lon > 180) { setMessage("Longitude must be a number between -180 and 180."); return; }
    const entry = { lat, lon, label: draft.label.trim() || undefined, kind: draft.kind.trim() || undefined };
    if (await run(() => api.addLocation(entry), `${entry.label || `${lat}, ${lon}`} was added to the authorized locations registry.`)) setDraft(undefined);
  };
  const remove = (location: Location) => {
    if (!confirm(`Remove ${location.label || `${location.lat}, ${location.lon}`} from the authorized locations registry?`)) return;
    void run(() => api.removeLocation(location.id), `${location.label || `${location.lat}, ${location.lon}`} was removed.`);
  };

  return <section>
    <h2>Authorized locations</h2>
    <p className="lede">Sites this deployment is authorized to place infrastructure at — AWS local zones, datacenters, or anywhere else an operator wants to pre-declare. The NOC map draws every one of these as a hollow marker, whether or not anything is deployed there yet. This registry does not restrict where a relay, TURN server, or other component may actually declare its own location — it is informational, not an enforcement gate.</p>
    <div className="actions"><button className="primary" onClick={() => setDraft(blank)}>Add authorized location</button></div>
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
      <form onSubmit={(event) => { event.preventDefault(); void add(); }}>
        <label>Latitude<input aria-label="Location latitude" placeholder="51.5072" value={draft?.lat ?? ""} onChange={(event) => setDraft((current) => current && { ...current, lat: event.target.value })} /></label>
        <label>Longitude<input aria-label="Location longitude" placeholder="-0.1276" value={draft?.lon ?? ""} onChange={(event) => setDraft((current) => current && { ...current, lon: event.target.value })} /></label>
        <label>Label<input aria-label="Location label" placeholder="London" value={draft?.label ?? ""} onChange={(event) => setDraft((current) => current && { ...current, label: event.target.value })} /></label>
        <label>Kind<input aria-label="Location kind" placeholder="aws-local-zone" value={draft?.kind ?? ""} onChange={(event) => setDraft((current) => current && { ...current, kind: event.target.value })} /></label>
        <p className="lede">Kind is a free-text tag for your own reference — "datacenter", "aws-region", "aws-local-zone", or anything else. Not validated against any fixed list.</p>
        <div className="actions"><button type="button" onClick={() => setDraft(undefined)}>Cancel</button><button className="primary" type="submit">Add location</button></div>
      </form>
    </Dialog>
  </section>;
}
