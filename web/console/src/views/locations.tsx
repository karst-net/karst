// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { useState } from "react";
import { Dialog, EmptyState } from "@karst-net/ui";
import type { DiscoveredRegion, Location } from "@karst-net/api-client";
import { api } from "../api";
import { Failure, Notice, Rows, useMutation, useResource } from "../common";
import { TutorialHint } from "../tutorial";

type Draft = { lat: string; lon: string; label: string; kind: string };
const blank: Draft = { lat: "", lon: "", label: "", kind: "" };

type Source = "manual" | "cloud";

export function Locations() {
  const resource = useResource(api.locations);
  const { message, setMessage, run } = useMutation(resource.reload);
  const [draft, setDraft] = useState<Draft>();
  const [source, setSource] = useState<Source>("manual");
  const cloudAccounts = useResource(api.cloudAccounts);
  const [cloudAccountId, setCloudAccountId] = useState("");
  const regions = useResource(() => cloudAccountId ? api.cloudAccountRegions(cloudAccountId) : Promise.resolve([] as DiscoveredRegion[]), [cloudAccountId]);
  const [regionCode, setRegionCode] = useState("");

  if (resource.loading) return <p>Loading authorized locations…</p>;
  if (resource.error) return <Failure message={resource.error} retry={resource.reload} />;
  const locations = resource.value ?? [];
  const cloudAccountsAvailable = (cloudAccounts.value ?? []).length > 0;

  const openDialog = () => { setDraft(blank); setSource("manual"); setCloudAccountId(""); setRegionCode(""); };

  const add = async () => {
    if (!draft) return;
    const lat = Number(draft.lat), lon = Number(draft.lon);
    if (!Number.isFinite(lat) || lat < -90 || lat > 90) { setMessage("Latitude must be a number between -90 and 90."); return; }
    if (!Number.isFinite(lon) || lon < -180 || lon > 180) { setMessage("Longitude must be a number between -180 and 180."); return; }
    const entry = { lat, lon, label: draft.label.trim() || undefined, kind: draft.kind.trim() || undefined };
    if (await run(() => api.addLocation(entry), `${entry.label || `${lat}, ${lon}`} was added to the authorized locations registry.`)) setDraft(undefined);
  };
  const addFromCloud = async () => {
    const account = (cloudAccounts.value ?? []).find((a) => a.id === cloudAccountId);
    const region = (regions.value ?? []).find((r) => r.code === regionCode);
    if (!account || !region) { setMessage("Choose a cloud account and a region."); return; }
    if (region.lat === undefined || region.lon === undefined) { setMessage(`${region.name || region.code} has no known coordinates yet — add it to the cloud catalog, or declare it manually.`); return; }
    const label = region.name ? `${region.name} (${region.code})` : region.code;
    const entry = { lat: region.lat, lon: region.lon, label, kind: `${account.provider}-${region.kind}` };
    if (await run(() => api.addLocation(entry), `${label} was added to the authorized locations registry.`)) setDraft(undefined);
  };
  const remove = (location: Location) => {
    if (!confirm(`Remove ${location.label || `${location.lat}, ${location.lon}`} from the authorized locations registry?`)) return;
    void run(() => api.removeLocation(location.id), `${location.label || `${location.lat}, ${location.lon}`} was removed.`);
  };

  return <section>
    <h2>Authorized locations</h2>
    <TutorialHint>Sites this deployment is authorized to place infrastructure at — AWS local zones, datacenters, or anywhere else an operator wants to pre-declare. The NOC map draws every one of these as a hollow marker, whether or not anything is deployed there yet. This registry does not restrict where a relay, TURN server, or other component may actually declare its own location — it is informational, not an enforcement gate. A location is a logical entry here, not a running component: it only becomes "occupied" once something else (a relay, a TURN server) declares the same place.</TutorialHint>
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
          <input type="radio" name="location-source" checked={source === "cloud"} disabled={!cloudAccountsAvailable} onChange={() => setSource("cloud")} /> From a cloud account
          {!cloudAccountsAvailable && <span className="lede"> (add one in Settings first)</span>}
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
        : <form onSubmit={(event) => { event.preventDefault(); void addFromCloud(); }}>
          <label>Cloud account<select aria-label="Cloud account" value={cloudAccountId} onChange={(event) => { setCloudAccountId(event.target.value); setRegionCode(""); }}>
            <option value="">Choose one…</option>
            {(cloudAccounts.value ?? []).map((a) => <option key={a.id} value={a.id}>{a.label || a.provider} ({a.provider.toUpperCase()})</option>)}
          </select></label>
          {cloudAccountId && (regions.loading
            ? <p>Loading regions…</p>
            : regions.error
              ? <Failure message={regions.error} retry={regions.reload} />
              : <label>Region / zone<select aria-label="Cloud region or zone" value={regionCode} onChange={(event) => setRegionCode(event.target.value)}>
                <option value="">Choose one…</option>
                {(regions.value ?? []).map((r) => <option key={r.code} value={r.code}>{r.name ? `${r.name} (${r.code})` : r.code}{r.lat === undefined ? " — no coordinates yet" : ""}</option>)}
              </select></label>)}
          <div className="actions"><button type="button" onClick={() => setDraft(undefined)}>Cancel</button><button className="primary" type="submit" disabled={!cloudAccountId || !regionCode}>Add location</button></div>
        </form>}
    </Dialog>
  </section>;
}
