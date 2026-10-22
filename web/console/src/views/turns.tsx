// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { useState } from "react";
import { Dialog, EmptyState } from "@karst-net/ui";
import type { TurnServer } from "@karst-net/api-client";
import { api } from "../api";
import { Failure, Notice, Rows, useMutation, useResource } from "../common";
import { TutorialHint } from "../tutorial";

type Draft = { uri: string; region: string; locationId: string };
const blank: Draft = { uri: "", region: "default", locationId: "" };

// turncred.go's own validate() requires a turn: or turns: scheme (RFC 8656
// §3.1 / RFC 7065) and nothing else — this mirrors that check client-side so
// a malformed URI is rejected before a request is made, rather than after.
const uri = /^turns?:/;

export function Turns() {
  const resource = useResource(api.turns);
  const { message, setMessage, run } = useMutation(resource.reload);
  const locationsResource = useResource(api.locations);
  const [draft, setDraft] = useState<Draft>();

  if (resource.loading) return <p>Loading TURN servers…</p>;
  if (resource.error) return <Failure message={resource.error} retry={resource.reload} />;
  const turns = resource.value ?? [];
  const locations = locationsResource.value ?? [];
  const hasLocations = locations.length > 0;

  const add = async () => {
    if (!draft) return;
    const entry: { uri: string; region: string; location?: { lat: number; lon: number; label?: string } } = { uri: draft.uri.trim(), region: draft.region.trim() || "default" };
    if (!uri.test(entry.uri)) { setMessage("The URI must start with turn: or turns:, such as turn:turn.example.com:3478."); return; }
    const selected = locations.find((l) => l.id === draft.locationId);
    if (selected) entry.location = { lat: selected.lat, lon: selected.lon, label: selected.label || undefined };
    if (await run(() => api.addTurn(entry), `TURN server ${entry.uri} was added. Nodes pick it up with their next netmap.`)) setDraft(undefined);
  };
  const remove = (turn: TurnServer) => {
    if (!confirm(`Remove the TURN server at ${turn.uri}? Nodes that need TURN as a last-resort fallback lose it once their next netmap arrives.`)) return;
    void run(() => api.removeTurn(turn.id), `TURN server ${turn.uri} was removed.`);
  };

  return <section>
    <h2>TURN servers</h2>
    <TutorialHint>A TURN server is a real machine running a standard STUN/TURN implementation (RFC 8656) that relays traffic byte-for-byte when nothing smarter is possible — it has no idea what Karst is, it just forwards packets for whichever client/credential pair asks. ADR-0008 §4's last-resort fallback: every node is told about exactly the TURN servers listed here, for use only when a direct path and every relay have failed. A declared location is picked from Authorized Locations, so adding one needs at least one there first.</TutorialHint>
    <div className="actions"><button className="primary" disabled={!hasLocations} onClick={() => setDraft(blank)}>Add TURN server</button></div>
    {!hasLocations && <p className="lede">Add an authorized location first — see Authorized Locations. A TURN server's declared location is picked from that registry.</p>}
    <Notice message={message} />
    {turns.length === 0
      ? <EmptyState title="No TURN servers configured">A deployment with no TURN registry is unaffected: nodes simply have no last-resort fallback beyond direct paths and relays.</EmptyState>
      : <Rows head={<><th>Region</th><th>URI</th><th>Location</th><th>Actions</th></>}>
        {turns.map((turn) => <tr key={turn.id}>
          <td>{turn.region}</td>
          <td><code>{turn.uri}</code></td>
          <td>{turn.location ? (turn.location.label || `${turn.location.lat}, ${turn.location.lon}`) : <span className="lede">No location</span>}</td>
          <td><button className="danger" onClick={() => remove(turn)}>Remove</button></td>
        </tr>)}
      </Rows>}

    <Dialog open={Boolean(draft)} title="Add TURN server" onClose={() => setDraft(undefined)}>
      <form onSubmit={(event) => { event.preventDefault(); void add(); }}>
        <label>URI<input aria-label="TURN server URI" placeholder="turn:turn.example.com:3478" value={draft?.uri ?? ""} onChange={(event) => setDraft((current) => current && { ...current, uri: event.target.value })} /></label>
        <p className="lede">A turn: or turns: URI (RFC 8656 §3.1 / RFC 7065). The credential a node uses to authenticate to it is minted per response and never configured here.</p>
        <label>Region<input aria-label="TURN server region" value={draft?.region ?? ""} onChange={(event) => setDraft((current) => current && { ...current, region: event.target.value })} /></label>
        <label>Location<select aria-label="TURN server location" value={draft?.locationId ?? ""} onChange={(event) => setDraft((current) => current && { ...current, locationId: event.target.value })}>
          <option value="">No location</option>
          {locations.map((location) => <option key={location.id} value={location.id}>{location.label || `${location.lat}, ${location.lon}`}</option>)}
        </select></label>
        <p className="lede">Optional. Shown on the NOC map — never inferred from the URI, so a TURN server with no declared location shows there as unplaced rather than a guess.</p>
        <div className="actions"><button type="button" onClick={() => setDraft(undefined)}>Cancel</button><button className="primary" type="submit">Add TURN server</button></div>
      </form>
    </Dialog>
  </section>;
}
