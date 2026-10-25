// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { useState } from "react";
import { Dialog, EmptyState } from "@karst-net/ui";
import { GroupDeletion } from "./group-deletion";
import { api, type Group } from "../api";
import { Failure, Notice, Rows, useMutation, useResource } from "../common";

// A group synchronised from an identity provider is a copy, not a source. The
// server rejects an edit to one, and the rejection arrives too late to be
// useful — so the console does not offer the button in the first place and says
// why in the row itself.
const editable = (group: Group) => (group.issued ?? "api") === "api" && group.name !== "All";

export function Groups() {
  const resource = useResource(api.groups);
  const policy = useResource(api.policy);
  const relayAccess = useResource(api.relayServices);
  const peerResource = useResource(api.groupPeers);
  const [membership, setMembership] = useState<{ group: Group; peers: string[] }>();
  const [membershipBusy, setMembershipBusy] = useState(false);
  const grants: import("../access-model").AccessGrant[] = (() => { try { return JSON.parse(policy.value?.document ?? "{}").grants ?? []; } catch { return []; } })();
  const referencing = (group: Group) => grants.filter(grant => grant.source_groups.includes(group.id) || grant.target_groups?.includes(group.id));
  const groupLocations = useResource(api.groupLocations);
  const locationByGroup = new Map((groupLocations.value ?? []).map((gl) => [gl.group_id, gl]));
  const { message, setMessage, run } = useMutation(() => { resource.reload(); groupLocations.reload(); });
  const [deleting, setDeleting] = useState<string>();
  const [creating, setCreating] = useState<string>();
  const [renaming, setRenaming] = useState<{ group: Group; name: string }>();
  const [locating, setLocating] = useState<{ group: Group; lat: string; lon: string; label: string }>();

  if (resource.loading) return <p>Loading groups…</p>;
  if (resource.error) return <Failure message={resource.error} retry={resource.reload} />;
  const groups = resource.value ?? [];

  const create = async () => {
    const name = (creating ?? "").trim();
    if (!name) { setMessage("A group needs a name."); return; }
    if (await run(() => api.createGroup(name), `Group ${name} was created.`)) setCreating(undefined);
  };
  const rename = async () => {
    if (!renaming) return;
    const name = renaming.name.trim();
    if (!name) { setMessage("A group needs a name."); return; }
    if (await run(() => api.renameGroup(renaming.group.id, name), `Group ${renaming.group.name} is now named ${name}.`)) setRenaming(undefined);
  };
  const saveLocation = async () => {
    if (!locating) return;
    const lat = Number(locating.lat), lon = Number(locating.lon);
    if (!Number.isFinite(lat) || lat < -90 || lat > 90) { setMessage("Latitude must be a number between -90 and 90."); return; }
    if (!Number.isFinite(lon) || lon < -180 || lon > 180) { setMessage("Longitude must be a number between -180 and 180."); return; }
    const label = locating.label.trim() || undefined;
    if (await run(() => api.setGroupLocation(locating.group.id, { lat, lon, label }), `${locating.group.name}'s location was declared.`)) setLocating(undefined);
  };
  const clearLocation = (group: Group) => {
    if (!confirm(`Clear ${group.name}'s declared location? Any exit-node/subnet-router marker this group places on the NOC map disappears.`)) return;
    void run(() => api.removeGroupLocation(group.id), `${group.name}'s declared location was cleared.`);
  };

  return <section>
    <h3>Groups</h3>
    <p className="lede">Groups are what access rules name. Groups synchronised from an identity provider are managed there and are read-only here.</p>
    <div className="actions"><button className="primary" onClick={() => setCreating("")}>Create group</button></div>
    <Notice message={message} />
    {groups.length === 0
      ? <EmptyState title="No groups">Groups from your identity provider will appear here.</EmptyState>
      : <Rows head={<><th>Name</th><th>Members</th><th>Resources</th><th>Source</th><th>Access rules</th><th>Location</th><th>Actions</th></>}>
        {groups.map((group) => {
          const related = referencing(group);
          const location = locationByGroup.get(group.id);
          return <tr key={group.id}>
            <td><strong>{group.name}</strong><br /><code>{group.id}</code></td>
            <td>{group.peers_count}</td>
            <td>{group.resources_count}</td>
            <td>{group.issued ?? "api"}</td>
            <td>{relayAccess.value?.filter(service => service.allowed_groups?.includes(group.id)).map(service => <p key={service.id}><a href="#/relays">Relay {service.id}</a></p>)}{related.length > 0
              ? <a href="#/groups/access">{related.length} access grant{related.length === 1 ? "" : "s"}</a>
              : <span className="lede">{policy.error ? "Access unavailable" : "None"}</span>}</td>
            <td>{location ? (location.label || `${location.lat}, ${location.lon}`) : <span className="lede">No location</span>}</td>
            <td><div className="actions">
              {editable(group) && <button onClick={() => { setMembershipBusy(true); void api.group(group.id).then(current => setMembership({ group: current, peers: current.peers?.map(peer => peer.id) ?? [] })).catch(error => setMessage((error as Error).message)).finally(() => setMembershipBusy(false)); }} disabled={membershipBusy}>Members of {group.name}</button>}
              {editable(group) && <button onClick={() => setRenaming({ group, name: group.name })}>Rename</button>}
              <button onClick={() => setLocating({ group, lat: location ? String(location.lat) : "", lon: location ? String(location.lon) : "", label: location?.label ?? "" })}>{location ? "Edit location" : "Set location"}</button>
              {location && <button onClick={() => clearLocation(group)}>Clear location</button>}
              {editable(group) && <button className="danger" onClick={() => setDeleting(group.id)}>Delete</button>}
              {!editable(group) && <span className="lede">{group.name === "All" ? "Built in" : "Managed by the identity provider"}</span>}
            </div></td>
          </tr>;
        })}
      </Rows>}

    {deleting && <GroupDeletion id={deleting} onClose={() => setDeleting(undefined)} onDeleted={name => { setDeleting(undefined); setMessage(`Group ${name} was deleted.`); resource.reload(); policy.reload(); relayAccess.reload(); groupLocations.reload(); }} />}

    <Dialog open={creating !== undefined} title="Create group" onClose={() => setCreating(undefined)}>
      <form onSubmit={(event) => { event.preventDefault(); void create(); }}>
        <label>Group name<input aria-label="Group name" placeholder="sre" value={creating ?? ""} onChange={(event) => setCreating(event.target.value)} /></label>
        <p className="lede">Members are added by enrolling a machine with an auth key that auto-assigns this group, or by editing a user’s auto-assigned groups.</p>
        <div className="actions"><button type="button" onClick={() => setCreating(undefined)}>Cancel</button><button className="primary" type="submit">Create group</button></div>
      </form>
    </Dialog>

    <Dialog open={Boolean(renaming)} title="Rename group" onClose={() => setRenaming(undefined)}>
      <form onSubmit={(event) => { event.preventDefault(); void rename(); }}>
        <label>Group name<input aria-label="New group name" value={renaming?.name ?? ""} onChange={(event) => setRenaming((current) => current && { ...current, name: event.target.value })} /></label>
        <p className="lede">Access grants reference this group by its stable identity. Renaming preserves membership and form-managed access. Existing legacy policies remain unchanged.</p>
        <div className="actions"><button type="button" onClick={() => setRenaming(undefined)}>Cancel</button><button className="primary" type="submit">Save name</button></div>
      </form>
    </Dialog>

    <Dialog open={Boolean(locating)} title={locating ? `Declare ${locating.group.name}'s location` : ""} onClose={() => setLocating(undefined)}>
      <form onSubmit={(event) => { event.preventDefault(); void saveLocation(); }}>
        <p className="lede">This is where this group's machines are, for the NOC map only — it places a marker for any exit-node or subnet-router route whose routing group is this one.</p>
        <label>Latitude<input aria-label="Group latitude" placeholder="51.5072" value={locating?.lat ?? ""} onChange={(event) => setLocating((current) => current && { ...current, lat: event.target.value })} /></label>
        <label>Longitude<input aria-label="Group longitude" placeholder="-0.1276" value={locating?.lon ?? ""} onChange={(event) => setLocating((current) => current && { ...current, lon: event.target.value })} /></label>
        <label>Location label<input aria-label="Group location label" placeholder="London" value={locating?.label ?? ""} onChange={(event) => setLocating((current) => current && { ...current, label: event.target.value })} /></label>
        <div className="actions"><button type="button" onClick={() => setLocating(undefined)}>Cancel</button><button className="primary" type="submit">Save location</button></div>
      </form>
    </Dialog>

    {membership && <Dialog open title={`Members of ${membership.group.name}`} onClose={() => { if (!membershipBusy) setMembership(undefined); }}>
      <p>Membership changes affect access to resources assigned to this group.</p>
      {peerResource.error ? <Failure message={peerResource.error} retry={peerResource.reload} /> : <fieldset><legend>Machines</legend>{peerResource.value?.map(peer => <label key={peer.id}><input type="checkbox" checked={membership.peers.includes(peer.id)} onChange={event => setMembership({ ...membership, peers: event.target.checked ? [...membership.peers, peer.id] : membership.peers.filter(id => id !== peer.id) })} />{peer.name}</label>)}</fieldset>}
      <div className="actions"><button disabled={membershipBusy} onClick={() => setMembership(undefined)}>Cancel</button><button disabled={membershipBusy || peerResource.loading || Boolean(peerResource.error)} onClick={() => { setMembershipBusy(true); void run(() => api.setGroupMembers(membership.group.id, membership.peers), "Group membership saved.").then(saved => { if (saved) setMembership(undefined); }).finally(() => setMembershipBusy(false)); }}>Save members</button></div>
    </Dialog>}
  </section>;
}
