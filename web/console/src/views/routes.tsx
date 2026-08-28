// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { useState } from "react";
import { Dialog, EmptyState, Status } from "@karst-net/ui";
import { api, type NetworkRoute, type NetworkRouteDraft } from "../api";
import { Failure, Notice, Rows, idList, useMutation, useResource } from "../common";

const blank: NetworkRouteDraft = { network_id: "", description: "", enabled: true, network: "", peer_groups: [], groups: [], metric: 9999, masquerade: true, keep_route: false };
const cidr = /^(?:\d{1,3}(?:\.\d{1,3}){3}\/\d{1,2}|[0-9a-fA-F:]+\/\d{1,3})$/;

export function Routes() {
  const resource = useResource(api.routes);
  const { message, setMessage, run } = useMutation(resource.reload);
  const [draft, setDraft] = useState<{ value: NetworkRouteDraft; id?: string }>();

  if (resource.loading) return <p>Loading network routes…</p>;
  if (resource.error) return <Failure message={resource.error} retry={resource.reload} />;
  const routes = resource.value ?? [];

  const save = async () => {
    if (!draft) return;
    const value = { ...draft.value, network_id: draft.value.network_id.trim(), network: draft.value.network.trim() };
    if (!value.network_id) { setMessage("A route needs a short identifier — it is what appears on the machines that install it."); return; }
    if (!cidr.test(value.network)) { setMessage("The network must be a CIDR prefix, such as 10.10.0.0/16."); return; }
    if (value.peer_groups.length === 0) { setMessage("A route needs at least one routing group: the machines that will carry traffic into that network."); return; }
    if (value.groups.length === 0) { setMessage("A route needs at least one distribution group, or no machine is told the route exists."); return; }
    const done = draft.id
      ? await run(() => api.updateRoute(draft.id!, value), `Route ${value.network_id} was updated.`)
      : await run(() => api.createRoute(value), `Route ${value.network_id} was created.`);
    if (done) setDraft(undefined);
  };
  const remove = (route: NetworkRoute) => {
    if (!confirm(`Delete the route to ${route.network}? Machines in its distribution groups lose that path at their next netmap.`)) return;
    void run(() => api.deleteRoute(route.id), `Route ${route.network_id} was deleted.`);
  };
  const toggle = (route: NetworkRoute) => {
    const { id, ...rest } = route;
    void run(() => api.updateRoute(id, { ...rest, enabled: !route.enabled }), `Route ${route.network_id} was ${route.enabled ? "disabled" : "enabled"}.`);
  };

  return <section>
    <h2>Network routes</h2>
    <p className="lede">A route lets machines reach a subnet that is not itself on the overlay — a VPC, a home LAN, a rack. The routing groups carry the traffic; the distribution groups are told the route exists.</p>
    <div className="actions"><button className="primary" onClick={() => setDraft({ value: blank })}>Add route</button></div>
    <Notice message={message} />
    {routes.length === 0
      ? <EmptyState title="No network routes">Add a route to reach a subnet behind one of your machines.</EmptyState>
      : <Rows head={<><th>Identifier</th><th>Network</th><th>Routing groups</th><th>Distributed to</th><th>Metric</th><th>State</th><th>Actions</th></>}>
        {routes.map((route) => <tr key={route.id}>
          <td><strong>{route.network_id}</strong>{route.description && <><br /><span className="lede">{route.description}</span></>}</td>
          <td><code>{route.network}</code></td>
          <td>{route.peer_groups.join(", ") || "—"}</td>
          <td>{route.groups.join(", ") || "—"}</td>
          <td>{route.metric}</td>
          <td><Status state={route.enabled ? "healthy" : "unknown"} label={route.enabled ? "enabled" : "disabled"} /></td>
          <td><div className="actions">
            <button onClick={() => { const { id, ...rest } = route; setDraft({ value: rest, id }); }}>Edit</button>
            <button onClick={() => toggle(route)}>{route.enabled ? "Disable" : "Enable"}</button>
            <button className="danger" onClick={() => remove(route)}>Delete</button>
          </div></td>
        </tr>)}
      </Rows>}

    <Dialog open={Boolean(draft)} title={draft?.id ? "Edit route" : "Add route"} onClose={() => setDraft(undefined)}>
      <form onSubmit={(event) => { event.preventDefault(); void save(); }}>
        <label>Identifier<input aria-label="Route identifier" placeholder="aws-prod" value={draft?.value.network_id ?? ""} onChange={(event) => setDraft((current) => current && { ...current, value: { ...current.value, network_id: event.target.value } })} /></label>
        <label>Network (CIDR)<input aria-label="Route network (CIDR)" placeholder="10.10.0.0/16" value={draft?.value.network ?? ""} onChange={(event) => setDraft((current) => current && { ...current, value: { ...current.value, network: event.target.value } })} /></label>
        <label>Description<input aria-label="Route description" value={draft?.value.description ?? ""} onChange={(event) => setDraft((current) => current && { ...current, value: { ...current.value, description: event.target.value } })} /></label>
        <label>Routing group IDs<input aria-label="Routing group IDs" placeholder="group-gateways" value={(draft?.value.peer_groups ?? []).join(", ")} onChange={(event) => setDraft((current) => current && { ...current, value: { ...current.value, peer_groups: idList(event.target.value) } })} /></label>
        <p className="lede">The machines that will forward into this network. Two machines in the group is a failover pair; the lower metric wins.</p>
        <label>Distribution group IDs<input aria-label="Distribution group IDs" placeholder="group-engineering" value={(draft?.value.groups ?? []).join(", ")} onChange={(event) => setDraft((current) => current && { ...current, value: { ...current.value, groups: idList(event.target.value) } })} /></label>
        <label>Metric<input aria-label="Route metric" type="number" min={1} max={9999} value={draft?.value.metric ?? 9999} onChange={(event) => setDraft((current) => current && { ...current, value: { ...current.value, metric: Number(event.target.value) } })} /></label>
        <label><input type="checkbox" checked={draft?.value.masquerade ?? true} onChange={(event) => setDraft((current) => current && { ...current, value: { ...current.value, masquerade: event.target.checked } })} /> Masquerade — rewrite the source address to the routing machine</label>
        <p className="lede">Leave masquerade on unless the target network has routes back to the overlay. Turning it off without those routes produces traffic that arrives and can never reply.</p>
        <label><input type="checkbox" checked={draft?.value.enabled ?? true} onChange={(event) => setDraft((current) => current && { ...current, value: { ...current.value, enabled: event.target.checked } })} /> Enabled</label>
        <div className="actions"><button type="button" onClick={() => setDraft(undefined)}>Cancel</button><button className="primary" type="submit">{draft?.id ? "Save route" : "Add route"}</button></div>
      </form>
    </Dialog>
  </section>;
}
