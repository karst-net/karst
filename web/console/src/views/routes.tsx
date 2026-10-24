// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { useState } from "react";
import { Dialog, EmptyState, Status } from "@karst-net/ui";
import { api, type Group, type NetworkRoute, type NetworkRouteDraft } from "../api";
import { Failure, Notice, Rows, useMutation, useResource } from "../common";
import { TutorialHint } from "../tutorial";

const blank: NetworkRouteDraft = {
  network_id: "", description: "", enabled: true, network: "", peer_groups: [], groups: [], access_control_groups: [],
  metric: 9999, masquerade: true, keep_route: false, skip_auto_apply: false,
};
const cidr = /^(?:\d{1,3}(?:\.\d{1,3}){3}\/\d{1,2}|[0-9a-fA-F:]+\/\d{1,3})$/;
const isExit = (network: string) => network === "0.0.0.0/0" || network === "::/0";
const fresh = (network = ""): NetworkRouteDraft => ({ ...blank, network, skip_auto_apply: isExit(network) });

function GroupSelect({ label, value, groups, onChange }: { label: string; value: string[]; groups: Group[]; onChange: (ids: string[]) => void }) {
  return <label>{label}<select aria-label={label} multiple size={Math.min(7, Math.max(3, groups.length))} value={value} onChange={(event) => onChange(Array.from(event.currentTarget.selectedOptions, (option) => option.value))}>
    {groups.map((group) => <option key={group.id} value={group.id}>{group.name} ({group.peers_count} machines)</option>)}
  </select></label>;
}

export function Routes({ defaultTab = "manage" }: { defaultTab?: "manage" | "metrics" }) {
  const [tab, setTab] = useState(defaultTab);
  const resource = useResource(api.routes);
  const groupResource = useResource(api.groups);
  const inventory = useResource(api.gateways);
  const { message, setMessage, run } = useMutation(() => { resource.reload(); inventory.reload(); });
  const [draft, setDraft] = useState<{ value: NetworkRouteDraft; id?: string }>();

  if (resource.loading || groupResource.loading) return <p>Loading network routes…</p>;
  if (resource.error) return <Failure message={resource.error} retry={resource.reload} />;
  if (groupResource.error) return <Failure message={groupResource.error} retry={groupResource.reload} />;
  const routes = resource.value ?? [];
  const groups = groupResource.value ?? [];
  const groupNames = new Map(groups.map((group) => [group.id, group.name]));
  const names = (ids: string[]) => ids.map((id) => groupNames.get(id) ?? id).join(", ") || "—";

  const save = async () => {
    if (!draft) return;
    const value = { ...draft.value, network_id: draft.value.network_id.trim(), network: draft.value.network.trim() };
    if (!value.network_id) { setMessage("A route needs a short identifier — it is what appears on machines that install it."); return; }
    if (!cidr.test(value.network)) { setMessage("The network must be a CIDR prefix, such as 10.10.0.0/16."); return; }
    if (value.peer_groups.length === 0) { setMessage("Select at least one routing group: the machines that forward this traffic."); return; }
    if (value.groups.length === 0) { setMessage("Select at least one distribution group, or no machine is offered the route."); return; }
    if (value.access_control_groups.length === 0) { setMessage("Select at least one access-control group. Distribution alone is not authorization."); return; }
    value.skip_auto_apply = isExit(value.network);
    const done = draft.id
      ? await run(() => api.updateRoute(draft.id!, value), `Route ${value.network_id} was updated.`)
      : await run(() => api.createRoute(value), `Route ${value.network_id} was created.`);
    if (done) setDraft(undefined);
  };
  const remove = (route: NetworkRoute) => {
    if (!confirm(`Delete the route to ${route.network}? Recipients lose that path on the next pushed netmap.`)) return;
    void run(() => api.deleteRoute(route.id), `Route ${route.network_id} was deleted.`);
  };
  const toggle = (route: NetworkRoute) => {
    const { id, ...rest } = route;
    void run(() => api.updateRoute(id, { ...rest, enabled: !route.enabled }), `Route ${route.network_id} was ${route.enabled ? "disabled" : "enabled"}.`);
  };
  const addBehavior = (peer_groups: string[] = []) => setDraft({ value: { ...fresh(), peer_groups } });
  const edit = (route: NetworkRoute) => {
    const { id, ...rest } = route;
    setDraft({ id, value: { ...rest, access_control_groups: rest.access_control_groups ?? [], skip_auto_apply: isExit(rest.network) } });
  };

  return <section>
    <h2>Gateways</h2>
    <nav aria-label="Gateways view" className="actions">
      <button aria-pressed={tab === "manage"} onClick={() => setTab("manage")}>Manage</button>
      <button aria-pressed={tab === "metrics"} onClick={() => setTab("metrics")}>Metrics</button>
    </nav>
    {tab === "metrics" ? <section aria-label="Configured Gateway nodes">
      <h3>Configured Gateway nodes</h3>
      <p className="lede">One enrolled node can serve subnet access and default-route egress together. Control connectivity is shown separately from forwarding readiness. Local exit consent and destination policy still apply.</p>
      <button onClick={inventory.reload}>Refresh Gateway inventory</button>
      {inventory.loading ? <p>Loading Gateway inventory…</p> : inventory.error ? <><Failure message={`Gateway inventory unavailable: ${inventory.error}`} retry={inventory.reload} /><p>Route administration remains available under Manage.</p></> : <>
        {inventory.value?.gateways.length ? <Rows head={<><th>Node</th><th>Configured behaviors</th><th>Recorded control connection</th><th>Forwarding readiness</th></>}>
          {inventory.value.gateways.map((gateway) => <tr key={gateway.node_id}>
            <td><strong>{gateway.name}</strong><br /><code>{gateway.node_id}</code><br /><button onClick={() => addBehavior([...new Set(routes.filter((route) => gateway.offers.some((offer) => offer.id === route.id)).flatMap((route) => route.peer_groups))])}>Add behavior to {gateway.name}</button></td>
            <td>{gateway.offers.map((offer) => <div key={offer.id}><code>{offer.prefix}</code> · {offer.kind === "subnet" ? "Subnet" : offer.kind === "default_ipv4" ? "IPv4 default" : "IPv6 default"} · {offer.enabled ? "enabled" : "disabled"}{offer.requires_client_consent && " · client consent required"} · {offer.forwarding_readiness === "ready" ? "ready" : offer.forwarding_readiness === "degraded" ? "degraded" : "unreported"}</div>)}</td>
            <td>{gateway.control_connected ? "Connected" : "Disconnected"}</td>
            <td><p>{gateway.offers.filter((offer) => offer.enabled && offer.forwarding_readiness === "ready").length} ready · {gateway.offers.filter((offer) => offer.enabled && offer.forwarding_readiness === "degraded").length} degraded · {gateway.offers.filter((offer) => offer.enabled && offer.forwarding_readiness === "unreported").length} unreported enabled behaviors</p>{gateway.forwarding_readiness === "ready" ? "Ready" : gateway.forwarding_readiness === "degraded" ? "Degraded — check the node for an nftables apply failure." : <>Unreported — inspect <code>karst gateway status</code> on the node.</>}</td>
          </tr>)}
        </Rows> : <p>No Gateway nodes resolved from the configured route offers.</p>}
        {Boolean(inventory.value?.unresolved_routes.length) && <p role="status">Routes without a visible eligible node: {inventory.value?.unresolved_routes.join(", ")}. Check routing groups and enrolled machines.</p>}
        {Boolean(inventory.value?.unsupported_routes.length) && <p role="status">Routes outside the CIDR Gateway model: {inventory.value?.unsupported_routes.join(", ")}.</p>}
      </>}
    </section> : <>
      <h3>Gateway behaviors</h3>
      <TutorialHint>A route is a logical declaration, not a device of its own — it names a real subnet (or "the whole internet," for a default route) and which already-enrolled machines ("gateways") will carry traffic to it. Advertise a subnet or default route through enrolled gateway machines. Distribution controls who sees an offer; access control independently governs who may use it.</TutorialHint>
      <div className="actions">
        <button className="primary" onClick={() => addBehavior()}>Add Gateway behavior</button>
        <button onClick={() => setDraft({ value: fresh() })}>Add subnet route</button>
        <button onClick={() => setDraft({ value: fresh("0.0.0.0/0") })}>Add IPv4 exit route</button>
        <button onClick={() => setDraft({ value: fresh("::/0") })}>Add IPv6 exit route</button>
      </div>
      <Notice message={message} />
      {routes.length === 0
        ? <EmptyState title="No network routes">Add a subnet route or offer an exit route that clients may explicitly accept.</EmptyState>
        : <Rows head={<><th>Identifier</th><th>Route</th><th>Gateways</th><th>Recipients</th><th>Access</th><th>State</th><th>Actions</th></>}>
          {routes.map((route) => <tr key={route.id}>
            <td><strong>{route.network_id}</strong>{route.description && <><br /><span className="lede">{route.description}</span></>}</td>
            <td><strong>{isExit(route.network) ? "Exit" : "Subnet"}</strong><br /><code>{route.network}</code><br /><span className="lede">metric {route.metric}</span></td>
            <td>{names(route.peer_groups)}</td>
            <td>{names(route.groups)}</td>
            <td>{names(route.access_control_groups ?? [])}</td>
            <td><Status state={route.enabled ? "healthy" : "unknown"} label={route.enabled ? (isExit(route.network) ? "offered · client consent required" : "offered") : "disabled"} /></td>
            <td><div className="actions">
              <button onClick={() => edit(route)}>Edit</button>
              <button onClick={() => toggle(route)}>{route.enabled ? "Disable" : "Enable"}</button>
              <button className="danger" onClick={() => remove(route)}>Delete</button>
            </div></td>
          </tr>)}
        </Rows>}
    </>}

    <Dialog open={Boolean(draft)} title={draft?.id ? "Edit Gateway behavior" : "Add Gateway behavior"} onClose={() => setDraft(undefined)}>
      <form onSubmit={(event) => { event.preventDefault(); void save(); }}>
        <label>Identifier<input aria-label="Route identifier" placeholder="aws-prod" value={draft?.value.network_id ?? ""} onChange={(event) => setDraft((current) => current && { ...current, value: { ...current.value, network_id: event.target.value } })} /></label>
        <label>Behavior<select aria-label="Gateway behavior" value={isExit(draft?.value.network ?? "") ? draft?.value.network : "subnet"} onChange={(event) => setDraft((current) => current && { ...current, value: { ...current.value, network: event.target.value === "subnet" ? "" : event.target.value, skip_auto_apply: event.target.value !== "subnet" } })}>
          <option value="subnet">Specific-prefix access</option><option value="0.0.0.0/0">IPv4 default-route egress</option><option value="::/0">IPv6 default-route egress</option>
        </select></label>
        <label>Network (CIDR)<input aria-label="Route network (CIDR)" placeholder="10.10.0.0/16" value={draft?.value.network ?? ""} onChange={(event) => setDraft((current) => current && { ...current, value: { ...current.value, network: event.target.value, skip_auto_apply: isExit(event.target.value) } })} /></label>
        {isExit(draft?.value.network ?? "") && <p className="lede">The server only offers this default route. Each client must run <code>karst gateway exit use &lt;route-id&gt;</code> locally before it becomes active. IPv4 and IPv6 consent are independent.</p>}
        <label>Description<input aria-label="Route description" value={draft?.value.description ?? ""} onChange={(event) => setDraft((current) => current && { ...current, value: { ...current.value, description: event.target.value } })} /></label>
        <GroupSelect label="Routing groups" groups={groups} value={draft?.value.peer_groups ?? []} onChange={(peer_groups) => setDraft((current) => current && { ...current, value: { ...current.value, peer_groups } })} />
        <p className="lede">These machines must have Linux forwarding and nftables available. Multiple members form a failover set; the selected route metric determines preference.</p>
        <GroupSelect label="Distribution groups" groups={groups} value={draft?.value.groups ?? []} onChange={(selected) => setDraft((current) => current && { ...current, value: { ...current.value, groups: selected } })} />
        <GroupSelect label="Access-control groups" groups={groups} value={draft?.value.access_control_groups ?? []} onChange={(access_control_groups) => setDraft((current) => current && { ...current, value: { ...current.value, access_control_groups } })} />
        <p className="lede">Recipients must be both distributed the offer and authorized by access control. The two gates are intentionally independent.</p>
        <label>Metric<input aria-label="Route metric" type="number" min={1} max={9999} value={draft?.value.metric ?? 9999} onChange={(event) => setDraft((current) => current && { ...current, value: { ...current.value, metric: Number(event.target.value) } })} /></label>
        <label><input type="checkbox" checked={draft?.value.masquerade ?? true} onChange={(event) => setDraft((current) => current && { ...current, value: { ...current.value, masquerade: event.target.checked } })} /> Masquerade — rewrite the source address to the gateway</label>
        {!draft?.value.masquerade && <p className="lede">The destination network must have an explicit return route to the Karst overlay. Without it, requests arrive but replies do not.</p>}
        <label><input type="checkbox" checked={draft?.value.keep_route ?? false} onChange={(event) => setDraft((current) => current && { ...current, value: { ...current.value, keep_route: event.target.checked } })} /> Keep route while a gateway is unavailable (traffic is blackholed)</label>
        <label><input type="checkbox" checked={draft?.value.enabled ?? true} onChange={(event) => setDraft((current) => current && { ...current, value: { ...current.value, enabled: event.target.checked } })} /> Enabled</label>
        <div className="actions"><button type="button" onClick={() => setDraft(undefined)}>Cancel</button><button className="primary" type="submit">{draft?.id ? "Save route" : "Add route"}</button></div>
      </form>
    </Dialog>
  </section>;
}
