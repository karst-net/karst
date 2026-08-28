// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { useEffect, useState } from "react";
import { Dialog, EmptyState, Status } from "@karst-net/ui";
import { api, type NameserverGroup, type NameserverGroupDraft } from "../api";
import { Failure, Notice, Rows, idList, useMutation, useResource } from "../common";

const blank: NameserverGroupDraft = { name: "", description: "", nameservers: [{ ip: "", ns_type: "udp", port: 53 }], enabled: true, groups: [], primary: false, domains: [], search_domains_enabled: false };

export function Dns() {
  const settings = useResource(api.dnsSettings);
  const servers = useResource(api.nameservers);
  const { message, setMessage, run } = useMutation(() => { settings.reload(); servers.reload(); });
  const [excluded, setExcluded] = useState("");
  const [draft, setDraft] = useState<{ value: NameserverGroupDraft; id?: string }>();
  useEffect(() => { if (settings.value) setExcluded(settings.value.disabled_management_groups.join(", ")); }, [settings.value]);

  if (settings.loading) return <p>Loading DNS settings…</p>;
  if (settings.error) return <Failure message={settings.error} retry={settings.reload} />;

  const saveSettings = () => void run(() => api.saveDnsSettings(idList(excluded)), "DNS settings saved.");
  const save = async () => {
    if (!draft) return;
    const value = { ...draft.value, name: draft.value.name.trim(), nameservers: draft.value.nameservers.filter((server) => server.ip.trim()).map((server) => ({ ...server, ip: server.ip.trim() })) };
    if (!value.name) { setMessage("A nameserver group needs a name."); return; }
    if (value.nameservers.length === 0) { setMessage("A nameserver group needs at least one nameserver."); return; }
    // The server enforces this pair and rejects the request, but the rejection
    // reads as a schema error. Said plainly here instead: a primary group
    // answers everything, so it cannot also be scoped to match domains.
    if (value.primary && value.domains.length > 0) { setMessage("A primary group resolves every domain, so it cannot also list match domains. Clear one or the other."); return; }
    if (!value.primary && value.domains.length === 0) { setMessage("A non-primary group needs at least one match domain, or it never applies to anything."); return; }
    const done = draft.id
      ? await run(() => api.updateNameserverGroup(draft.id!, value), `Nameserver group ${value.name} was updated.`)
      : await run(() => api.createNameserverGroup(value), `Nameserver group ${value.name} was created.`);
    if (done) setDraft(undefined);
  };
  const remove = (group: NameserverGroup) => {
    if (!confirm(`Delete ${group.name}? Machines in its distribution groups fall back to their next matching resolver.`)) return;
    void run(() => api.deleteNameserverGroup(group.id), `Nameserver group ${group.name} was deleted.`);
  };
  const setServer = (index: number, patch: Partial<NameserverGroupDraft["nameservers"][number]>) =>
    setDraft((current) => current && { ...current, value: { ...current.value, nameservers: current.value.nameservers.map((server, position) => position === index ? { ...server, ...patch } : server) } });

  return <section>
    <h2>DNS</h2>
    <p className="lede">Which resolvers your machines use, and which groups Karst leaves alone.</p>
    <Notice message={message} />

    <h3>Managed resolvers</h3>
    <label htmlFor="dns-groups">Groups excluded from DNS management</label>
    <input id="dns-groups" value={excluded} onChange={(event) => setExcluded(event.target.value)} />
    <p className="lede">Machines in these groups keep the resolver configuration they already have. Separate group IDs with commas.</p>
    <div className="actions"><button className="primary" onClick={saveSettings}>Save DNS settings</button></div>

    <h3>Nameserver groups</h3>
    <div className="actions"><button onClick={() => setDraft({ value: blank })}>Add nameserver group</button></div>
    {servers.error ? <Failure message={servers.error} retry={servers.reload} />
      : (servers.value ?? []).length === 0
        ? <EmptyState title="No nameserver groups">Add one to point selected machines at a private resolver.</EmptyState>
        : <Rows head={<><th>Name</th><th>Nameservers</th><th>Match domains</th><th>Distributed to</th><th>State</th><th>Actions</th></>}>
          {(servers.value ?? []).map((group) => <tr key={group.id}>
            <td><strong>{group.name}</strong>{group.description && <><br /><span className="lede">{group.description}</span></>}</td>
            <td>{group.nameservers.map((server) => <div key={server.ip}><code>{server.ip}:{server.port}</code></div>)}</td>
            <td>{group.primary ? "All domains (primary)" : group.domains.join(", ") || "—"}</td>
            <td>{group.groups.join(", ") || "—"}</td>
            <td><Status state={group.enabled ? "healthy" : "unknown"} label={group.enabled ? "enabled" : "disabled"} /></td>
            <td><div className="actions">
              <button onClick={() => { const { id, ...rest } = group; setDraft({ value: rest, id }); }}>Edit</button>
              <button className="danger" onClick={() => remove(group)}>Delete</button>
            </div></td>
          </tr>)}
        </Rows>}

    <Dialog open={Boolean(draft)} title={draft?.id ? "Edit nameserver group" : "Add nameserver group"} onClose={() => setDraft(undefined)}>
      <form onSubmit={(event) => { event.preventDefault(); void save(); }}>
        <label>Name<input aria-label="Nameserver group name" placeholder="corp-internal" value={draft?.value.name ?? ""} onChange={(event) => setDraft((current) => current && { ...current, value: { ...current.value, name: event.target.value } })} /></label>
        <label>Description<input aria-label="Nameserver group description" value={draft?.value.description ?? ""} onChange={(event) => setDraft((current) => current && { ...current, value: { ...current.value, description: event.target.value } })} /></label>
        {(draft?.value.nameservers ?? []).map((server, index) => <div key={index} className="two-col">
          <label>Nameserver {index + 1} IP<input aria-label={`Nameserver ${index + 1} IP`} placeholder="10.0.0.53" value={server.ip} onChange={(event) => setServer(index, { ip: event.target.value })} /></label>
          <label>Nameserver {index + 1} port<input aria-label={`Nameserver ${index + 1} port`} type="number" min={1} max={65535} value={server.port} onChange={(event) => setServer(index, { port: Number(event.target.value) })} /></label>
        </div>)}
        <div className="actions"><button type="button" onClick={() => setDraft((current) => current && { ...current, value: { ...current.value, nameservers: [...current.value.nameservers, { ip: "", ns_type: "udp", port: 53 }] } })}>Add another nameserver</button></div>
        <label><input type="checkbox" checked={draft?.value.primary ?? false} onChange={(event) => setDraft((current) => current && { ...current, value: { ...current.value, primary: event.target.checked, domains: event.target.checked ? [] : current.value.domains } })} /> Primary — resolve every domain through these servers</label>
        {!draft?.value.primary && <label>Match domains<input aria-label="Match domains" placeholder="corp.example.com, internal.test" value={(draft?.value.domains ?? []).join(", ")} onChange={(event) => setDraft((current) => current && { ...current, value: { ...current.value, domains: idList(event.target.value) } })} /></label>}
        <label>Distribution group IDs<input aria-label="Nameserver distribution group IDs" placeholder="group-engineering" value={(draft?.value.groups ?? []).join(", ")} onChange={(event) => setDraft((current) => current && { ...current, value: { ...current.value, groups: idList(event.target.value) } })} /></label>
        <label><input type="checkbox" checked={draft?.value.enabled ?? true} onChange={(event) => setDraft((current) => current && { ...current, value: { ...current.value, enabled: event.target.checked } })} /> Enabled</label>
        <div className="actions"><button type="button" onClick={() => setDraft(undefined)}>Cancel</button><button className="primary" type="submit">{draft?.id ? "Save group" : "Add group"}</button></div>
      </form>
    </Dialog>
  </section>;
}
