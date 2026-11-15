// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { useEffect, useState } from "react";
import { Dialog, EmptyState, Status } from "@karst-net/ui";
import { api, type NameserverGroup, type NameserverGroupDraft } from "../api";
import { Failure, Notice, Rows, idList, useMutation, useResource } from "../common";
import { GroupPicker } from "./access";
import { TutorialHint } from "../tutorial";

const blank: NameserverGroupDraft = { name: "", description: "", nameservers: [{ ip: "", ns_type: "udp", port: 53 }], enabled: true, groups: [], primary: false, domains: [], search_domains_enabled: false };

export function Dns() {
  const settings = useResource(api.dnsSettings);
  const servers = useResource(api.nameservers);
  const groups = useResource(api.groups);
  const { message, setMessage, run } = useMutation(() => { settings.reload(); servers.reload(); });
  const [excluded, setExcluded] = useState<string[]>([]);
  const [draft, setDraft] = useState<{ value: NameserverGroupDraft; id?: string }>();
  useEffect(() => { if (settings.value) setExcluded(settings.value.disabled_management_groups); }, [settings.value]);

  if (settings.loading || groups.loading) return <p>Loading DNS settings…</p>;
  if (settings.error) return <Failure message={settings.error} retry={settings.reload} />;

  if (groups.error) return <Failure message={groups.error} retry={groups.reload} />;

  const allGroups = groups.value ?? [];
  const names = (ids: string[]) => ids.map(id => allGroups.find(group => group.id === id)?.name ?? "Unavailable group").join(", ");
  const savedExcluded = settings.value?.disabled_management_groups ?? [];
  const overlap = (draft?.value.groups ?? []).filter(id => savedExcluded.includes(id));
  const excludedAssignments = (servers.value ?? []).filter(group => group.groups.some(id => excluded.includes(id)));
  const saveSettings = () => void run(() => api.saveDnsSettings(excluded), "DNS settings saved.");
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
    if (!confirm(`Delete ${group.name}? Devices in its distribution groups fall back to their next matching resolver.`)) return;
    void run(() => api.deleteNameserverGroup(group.id), `Nameserver group ${group.name} was deleted.`);
  };
  const setServer = (index: number, patch: Partial<NameserverGroupDraft["nameservers"][number]>) =>
    setDraft((current) => current && { ...current, value: { ...current.value, nameservers: current.value.nameservers.map((server, position) => position === index ? { ...server, ...patch } : server) } });

  return <section>
    <h2>DNS</h2>
    <TutorialHint>A purely logical/configuration layer: these settings tell each enrolled device's own Karst client which DNS resolver to use for which domains, pushed down the same control channel as everything else. No separate DNS server runs here — "managed" means a resolver this account has declared, not a service Karst operates. Which resolvers your devices use, and which groups Karst leaves alone.</TutorialHint>
    <Notice message={message} />

    <h3>Managed resolvers</h3>
    <GroupPicker label="Groups excluded from DNS management" groups={allGroups} value={excluded} onChange={setExcluded} />
    <p className="lede">Choose groups managed in Identity &amp; Access. Devices in any excluded group keep their existing resolver configuration. Exclusion takes precedence over every nameserver assignment, including assignments through other groups the device belongs to.</p>
    {excludedAssignments.length > 0 && <p role="note">These exclusions overlap distribution groups for: {excludedAssignments.map(group => group.name).join(", ")}. Devices in the excluded groups will not use those managed resolvers.</p>}
    <div className="actions"><button className="primary" onClick={saveSettings}>Save DNS settings</button></div>

    <h3>Nameserver groups</h3>
    <div className="actions"><button onClick={() => setDraft({ value: blank })}>Add nameserver group</button></div>
    {servers.error ? <Failure message={servers.error} retry={servers.reload} />
      : (servers.value ?? []).length === 0
        ? <EmptyState title="No nameserver groups">Add one to point selected devices at a private resolver.</EmptyState>
        : <Rows head={<><th>Name</th><th>Nameservers</th><th>Match domains</th><th>Distributed to</th><th>State</th><th>Actions</th></>}>
          {(servers.value ?? []).map((group) => <tr key={group.id}>
            <td><strong>{group.name}</strong>{group.description && <><br /><span className="lede">{group.description}</span></>}</td>
            <td>{group.nameservers.map((server) => <div key={server.ip}><code>{server.ip}:{server.port}</code></div>)}</td>
            <td>{group.primary ? "All domains (primary)" : group.domains.join(", ") || "—"}</td>
            <td>{names(group.groups) || "—"}{group.groups.some(id => savedExcluded.includes(id)) && <p className="lede">Includes excluded groups; exclusion takes precedence.</p>}</td>
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
        <GroupPicker label="Distribution groups" groups={allGroups} value={draft?.value.groups ?? []} onChange={selected => setDraft(current => current && { ...current, value: { ...current.value, groups: selected } })} />
        <p className="lede">Choose groups from Identity &amp; Access whose devices should use these resolvers. Devices belonging to any group excluded from DNS management keep their existing resolvers, even when selected here.</p>
        {overlap.length > 0 && <p role="note">Excluded from DNS management: {names(overlap)}. This assignment will not apply to devices in these groups. To manage their DNS, remove the exclusion and save DNS settings.</p>}
        <label><input type="checkbox" checked={draft?.value.enabled ?? true} onChange={(event) => setDraft((current) => current && { ...current, value: { ...current.value, enabled: event.target.checked } })} /> Enabled</label>
        <div className="actions"><button type="button" onClick={() => setDraft(undefined)}>Cancel</button><button className="primary" type="submit">{draft?.id ? "Save group" : "Add group"}</button></div>
      </form>
    </Dialog>
  </section>;
}
