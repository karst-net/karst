// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { useEffect, useState } from "react";
import { Dialog, Observed } from "@karst-net/ui";
import { api, ApiError, type Group } from "../api";
import { Failure, Notice, Rows, useResource } from "../common";
import { type AccessDocument, type AccessGrant, withGrant, withoutGrant } from "../access-model";

export function GroupPicker({ label, groups, value, onChange }: { label: string; groups: Group[]; value: string[]; onChange: (value: string[]) => void }) {
  return <fieldset><legend>{label}</legend>{groups.map(group => <label key={group.id}><input type="checkbox" checked={value.includes(group.id)} onChange={event => onChange(event.target.checked ? [...value, group.id] : value.filter(id => id !== group.id))} />{group.name}</label>)}{value.filter(id => !groups.some(group => group.id === id)).map(id => <label key={id}><input type="checkbox" checked onChange={() => onChange(value.filter(value => value !== id))} />Unavailable group — uncheck to remove</label>)}{groups.length === 0 && <p>Create a group first.</p>}</fieldset>;
}

export function Access() {
  const resource = useResource(async () => {
    try { return await api.policy(); }
    catch (error) { if (error instanceof ApiError && error.status === 404) return { version: 0, document: "{}", author: "", created_at: new Date(0).toISOString() }; throw error; }
  });
  const groups = useResource(api.groups);
  const machines = useResource(async () => { const result = await api.nodes(); while (result.next_cursor) { const next = await api.nodes(result.next_cursor); result.items.push(...next.items); result.next_cursor = next.next_cursor; } return result; });
  const routes = useResource(api.routes);
  const history = useResource(api.policyVersions);
  const [document, setDocument] = useState<AccessDocument>({});
  const [parseError, setParseError] = useState<string>();
  const [draft, setDraft] = useState<AccessGrant>();
  const [kind, setKind] = useState("groups");
  const [portChoice, setPortChoice] = useState("all");
  const [notice, setNotice] = useState<string>();
  const [conflicted, setConflicted] = useState(false);
  const [busy, setBusy] = useState(false);
  const [review, setReview] = useState<{ document: AccessDocument; preview: Awaited<ReturnType<typeof api.preview>> }>();
  const [acknowledged, setAcknowledged] = useState(false);
  const [bindings, setBindings] = useState<Record<string, string>>({});
  useEffect(() => {
    if (!resource.value) return;
    try { const parsed = JSON.parse(resource.value.document) as AccessDocument; setDocument(parsed); setBindings(parsed.groupBindings ?? {}); setParseError(undefined); }
    catch { setParseError("The current access policy could not be read. No changes have been made."); }
  }, [resource.value]);
  const allGroups = groups.value ?? [];
  const names = (ids: string[]) => ids.map(id => allGroups.find(g => g.id === id)?.name ?? "Unavailable group").join(", ");
  const describe = (grant: AccessGrant) => [...(grant.gateway ? [`Forward through ${machines.value?.items.find(n => n.handle === grant.gateway)?.name ?? "Unavailable Gateway"}`] : []),...(grant.target_groups?.length ? [names(grant.target_groups)] : []), ...(grant.target_nodes ?? []).map(id => machines.value?.items.find(n => n.handle === id)?.name ?? "Unavailable machine"), ...(grant.networks ?? []).map(network => network === "0.0.0.0/0" ? "Internet (IPv4)" : network === "::/0" ? "Internet (IPv6)" : network)].join(", ");
  const preview = async (candidate: AccessDocument) => {
    setBusy(true); setNotice(undefined);
    try {
      const validation = await api.validate(JSON.stringify(candidate));
      if (!validation.valid) throw new Error(validation.diagnostics.map(d => d.message).join("; "));
      const result = await api.preview(JSON.stringify(candidate));
      setReview({ document: candidate, preview: result }); setAcknowledged(false);
    } catch (error) { setNotice((error as Error).message); }
    finally { setBusy(false); }
  };
  const save = async () => {
    if (!review) return;
    setBusy(true);
    try {
      await api.savePolicy(JSON.stringify(review.document), resource.value?.version ?? 0);
      setReview(undefined); setDraft(undefined); setConflicted(false); setNotice("Access changes saved."); resource.reload(); history.reload();
    } catch (error) {
      if (error instanceof ApiError && error.status === 412) { setConflicted(true); setReview(undefined); setDraft(undefined); setNotice("Access was not saved because another administrator changed it. Reload before reapplying your edits."); }
      else setNotice(`Access was not saved: ${(error as Error).message}`);
    } finally { setBusy(false); }
  };
  const restore = async (version: number) => {
    setBusy(true);
    try { const old = await api.policyVersion(version); await preview(JSON.parse(old.document) as AccessDocument); }
    catch (error) { setNotice((error as Error).message); }
    finally { setBusy(false); }
  };
  if (resource.loading || groups.loading) return <p>Loading access…</p>;
  if (resource.error) return <Failure message={resource.error} retry={resource.reload} />;
  if (groups.error) return <Failure message={groups.error} retry={groups.reload} />;
  if (parseError) return <p role="alert">{parseError}</p>;
  return <section>
    <h3>Access grants</h3>
    <p>Select which groups can reach machines or networks. Changes use current group membership; renaming a group preserves access. Unmatched traffic is denied.</p>
    <button className="primary" disabled={busy || conflicted} onClick={() => { setKind("groups"); setPortChoice("all"); setDraft({ id: crypto.randomUUID(), name: "", source_groups: [], target_groups: [], ports: "*" }); }}>Add access grant</button>
    <Notice message={notice} />
    {conflicted && <section aria-label="Policy conflict"><h4>Access changed elsewhere</h4><button onClick={() => { resource.reload(); setConflicted(false); setDraft(undefined); }}>Reload current access</button></section>}
    {(document.grants ?? []).length === 0 ? <p>No form-managed access grants yet.</p> : <Rows head={<><th>Name</th><th>Allowed groups</th><th>Destination</th><th>Ports</th><th>SSH</th><th>Actions</th></>}>
      {document.grants?.map(grant => <tr key={grant.id}><td>{grant.name}</td><td>{names(grant.source_groups)}</td><td>{describe(grant)}</td><td>{grant.ports === "*" ? "All" : grant.ports}</td><td>{grant.ssh ? "Additional SSH permission" : "Existing SSH gate applies"}</td><td><button disabled={busy || conflicted || grant.id.startsWith("relay-exit-")} onClick={() => { setKind(grant.networks?.length ? "network" : grant.target_nodes?.length ? "machines" : "groups"); setPortChoice(grant.ports === "*" ? "all" : grant.ports === "22" ? "ssh" : grant.ports === "80,443" ? "web" : "custom"); setDraft(structuredClone(grant)); }}>Edit {grant.name}</button><button disabled={busy || conflicted || grant.id.startsWith("relay-exit-")} onClick={() => void preview(withoutGrant(document, grant.id))}>Remove {grant.name}</button></td></tr>)}
    </Rows>}
    {Boolean(document.acls?.length || document.ssh?.length || Object.keys(document.groups ?? {}).length) && <section aria-label="Existing access">
      <h3>Existing access</h3><p>Existing rules are retained. Mapping a legacy group below changes that group's rules to use live device membership. Review the affected connections before applying.</p>
      <ul>{(document.acls ?? []).map((rule,i) => <li key={`traffic-${i}`}>{rule.src.join(", ")} may reach {rule.dst.join(", ")} <button disabled={busy || conflicted} onClick={() => void preview({ ...document, acls: document.acls?.filter((_,index) => index !== i) })}>Remove existing traffic rule {i+1}</button></li>)}{(document.ssh ?? []).map((rule,i) => <li key={`ssh-${i}`}>{rule.src.join(", ")} has SSH permission to {rule.dst.join(", ")} <button disabled={busy || conflicted} onClick={() => void preview({ ...document, ssh: document.ssh?.filter((_,index) => index !== i) })}>Remove existing SSH permission {i+1}</button></li>)}</ul>
      {Object.keys(document.groups ?? {}).map(name => <label key={name}>Membership for {name.replace(/^group:/, "")}<select value={bindings[name] ?? ""} onChange={event => setBindings(current => { const next = { ...current }; if (event.target.value) next[name] = event.target.value; else delete next[name]; return next; })}><option value="">Keep existing user membership</option>{allGroups.map(g => <option key={g.id} value={g.id}>{g.name} — current device membership</option>)}</select></label>)}
      <button disabled={busy || conflicted} onClick={() => void preview({ ...document, groupBindings: bindings })}>Review membership migration</button>
    </section>}
    <section aria-label="Access history"><h3>Change history</h3>{history.error ? <Failure message={history.error} retry={history.reload} /> : <Rows head={<><th>Version</th><th>Author</th><th>Created</th><th>Actions</th></>}>{history.value?.items.map(version => <tr key={version.version}><td>{version.version}</td><td>{version.author}</td><td><Observed at={version.created_at} /></td><td><button disabled={busy || conflicted} onClick={() => void restore(version.version)}>Review version {version.version}</button></td></tr>)}</Rows>}</section>
    {draft && <Dialog open title="Configure access grant" onClose={() => { if (!busy) setDraft(undefined); }}><form onSubmit={event => { event.preventDefault(); void preview(withGrant(document, draft)); }}>
      <label>Name<input required value={draft.name} onChange={event => setDraft({ ...draft, name: event.target.value })} /></label>
      <GroupPicker label="Allowed groups" groups={allGroups} value={draft.source_groups} onChange={source_groups => setDraft({ ...draft, source_groups })} />
      <label>Destination type<select aria-label="Destination type" value={kind} onChange={event => { setKind(event.target.value); setDraft({ ...draft, target_groups: [], target_nodes: [], networks: [], ssh: false }); }}><option value="groups">Machine groups</option><option value="machines">Specific machines</option><option value="network">Gateway networks and internet egress</option></select></label>
      {kind === "groups" && <GroupPicker label="Destination groups" groups={allGroups} value={draft.target_groups ?? []} onChange={target_groups => setDraft({ ...draft, target_groups })} />}
      {kind === "machines" && <fieldset><legend>Destination machines</legend>{machines.error && <Failure message={machines.error} retry={machines.reload} />}{machines.value?.items.map(node => <label key={node.handle}><input type="checkbox" checked={draft.target_nodes?.includes(node.handle) ?? false} onChange={event => setDraft({ ...draft, target_nodes: event.target.checked ? [...(draft.target_nodes ?? []), node.handle] : draft.target_nodes?.filter(id => id !== node.handle) })} />{node.name}</label>)}</fieldset>}
      {kind === "network" && <fieldset><legend>Destination networks</legend>{routes.error && <Failure message={routes.error} retry={routes.reload} />}{[...new Set(routes.value?.map(route => route.network) ?? [])].map(network => <label key={network}><input type="checkbox" checked={draft.networks?.includes(network) ?? false} onChange={event => setDraft({ ...draft, networks: event.target.checked ? [...(draft.networks ?? []), network] : draft.networks?.filter(n => n !== network) })} />{network === "0.0.0.0/0" ? "Internet (IPv4)" : network === "::/0" ? "Internet (IPv6)" : network}</label>)}<p>Gateway distribution, forwarding readiness, and each client's exit consent also apply.</p></fieldset>}
      <label>Ports<select aria-label="Ports" value={portChoice} onChange={event => { setPortChoice(event.target.value); setDraft({ ...draft, ports: event.target.value === "all" ? "*" : event.target.value === "ssh" ? "22" : event.target.value === "web" ? "80,443" : "443" }); }}><option value="all">All ports</option><option value="ssh">SSH (22)</option><option value="web">Web (80, 443)</option><option value="custom">Specific ports</option></select></label>
      {portChoice === "custom" && <label>Port numbers or ranges<input required value={draft.ports} onChange={event => setDraft({ ...draft, ports: event.target.value })} /></label>}
      {kind !== "network" && <label><input type="checkbox" checked={draft.ssh ?? false} onChange={event => setDraft({ ...draft, ssh: event.target.checked })} />Grant additional SSH permission</label>}
      <p>Adding the first SSH permission activates the additional SSH gate. Review any SSH access that will be removed.</p>
      <div className="actions"><button type="button" disabled={busy} onClick={() => setDraft(undefined)}>Cancel</button><button type="submit" disabled={busy || conflicted || !draft.source_groups.length || !(draft.target_groups?.length || draft.target_nodes?.length || draft.networks?.length)}>Review access changes</button></div>
    </form></Dialog>}
    {review && <Dialog open title="Review access changes" onClose={() => { if (!busy) setReview(undefined); }}>
      {document.ssh === undefined && !document.grants?.some(grant => grant.ssh) && (review.document.ssh !== undefined || review.document.grants?.some(grant => grant.ssh)) && <p role="alert">This activates the additional SSH gate for the account. Previously permitted SSH connections will stop working unless an explicit SSH permission also allows them.</p>}
      <p>{review.preview.added.length} connections added; {review.preview.removed.length} removed.</p>
      <ul>{review.preview.added.map((flow, i) => <li key={`a${i}`}>Allow {flow.source} to {flow.destination}, ports {flow.ports}</li>)}{review.preview.removed.map((flow, i) => <li key={`r${i}`}>Remove {flow.source} to {flow.destination}, ports {flow.ports}</li>)}</ul>
      <p>{review.preview.ssh_added?.length ?? 0} SSH permissions added; {review.preview.ssh_removed?.length ?? 0} removed.</p>
      <label><input type="checkbox" checked={acknowledged} onChange={event => setAcknowledged(event.target.checked)} />I reviewed the access changes.</label>
      <div className="actions"><button disabled={busy} onClick={() => setReview(undefined)}>Back</button><button className="primary" disabled={!acknowledged || busy || conflicted} onClick={() => void save()}>Apply access changes</button></div>
    </Dialog>}
  </section>;
}
