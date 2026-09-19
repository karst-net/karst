// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { useEffect, useState } from "react";
import { Dialog, EmptyState } from "@karst-net/ui";
import { api, type AccountUser, type DomainDelegation, type MeshDomain } from "../api";
import { Failure, Notice, Rows, useMutation, useResource } from "../common";

/** Depth-first, root-first order, so a subdomain always renders under its
 *  parent — the only order that makes an indented table read as a tree
 *  rather than a shuffled list. */
function byTree(domains: MeshDomain[]): Array<{ domain: MeshDomain; depth: number }> {
  const children = new Map<string, MeshDomain[]>();
  for (const domain of domains) {
    const key = domain.parent_id ?? "";
    children.set(key, [...(children.get(key) ?? []), domain]);
  }
  for (const list of children.values()) list.sort((a, b) => a.label.localeCompare(b.label));
  const ordered: Array<{ domain: MeshDomain; depth: number }> = [];
  const visit = (parentId: string, depth: number) => { for (const domain of children.get(parentId) ?? []) { ordered.push({ domain, depth }); visit(domain.id, depth + 1); } };
  visit("", 0);
  return ordered;
}

function userLabel(users: AccountUser[], id: string): string {
  const user = users.find((candidate) => candidate.id === id);
  return user ? `${user.name} (${user.email})` : id;
}

export function Domains() {
  const resource = useResource(api.domains);
  const usersResource = useResource(api.users);
  const { message, setMessage, run } = useMutation(resource.reload);
  const [creating, setCreating] = useState<{ parentId: string; label: string }>();
  const [managing, setManaging] = useState<MeshDomain>();

  if (resource.loading) return <p>Loading domains…</p>;
  if (resource.error) return <Failure message={resource.error} retry={resource.reload} />;
  const domains = resource.value ?? [];
  const users = usersResource.value ?? [];

  const create = async () => {
    const label = (creating?.label ?? "").trim();
    if (!label) { setMessage("A domain needs a label."); return; }
    if (await run(() => api.createDomain(creating?.parentId ?? "", label), `Domain ${label} was created.`)) setCreating(undefined);
  };
  const remove = (domain: MeshDomain) => {
    if (!confirm(`Delete ${domain.path}? This fails if it still has subdomains or devices — move or remove those first.`)) return;
    void run(() => api.deleteDomain(domain.id), `Domain ${domain.path} was deleted.`);
  };

  return <section>
    <h2>Domains</h2>
    <p className="lede">Domains organize devices into a naming hierarchy (ADR-0032): a device placed in one is addressed as <code>device.subdomain.domain</code> instead of a bare name. A domain's admin can create subdomains under it and delegate their administration to another user, without granting that user access to the rest of the account.</p>
    <div className="actions"><button className="primary" onClick={() => setCreating({ parentId: "", label: "" })}>Create domain</button></div>
    <Notice message={message} />
    {domains.length === 0
      ? <EmptyState title="No domains">Devices enrolled without a domain use the account's root naming — nothing to configure here until you create one.</EmptyState>
      : <Rows head={<><th>Domain</th><th>Path</th><th>Actions</th></>}>
        {byTree(domains).map(({ domain, depth }) => <tr key={domain.id}>
          <td style={{ paddingLeft: `${depth * 1.5}em` }}>{depth > 0 ? "↳ " : ""}{domain.label}</td>
          <td><code>{domain.path}</code></td>
          <td><div className="actions">
            <button onClick={() => setManaging(domain)}>Delegations</button>
            <button onClick={() => setCreating({ parentId: domain.id, label: "" })}>Add subdomain</button>
            <button className="danger" onClick={() => remove(domain)}>Delete</button>
          </div></td>
        </tr>)}
      </Rows>}

    <Dialog open={Boolean(creating)} title={creating?.parentId ? "Create subdomain" : "Create domain"} onClose={() => setCreating(undefined)}>
      <form onSubmit={(event) => { event.preventDefault(); void create(); }}>
        <label>Parent<select aria-label="Parent domain" value={creating?.parentId ?? ""} onChange={(event) => setCreating((current) => current && { ...current, parentId: event.target.value })}>
          <option value="">Top-level (no parent)</option>
          {domains.map((domain) => <option key={domain.id} value={domain.id}>{domain.path}</option>)}
        </select></label>
        <label>Label<input aria-label="Domain label" placeholder="engineering" value={creating?.label ?? ""} onChange={(event) => setCreating((current) => current && { ...current, label: event.target.value })} /></label>
        <p className="lede">Letters, digits and hyphens only, like any DNS label. Must be unique among sibling domains under the same parent.</p>
        <div className="actions"><button type="button" onClick={() => setCreating(undefined)}>Cancel</button><button className="primary" type="submit">Create</button></div>
      </form>
    </Dialog>

    <DelegationDialog domain={managing} users={users} onClose={() => setManaging(undefined)} onChanged={() => setMessage(undefined)} />
  </section>;
}

/** Its own component because it owns a resource load (delegations for one
 *  domain) that only makes sense once a domain is picked to manage — fetching
 *  it for every domain up front just to populate a dialog nobody may open
 *  would be a lot of unused work on a page with many domains. */
function DelegationDialog({ domain, users, onClose, onChanged }: { domain?: MeshDomain; users: AccountUser[]; onClose: () => void; onChanged: () => void }) {
  const [delegations, setDelegations] = useState<DomainDelegation[]>();
  const [error, setError] = useState<string>();
  const [granteeId, setGranteeId] = useState("");
  const [busy, setBusy] = useState(false);

  const reload = (domainId: string) => { api.domainDelegations(domainId).then(setDelegations).catch((e: Error) => setError(e.message)); };
  useEffect(() => {
    setDelegations(undefined); setError(undefined); setGranteeId("");
    if (domain) reload(domain.id);
  }, [domain]);

  if (!domain) return <Dialog open={false} title="" onClose={onClose}>{null}</Dialog>;

  const delegate = async () => {
    if (!granteeId) { setError("Choose a user to delegate to."); return; }
    setBusy(true); setError(undefined);
    try { await api.delegateDomain(domain.id, granteeId); setGranteeId(""); reload(domain.id); onChanged(); }
    catch (e) { setError(e instanceof Error ? e.message : "Could not delegate this domain."); }
    finally { setBusy(false); }
  };
  const revoke = async (binding: DomainDelegation) => {
    setBusy(true); setError(undefined);
    try { await api.revokeDomainDelegation(binding.id); reload(domain.id); onChanged(); }
    catch (e) { setError(e instanceof Error ? e.message : "Could not revoke this delegation."); }
    finally { setBusy(false); }
  };

  return <Dialog open title={`Delegations for ${domain.path}`} onClose={onClose}>
    <p className="lede">A delegated user can manage this domain and any subdomain under it — create further subdomains, issue device invitations into them, and delegate again — without any account-wide role.</p>
    {error && <p role="alert">{error}</p>}
    {delegations === undefined
      ? <p>Loading…</p>
      : delegations.length === 0
        ? <p className="lede">No one is delegated for this domain.</p>
        : <Rows head={<><th>User</th><th>Actions</th></>}>
          {delegations.map((binding) => <tr key={binding.id}>
            <td>{userLabel(users, binding.user_id)}</td>
            <td><button className="danger" disabled={busy} onClick={() => void revoke(binding)}>Revoke</button></td>
          </tr>)}
        </Rows>}
    <form onSubmit={(event) => { event.preventDefault(); void delegate(); }}>
      <label>Delegate to<select aria-label="Delegate to" value={granteeId} onChange={(event) => setGranteeId(event.target.value)}>
        <option value="">Choose a user…</option>
        {users.map((user) => <option key={user.id} value={user.id}>{user.name} ({user.email})</option>)}
      </select></label>
      <div className="actions"><button type="button" onClick={onClose}>Close</button><button className="primary" type="submit" disabled={busy || !granteeId}>Delegate</button></div>
    </form>
  </Dialog>;
}
