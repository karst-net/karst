// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { useEffect, useState } from "react";
import { Dialog, EmptyState } from "@karst-net/ui";
import { api, type AccountUser, type DomainDelegation, type MeshDomain, type RootRenamePreview } from "../api";
import { Failure, Notice, Rows, useMutation, useResource } from "../common";
import { byTree } from "../domains";

function userLabel(users: AccountUser[], id: string): string {
  const user = users.find((candidate) => candidate.id === id);
  return user ? `${user.name} (${user.email})` : id;
}

export function Domains() {
  const resource = useResource(api.domains);
  const usersResource = useResource(api.users);
  const { message, setMessage, run } = useMutation(resource.reload);
  const [creating, setCreating] = useState<{ parentId: string; label: string }>();
  const [renaming, setRenaming] = useState<{ suffix: string }>();
  const [lastRename, setLastRename] = useState<RootRenamePreview>();
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
    <p className="lede">Domains organize devices into a naming hierarchy: a device placed in one is addressed as <code>device.subdomain.domain</code>. Every device belongs to a domain; new organizations start with the karst root. A domain's admin can create subdomains under it and delegate their administration to another user, without granting that user access to the rest of the account.</p>
    {domains.some((domain) => domain.is_root && (domain.naming_revision ?? 0) > 0) && <p className="lede">The root suffix is committed configuration. Client convergence is unobserved; online clients refresh automatically and offline clients update on reconnect.</p>}
    <div className="actions"><button className="primary" onClick={() => setCreating({ parentId: "", label: "" })}>Create domain</button></div>
    <Notice message={message} />
    {lastRename && <p role="status">Committed naming revision {lastRename.naming_revision}: <code>{lastRename.new_suffix}</code>. Client convergence is unobserved. Online clients switch on refresh; offline clients switch after reconnect. Cached answers may remain for 60 seconds. <button onClick={() => setRenaming({ suffix: lastRename.old_suffix })}>Preview rollback</button></p>}
    {domains.length === 0
      ? <EmptyState title="No visible domains">No domains are available to manage with your current permissions.</EmptyState>
      : <Rows head={<><th>Domain</th><th>Path</th><th>Actions</th></>}>
        {byTree(domains).map(({ domain, depth }) => <tr key={domain.id}>
          <td style={{ paddingLeft: `${depth * 1.5}em` }}>{depth > 0 ? "↳ " : ""}{domain.is_root ? `${domain.dns_suffix} (root)` : domain.label}</td>
          <td><code>{domain.dns_suffix || domain.path}</code></td>
          <td><div className="actions">
            <button onClick={() => setManaging(domain)}>Delegations</button>
            <button onClick={() => setCreating({ parentId: domain.id, label: "" })}>Add subdomain</button>
            {domain.is_root && <button onClick={() => setRenaming({ suffix: "" })}>Rename root</button>}
            {!domain.is_root && <button className="danger" onClick={() => remove(domain)}>Delete</button>}
          </div></td>
        </tr>)}
      </Rows>}

    <Dialog open={Boolean(creating)} title={creating?.parentId ? "Create subdomain" : "Create domain"} onClose={() => setCreating(undefined)}>
      <form onSubmit={(event) => { event.preventDefault(); void create(); }}>
        <label>Parent<select aria-label="Parent domain" value={creating?.parentId ?? ""} onChange={(event) => setCreating((current) => current && { ...current, parentId: event.target.value })}>
          <option value="">Account root (default)</option>
          {domains.map((domain) => <option key={domain.id} value={domain.id}>{domain.dns_suffix || domain.path}</option>)}
        </select></label>
        <label>Label<input aria-label="Domain label" placeholder="engineering" value={creating?.label ?? ""} onChange={(event) => setCreating((current) => current && { ...current, label: event.target.value })} /></label>
        <p className="lede">Letters, digits and hyphens only, like any DNS label. Must be unique among sibling domains under the same parent.</p>
        <div className="actions"><button type="button" onClick={() => setCreating(undefined)}>Cancel</button><button className="primary" type="submit">Create</button></div>
      </form>
    </Dialog>

    {renaming && <RootRenameDialog initialSuffix={renaming.suffix} onClose={() => setRenaming(undefined)} onCommitted={(result) => { setLastRename(result); setRenaming(undefined); resource.reload(); }} />}
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

  return <Dialog open title={`Delegations for ${domain.dns_suffix || domain.path}`} onClose={onClose}>
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

function RootRenameDialog({ initialSuffix, onClose, onCommitted }: { initialSuffix: string; onClose: () => void; onCommitted: (result: RootRenamePreview) => void }) {
  const [suffix, setSuffix] = useState(initialSuffix);
  const [preview, setPreview] = useState<RootRenamePreview>();
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();

  const loadPreview = async () => {
    setBusy(true); setError(undefined); setPreview(undefined); setConfirmed(false);
    try { setPreview(await api.previewRootRename(suffix.trim())); }
    catch (e) { setError(e instanceof Error ? e.message : "Could not preview root rename."); }
    finally { setBusy(false); }
  };
  const commit = async () => {
    if (!preview || !confirmed) return;
    setBusy(true); setError(undefined);
    try { onCommitted(await api.commitRootRename(preview)); }
    catch (e) { setError(e instanceof Error ? e.message : "Could not rename root."); setPreview(undefined); setConfirmed(false); }
    finally { setBusy(false); }
  };
  return <Dialog open title="Rename account root" onClose={() => { if (!busy) onClose(); }}>
    <p>This requires account-wide domain administration. Machine identities, domain memberships and access rules stay unchanged.</p>
    {error && <p role="alert">{error}</p>}
    <form onSubmit={(event) => { event.preventDefault(); void loadPreview(); }}>
      <label>New root suffix<input aria-label="New root suffix" required disabled={busy} value={suffix} onChange={(event) => { setSuffix(event.target.value); setPreview(undefined); setConfirmed(false); }} placeholder="corp.example" /></label>
      <button type="submit" disabled={busy || !suffix.trim()}>Preview rename</button>
    </form>
    {preview && <>
      <p>Change <code>{preview.old_suffix}</code> to <code>{preview.new_suffix}</code>: {preview.device_count} devices across {preview.domain_count} domains. Names passed validation.</p>
      {preview.examples.length > 0 && <Rows head={<><th>Current name</th><th>New name</th></>}>
        {preview.examples.map((example) => <tr key={example.before}><td><code>{example.before}</code></td><td><code>{example.after}</code></td></tr>)}
      </Rows>}
      <p>Old names stop resolving after clients refresh. There are no automatic aliases. Cached answers can remain for 60 seconds; offline clients retain old configuration until reconnect. A rollback requires another preview and confirmation.</p>
      <label><input type="checkbox" checked={confirmed} disabled={busy} onChange={(event) => setConfirmed(event.target.checked)} />I understand old DNS names will stop resolving</label>
      <button className="danger" disabled={busy || !confirmed} onClick={() => void commit()}>Confirm root rename</button>
    </>}
    <button disabled={busy} onClick={onClose}>Cancel</button>
  </Dialog>;
}
