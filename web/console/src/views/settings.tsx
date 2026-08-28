// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { useState } from "react";
import { Dialog, EmptyState, Observed } from "@karst-net/ui";
import { api, type Token } from "../api";
import { Failure, Notice, Rows, useMutation, useResource } from "../common";

const expiries = [["30 days", 30], ["90 days", 90], ["365 days", 365]] as const;

export function Settings() {
  const me = useResource(api.currentUser);
  const tokens = useResource(() => me.value ? api.tokens(me.value.id) : Promise.resolve([] as Token[]), [me.value?.id]);
  const { message, setMessage, run } = useMutation(tokens.reload);
  const [draft, setDraft] = useState<{ name: string; expires_in: number }>();
  const [issued, setIssued] = useState<string>();

  if (me.loading) return <p>Loading settings…</p>;
  if (me.error) return <Failure message={me.error} retry={me.reload} />;
  const user = me.value;

  const create = async () => {
    if (!draft || !user) return;
    const name = draft.name.trim();
    if (!name) { setMessage("A token needs a name — it is the only way to tell two of them apart later."); return; }
    try {
      const created = await api.createToken(user.id, name, draft.expires_in);
      setIssued(created.plain_token);
      setDraft(undefined);
      setMessage("Copy this token now. It is not stored and will not be shown again.");
      tokens.reload();
    } catch (error) { setMessage((error as Error).message); }
  };
  const remove = (token: Token) => {
    if (!user) return;
    if (!confirm(`Revoke ${token.name}? Anything using it stops working immediately.`)) return;
    void run(() => api.deleteToken(user.id, token.id), `${token.name} was revoked.`);
  };

  return <section>
    <h2>Settings</h2>
    <h3>Signed in as</h3>
    <Rows head={<><th>Name</th><th>Email</th><th>Role</th><th>User ID</th></>}>
      <tr><td>{user?.name}</td><td>{user?.email}</td><td>{user?.role}</td><td><code>{user?.id}</code></td></tr>
    </Rows>

    <h3>Personal access tokens</h3>
    <p className="lede">A token authenticates the API as you, with your permissions. Prefer one token per automation, so that revoking one does not break the others.</p>
    <div className="actions"><button className="primary" onClick={() => { setIssued(undefined); setDraft({ name: "", expires_in: 30 }); }}>Create token</button></div>
    <Notice message={message} />
    {issued && <label>New personal access token<input aria-label="New personal access token" readOnly value={issued} /></label>}
    {tokens.error ? <Failure message={tokens.error} retry={tokens.reload} />
      : (tokens.value ?? []).length === 0
        ? <EmptyState title="No personal access tokens">Create one to script against the control API.</EmptyState>
        : <Rows head={<><th>Name</th><th>Created</th><th>Expires</th><th>Last used</th><th>Actions</th></>}>
          {(tokens.value ?? []).map((token) => <tr key={token.id}>
            <td><strong>{token.name}</strong></td>
            <td><Observed at={token.created_at} /></td>
            <td><Observed at={token.expiration_date} /></td>
            <td>{token.last_used ? <Observed at={token.last_used} /> : "Never"}</td>
            <td><button className="danger" onClick={() => remove(token)}>Revoke</button></td>
          </tr>)}
        </Rows>}

    <h3>Organisation</h3>
    <p className="lede">Single sign-on, SCIM provisioning and webhooks are configured on the coordination server rather than here — they are server startup configuration, and a console that pretended to own them would be editing a file it cannot read. See <code>management.json</code> and the getting-started guide.</p>

    <Dialog open={Boolean(draft)} title="Create personal access token" onClose={() => setDraft(undefined)}>
      <form onSubmit={(event) => { event.preventDefault(); void create(); }}>
        <label>Token name<input aria-label="Token name" placeholder="ci-deploy" value={draft?.name ?? ""} onChange={(event) => setDraft((current) => current && { ...current, name: event.target.value })} /></label>
        <label>Expires in<select aria-label="Token expires in" value={draft?.expires_in ?? 30} onChange={(event) => setDraft((current) => current && { ...current, expires_in: Number(event.target.value) })}>{expiries.map(([label, value]) => <option key={value} value={value}>{label}</option>)}</select></label>
        <div className="actions"><button type="button" onClick={() => setDraft(undefined)}>Cancel</button><button className="primary" type="submit">Create token</button></div>
      </form>
    </Dialog>
  </section>;
}
