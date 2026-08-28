// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { useState } from "react";
import { Dialog, EmptyState, Observed, Status } from "@karst-net/ui";
import { api, type AccountUser, type UserDraft } from "../api";
import { Failure, Notice, Rows, idList, useMutation, useResource } from "../common";

const roles = ["admin", "user"];
const blank: UserDraft = { name: "", email: "", role: "user", auto_groups: [], is_service_user: false };

export function Users() {
  const resource = useResource(api.users);
  const { message, setMessage, run } = useMutation(resource.reload);
  const [creating, setCreating] = useState<UserDraft>();
  const [editing, setEditing] = useState<{ user: AccountUser; role: string; is_blocked: boolean; groups: string }>();

  if (resource.loading) return <p>Loading users…</p>;
  if (resource.error) return <Failure message={resource.error} retry={resource.reload} />;
  const users = resource.value ?? [];

  const create = async () => {
    if (!creating) return;
    if (!creating.email.trim()) { setMessage("An email address is required — it is where the invitation goes."); return; }
    if (await run(() => api.createUser({ ...creating, name: creating.name.trim() || creating.email.trim(), email: creating.email.trim() }), `${creating.email} was invited as ${creating.role}.`)) setCreating(undefined);
  };
  const save = async () => {
    if (!editing) return;
    if (await run(() => api.updateUser(editing.user.id, { role: editing.role, is_blocked: editing.is_blocked, auto_groups: idList(editing.groups) }), `${editing.user.name} was updated.`)) setEditing(undefined);
  };
  const deprovision = (user: AccountUser) => {
    if (!confirm(`Deprovision ${user.name}? Their node keys will expire and their sessions will be dropped.`)) return;
    void run(() => api.deprovisionUser(user.id), `${user.name} was deprovisioned.`);
  };
  // Blocking is the reversible half of deprovisioning and belongs next to it:
  // an admin dealing with a suspected compromise at 3am wants the sessions gone
  // now and the decision about the account reversible in the morning.
  const setBlocked = (user: AccountUser, blocked: boolean) =>
    void run(() => api.updateUser(user.id, { role: user.role, is_blocked: blocked, auto_groups: user.auto_groups ?? [] }), `${user.name} was ${blocked ? "blocked" : "unblocked"}.`);

  return <section>
    <h2>Users</h2>
    <p className="lede">Deprovisioning removes access and invalidates this user’s node sessions. Blocking is reversible; deprovisioning is not.</p>
    <div className="actions"><button className="primary" onClick={() => setCreating(blank)}>Invite user</button></div>
    <Notice message={message} />
    {users.length === 0
      ? <EmptyState title="No users">Invite a user through the configured identity provider.</EmptyState>
      : <Rows head={<><th>Name</th><th>Email</th><th>Role</th><th>Status</th><th>Last login</th><th>Actions</th></>}>
        {users.map((user) => <tr key={user.id}>
          <td>{user.name}{user.is_current && <> <span className="lede">(you)</span></>}</td>
          <td>{user.email}</td>
          <td>{user.role}</td>
          <td><Status state={user.is_blocked ? "danger" : user.status === "active" ? "healthy" : "warning"} label={user.is_blocked ? "blocked" : user.status} /></td>
          <td>{user.last_login ? <Observed at={user.last_login} /> : "Never"}</td>
          <td><div className="actions">
            <button onClick={() => setEditing({ user, role: user.role, is_blocked: user.is_blocked, groups: (user.auto_groups ?? []).join(", ") })}>Edit</button>
            <button onClick={() => void run(() => api.inviteUser(user.id), `Invitation resent to ${user.email}.`)}>Resend invite</button>
            {!user.is_current && <button onClick={() => setBlocked(user, !user.is_blocked)}>{user.is_blocked ? "Unblock" : "Block"}</button>}
            {user.is_current ? <span className="lede">Current user</span> : <button className="danger" onClick={() => deprovision(user)}>Deprovision</button>}
          </div></td>
        </tr>)}
      </Rows>}

    <Dialog open={Boolean(creating)} title="Invite a user" onClose={() => setCreating(undefined)}>
      <form onSubmit={(event) => { event.preventDefault(); void create(); }}>
        <label>Email<input aria-label="Email" type="email" value={creating?.email ?? ""} onChange={(event) => setCreating((current) => current && { ...current, email: event.target.value })} /></label>
        <label>Full name<input aria-label="Full name" value={creating?.name ?? ""} onChange={(event) => setCreating((current) => current && { ...current, name: event.target.value })} /></label>
        <label>Role<select aria-label="Role" value={creating?.role ?? "user"} onChange={(event) => setCreating((current) => current && { ...current, role: event.target.value })}>{roles.map((role) => <option key={role} value={role}>{role}</option>)}</select></label>
        <label>Auto-assign group IDs<input aria-label="Auto-assign group IDs" placeholder="group-sre, group-engineering" value={(creating?.auto_groups ?? []).join(", ")} onChange={(event) => setCreating((current) => current && { ...current, auto_groups: idList(event.target.value) })} /></label>
        <label><input type="checkbox" checked={creating?.is_service_user ?? false} onChange={(event) => setCreating((current) => current && { ...current, is_service_user: event.target.checked })} /> Service user (no invitation email; for automation)</label>
        <div className="actions"><button type="button" onClick={() => setCreating(undefined)}>Cancel</button><button className="primary" type="submit">Invite user</button></div>
      </form>
    </Dialog>

    <Dialog open={Boolean(editing)} title={`Edit ${editing?.user.name ?? "user"}`} onClose={() => setEditing(undefined)}>
      <form onSubmit={(event) => { event.preventDefault(); void save(); }}>
        <label>Role<select aria-label="Edit role" value={editing?.role ?? "user"} onChange={(event) => setEditing((current) => current && { ...current, role: event.target.value })}>{[...new Set([...roles, editing?.role ?? "user"])].map((role) => <option key={role} value={role}>{role}</option>)}</select></label>
        <label>Auto-assign group IDs<input aria-label="Edit auto-assign group IDs" value={editing?.groups ?? ""} onChange={(event) => setEditing((current) => current && { ...current, groups: event.target.value })} /></label>
        <label><input type="checkbox" checked={editing?.is_blocked ?? false} onChange={(event) => setEditing((current) => current && { ...current, is_blocked: event.target.checked })} /> Blocked</label>
        <div className="actions"><button type="button" onClick={() => setEditing(undefined)}>Cancel</button><button className="primary" type="submit">Save user</button></div>
      </form>
    </Dialog>
  </section>;
}
