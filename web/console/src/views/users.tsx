// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { useMemo, useState } from "react";
import { Dialog, EmptyState, Observed, Status } from "@karst-net/ui";
import { api, type AccountUser } from "../api";
import { Failure, Notice, Rows, idList, useMutation, useResource } from "../common";

const roles = ["admin", "user"];

export function Users() {
  const [filter, setFilter] = useState("");
  const [details, setDetails] = useState<AccountUser>();
  const resource = useResource(api.users);
  const { message, run } = useMutation(resource.reload);
  const [editing, setEditing] = useState<{ user: AccountUser; role: string; is_blocked: boolean; groups: string }>();

  const users = useMemo(() => (resource.value ?? []).filter(user => [user.name, user.email, user.role].join(" ").toLowerCase().includes(filter.toLowerCase())), [resource.value, filter]);

  if (resource.loading) return <p>Loading users…</p>;
  if (resource.error) return <Failure message={resource.error} retry={resource.reload} />;

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
    <p className="lede">Users are created in your identity provider, not here — this list fills in once someone signs in. Deprovisioning removes access and invalidates this user’s node sessions. Blocking is reversible; deprovisioning is not.</p>
    <Notice message={message} />
    <label>Search users<input type="search" value={filter} onChange={event => setFilter(event.target.value)} placeholder="Name, email, or role" /></label>
    {users.length === 0
      ? <EmptyState title={filter ? "No matching users" : "No users"}>{filter ? "Try a different search." : "Create the user in your identity provider; they’ll appear here after they first sign in."}</EmptyState>
      : <Rows head={<><th>Name</th><th>Email</th><th>Role</th><th>Status</th><th>Last login</th><th>Actions</th></>}>
        {users.map((user) => <tr key={user.id}>
          <td>{user.name}{user.is_current && <> <span className="lede">(you)</span></>}</td>
          <td>{user.email}</td>
          <td>{user.role}</td>
          <td><Status state={user.is_blocked ? "danger" : user.status === "active" ? "healthy" : "warning"} label={user.is_blocked ? "blocked" : user.status} /></td>
          <td>{user.last_login ? <Observed at={user.last_login} /> : "Never"}</td>
          <td><div className="actions">
            <button onClick={() => setDetails(user)}>Details</button>
            <button onClick={() => setEditing({ user, role: user.role, is_blocked: user.is_blocked, groups: (user.auto_groups ?? []).join(", ") })}>Edit</button>
            {!user.is_current && <button onClick={() => setBlocked(user, !user.is_blocked)}>{user.is_blocked ? "Unblock" : "Block"}</button>}
            {user.is_current ? <span className="lede">Current user</span> : <button className="danger" onClick={() => deprovision(user)}>Deprovision</button>}
          </div></td>
        </tr>)}
      </Rows>}

    {details && <UserDetails user={details} onClose={() => setDetails(undefined)} />}
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

function UserDetails({ user, onClose }: { user: AccountUser; onClose: () => void }) {
  const nodes = useResource(async () => {
    const first = await api.nodes();
    let cursor = first.next_cursor;
    while (cursor) {
      const page = await api.nodes(cursor);
      first.items.push(...page.items);
      cursor = page.next_cursor;
    }
    return first;
  });
  const invitations = useResource(api.invitations);
  const machines = nodes.value?.items.filter(node => node.user_id === user.id) ?? [];
  const pending = invitations.value?.filter(invitation => invitation.assigned_user_id === user.id && invitation.state === "pending") ?? [];
  return <Dialog open title={`${user.name} — details`} onClose={onClose}>
    <p>{user.email}</p>
    <h3>Machines</h3>
    {nodes.loading ? <p>Loading machines…</p> : nodes.error ? <Failure message={nodes.error} retry={nodes.reload} /> : machines.length ? <ul>{machines.map(node => <li key={node.handle}>{node.name} — {node.platform}</li>)}</ul> : <p>No machines assigned.</p>}
    <h3>Outstanding invitations</h3>
    {invitations.loading ? <p>Loading invitations…</p> : invitations.error ? <Failure message={invitations.error} retry={invitations.reload} /> : pending.length ? <ul>{pending.map(invitation => <li key={invitation.id}>{invitation.name} — expires {new Date(invitation.expires_at).toLocaleString()}{invitation.reusable && <> — {invitation.used_times ?? 0} / {invitation.usage_limit || "∞"} uses</>}</li>)}</ul> : <p>No outstanding invitations.</p>}
    <button onClick={onClose}>Close</button>
  </Dialog>;
}
