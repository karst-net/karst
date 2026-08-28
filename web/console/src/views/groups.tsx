// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { useState } from "react";
import { Dialog, EmptyState } from "@karst-net/ui";
import { api, type Group } from "../api";
import { Failure, Notice, Rows, useMutation, useResource } from "../common";

// A group synchronised from an identity provider is a copy, not a source. The
// server rejects an edit to one, and the rejection arrives too late to be
// useful — so the console does not offer the button in the first place and says
// why in the row itself.
const editable = (group: Group) => (group.issued ?? "api") === "api" && group.name !== "All";

export function Groups() {
  const resource = useResource(api.groups);
  const { message, setMessage, run } = useMutation(resource.reload);
  const [creating, setCreating] = useState<string>();
  const [renaming, setRenaming] = useState<{ group: Group; name: string }>();

  if (resource.loading) return <p>Loading groups…</p>;
  if (resource.error) return <Failure message={resource.error} retry={resource.reload} />;
  const groups = resource.value ?? [];

  const create = async () => {
    const name = (creating ?? "").trim();
    if (!name) { setMessage("A group needs a name."); return; }
    if (await run(() => api.createGroup(name), `Group ${name} was created.`)) setCreating(undefined);
  };
  const rename = async () => {
    if (!renaming) return;
    const name = renaming.name.trim();
    if (!name) { setMessage("A group needs a name."); return; }
    if (await run(() => api.renameGroup(renaming.group.id, name), `Group ${renaming.group.name} is now named ${name}.`)) setRenaming(undefined);
  };
  const remove = (group: Group) => {
    const warning = group.peers_count > 0
      ? `Delete ${group.name}? ${group.peers_count} machine(s) are in it, and any access rule naming this group stops matching them.`
      : `Delete ${group.name}?`;
    if (!confirm(warning)) return;
    void run(() => api.deleteGroup(group.id), `Group ${group.name} was deleted.`);
  };

  return <section>
    <h2>Groups</h2>
    <p className="lede">Groups are what access rules name. Groups synchronised from an identity provider are managed there and are read-only here.</p>
    <div className="actions"><button className="primary" onClick={() => setCreating("")}>Create group</button></div>
    <Notice message={message} />
    {groups.length === 0
      ? <EmptyState title="No groups">Groups from your identity provider will appear here.</EmptyState>
      : <Rows head={<><th>Name</th><th>Members</th><th>Resources</th><th>Source</th><th>Actions</th></>}>
        {groups.map((group) => <tr key={group.id}>
          <td><strong>{group.name}</strong><br /><code>{group.id}</code></td>
          <td>{group.peers_count}</td>
          <td>{group.resources_count}</td>
          <td>{group.issued ?? "api"}</td>
          <td>{editable(group)
            ? <div className="actions">
              <button onClick={() => setRenaming({ group, name: group.name })}>Rename</button>
              <button className="danger" onClick={() => remove(group)}>Delete</button>
            </div>
            : <span className="lede">{group.name === "All" ? "Built in" : "Managed by the identity provider"}</span>}</td>
        </tr>)}
      </Rows>}

    <Dialog open={creating !== undefined} title="Create group" onClose={() => setCreating(undefined)}>
      <form onSubmit={(event) => { event.preventDefault(); void create(); }}>
        <label>Group name<input aria-label="Group name" placeholder="sre" value={creating ?? ""} onChange={(event) => setCreating(event.target.value)} /></label>
        <p className="lede">Members are added by enrolling a machine with an auth key that auto-assigns this group, or by editing a user’s auto-assigned groups.</p>
        <div className="actions"><button type="button" onClick={() => setCreating(undefined)}>Cancel</button><button className="primary" type="submit">Create group</button></div>
      </form>
    </Dialog>

    <Dialog open={Boolean(renaming)} title="Rename group" onClose={() => setRenaming(undefined)}>
      <form onSubmit={(event) => { event.preventDefault(); void rename(); }}>
        <label>Group name<input aria-label="New group name" value={renaming?.name ?? ""} onChange={(event) => setRenaming((current) => current && { ...current, name: event.target.value })} /></label>
        <p className="lede">Access rules refer to the group by its id, so renaming does not change who can reach what.</p>
        <div className="actions"><button type="button" onClick={() => setRenaming(undefined)}>Cancel</button><button className="primary" type="submit">Save name</button></div>
      </form>
    </Dialog>
  </section>;
}
