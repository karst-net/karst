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

type PolicyRule = { action: string; src: string[]; dst: string[] };
type PolicyDocument = { acls?: PolicyRule[]; ssh?: PolicyRule[] };
type ReferencingRule = PolicyRule & { list: "acls" | "ssh" };

// The access policy (access.tsx) is its own JSON document with its own
// "groups" map — a selector like "group:sre" is resolved against *that*
// document's list of user identifiers, never against this page's group
// records. The two line up only when an admin names them the same way; there
// is no foreign key between them, so this is a best-effort, name-matched
// cross-reference, not an authoritative one.
function selectorFor(group: Group) { return `group:${group.name}`; }

/** Every acls/ssh rule whose src or dst names this group's selector. */
function rulesReferencing(document: PolicyDocument | undefined, selector: string): ReferencingRule[] {
  const acls = (document?.acls ?? []).filter((r) => r.src.includes(selector) || r.dst.includes(selector)).map((r) => ({ ...r, list: "acls" as const }));
  const ssh = (document?.ssh ?? []).filter((r) => r.src.includes(selector) || r.dst.includes(selector)).map((r) => ({ ...r, list: "ssh" as const }));
  return [...acls, ...ssh];
}

export function Groups() {
  const resource = useResource(api.groups);
  // Best-effort: if the policy document fails to load or fails to parse, the
  // "Access rules" column just reads "None" rather than blocking this whole
  // page on a second, unrelated fetch.
  const policy = useResource(api.policy);
  const document: PolicyDocument | undefined = (() => {
    if (!policy.value) return undefined;
    try { return JSON.parse(policy.value.document) as PolicyDocument; } catch { return undefined; }
  })();
  const { message, setMessage, run } = useMutation(resource.reload);
  const [creating, setCreating] = useState<string>();
  const [renaming, setRenaming] = useState<{ group: Group; name: string }>();
  const [viewing, setViewing] = useState<Group>();

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
    const referencing = rulesReferencing(document, selectorFor(group)).length;
    const warning = referencing > 0
      ? `Delete ${group.name}? ${referencing} access-policy rule(s) name "${selectorFor(group)}" and would stop matching until the policy document is edited to match.`
      : group.peers_count > 0
        ? `Delete ${group.name}? ${group.peers_count} machine(s) are in it.`
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
      : <Rows head={<><th>Name</th><th>Members</th><th>Resources</th><th>Source</th><th>Access rules</th><th>Actions</th></>}>
        {groups.map((group) => {
          const referencing = rulesReferencing(document, selectorFor(group));
          return <tr key={group.id}>
            <td><strong>{group.name}</strong><br /><code>{group.id}</code></td>
            <td>{group.peers_count}</td>
            <td>{group.resources_count}</td>
            <td>{group.issued ?? "api"}</td>
            <td>{referencing.length > 0
              ? <button onClick={() => setViewing(group)}>{referencing.length} rule{referencing.length === 1 ? "" : "s"}</button>
              : <span className="lede">None</span>}</td>
            <td>{editable(group)
              ? <div className="actions">
                <button onClick={() => setRenaming({ group, name: group.name })}>Rename</button>
                <button className="danger" onClick={() => remove(group)}>Delete</button>
              </div>
              : <span className="lede">{group.name === "All" ? "Built in" : "Managed by the identity provider"}</span>}</td>
          </tr>;
        })}
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
        <p className="lede">This changes nothing in the access policy document: it names groups independently, by whatever string an admin wrote into its own "groups" section. If this group's old name is referenced there, update the policy to match.</p>
        <div className="actions"><button type="button" onClick={() => setRenaming(undefined)}>Cancel</button><button className="primary" type="submit">Save name</button></div>
      </form>
    </Dialog>

    <Dialog open={Boolean(viewing)} title={viewing ? `Access rules naming ${selectorFor(viewing)}` : ""} onClose={() => setViewing(undefined)}>
      {viewing && <>
        <p className="lede">The access policy (Access controls page) defines its own "groups" map by name. These are the rules in the current policy whose src or dst is exactly <code>{selectorFor(viewing)}</code> — a name match, not a reference to this group's id.</p>
        {rulesReferencing(document, selectorFor(viewing)).length === 0
          ? <p>No rule in the current policy names this selector.</p>
          : <ul>{rulesReferencing(document, selectorFor(viewing)).map((rule, index) => <li key={index}><code>{rule.list}</code>: <code>{rule.src.join(", ")}</code> → <code>{rule.dst.join(", ")}</code></li>)}</ul>}
      </>}
    </Dialog>
  </section>;
}
