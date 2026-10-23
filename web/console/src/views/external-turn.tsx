// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { useState } from "react";
import { Dialog, EmptyState, Observed } from "@karst-net/ui";
import type { ExternalTurnServer } from "@karst-net/api-client";
import { api } from "../api";
import { Failure, Notice, Rows, useMutation, useResource } from "../common";
import { TutorialHint } from "../tutorial";

type ServerDraft = { uri: string; username: string; credential: string };
const blankDraft: ServerDraft = { uri: "turns:", username: "", credential: "" };

export function ExternalTurnServers() {
  const servers = useResource(api.externalTurnServers);
  const { message, setMessage, run } = useMutation(servers.reload);
  const [addDraft, setAddDraft] = useState<ServerDraft>();
  const [editing, setEditing] = useState<{ server: ExternalTurnServer; draft: ServerDraft }>();

  const addServer = async () => {
    if (!addDraft) return;
    if (!addDraft.uri.startsWith("turns:")) { setMessage("The URI must use the turns: scheme."); return; }
    if (!addDraft.username.trim()) { setMessage("A username is required."); return; }
    if (!addDraft.credential) { setMessage("A credential is required."); return; }
    if (await run(() => api.createExternalTurnServer({ uri: addDraft.uri.trim(), username: addDraft.username.trim(), credential: addDraft.credential }), "External TURN server added.")) {
      setAddDraft(undefined);
    }
  };
  const saveEdit = async () => {
    if (!editing) return;
    const { server, draft } = editing;
    if (!draft.uri.startsWith("turns:")) { setMessage("The URI must use the turns: scheme."); return; }
    if (!draft.username.trim()) { setMessage("A username is required."); return; }
    const entry = { uri: draft.uri.trim(), username: draft.username.trim(), credential: draft.credential || undefined };
    if (await run(() => api.updateExternalTurnServer(server.id, entry), `${draft.uri} was updated.`)) {
      setEditing(undefined);
    }
  };
  const removeServer = (server: ExternalTurnServer) => {
    if (!confirm(`Remove ${server.uri}? Every node stops trying this server as a last-resort fallback on its next poll.`)) return;
    void run(() => api.deleteExternalTurnServer(server.id), `${server.uri} was removed.`);
  };
  // Swaps the two neighboring ids and sends the account's full order --
  // the API's own consistency check (exactly the current entries, each
  // once) rejects anything else, so a partial reorder is not an option.
  const move = (server: ExternalTurnServer, direction: -1 | 1) => {
    const ordered = servers.value ?? [];
    const index = ordered.findIndex((s) => s.id === server.id);
    const swapWith = index + direction;
    if (index < 0 || swapWith < 0 || swapWith >= ordered.length) return;
    const ids = ordered.map((s) => s.id);
    [ids[index], ids[swapWith]] = [ids[swapWith], ids[index]];
    void run(() => api.reorderExternalTurnServers(ids), "Order updated.");
  };

  return <section>
    <h2>External TURN servers</h2>
    <TutorialHint>A last-resort fallback datapath when direct and Ponor-relayed connections both fail -- operated by you, not Karst. Karst stores exactly what you enter here and forwards it unchanged to every node; it never mints a credential, probes these servers' health, or keeps a registry of their state. Entries are tried in the order below. The credential is write-only: once saved, it is never shown again, including to you.</TutorialHint>
    <div className="actions"><button className="primary" onClick={() => setAddDraft(blankDraft)}>Add external TURN server</button></div>
    <Notice message={message} />
    {servers.loading ? <p>Loading external TURN servers…</p> : servers.error
      ? <Failure message={servers.error} retry={servers.reload} />
      : (servers.value ?? []).length === 0
        ? <EmptyState title="No external TURN servers configured">Nodes fall back to direct and Ponor-relayed connections only.</EmptyState>
        : <Rows head={<><th>Order</th><th>URI</th><th>Username</th><th>Updated</th><th>Actions</th></>}>
          {(servers.value ?? []).map((server, index) => <tr key={server.id}>
            <td>{index + 1}</td>
            <td><code>{server.uri}</code></td>
            <td>{server.username}</td>
            <td><Observed at={server.updated_at} /></td>
            <td>
              <button aria-label={`Move ${server.uri} up`} disabled={index === 0} onClick={() => move(server, -1)}>↑</button>
              <button aria-label={`Move ${server.uri} down`} disabled={index === (servers.value?.length ?? 0) - 1} onClick={() => move(server, 1)}>↓</button>
              <button onClick={() => setEditing({ server, draft: { uri: server.uri, username: server.username, credential: "" } })}>Edit</button>
              <button className="danger" onClick={() => removeServer(server)}>Remove</button>
            </td>
          </tr>)}
        </Rows>}

    <Dialog open={Boolean(addDraft)} title="Add external TURN server" onClose={() => setAddDraft(undefined)}>
      <form onSubmit={(event) => { event.preventDefault(); void addServer(); }}>
        <label>URI<input aria-label="Server URI" placeholder="turns:turn.example.com:5349" value={addDraft?.uri ?? ""} onChange={(event) => setAddDraft((current) => current && { ...current, uri: event.target.value })} /></label>
        <p className="lede">Must use the turns: scheme — a plain turn: entry is rejected. This long-lived credential is shared with every node, so TLS is required.</p>
        <label>Username<input aria-label="Server username" value={addDraft?.username ?? ""} onChange={(event) => setAddDraft((current) => current && { ...current, username: event.target.value })} /></label>
        <label>Credential<input aria-label="Server credential" type="password" value={addDraft?.credential ?? ""} onChange={(event) => setAddDraft((current) => current && { ...current, credential: event.target.value })} /></label>
        <p className="lede">The long-term credential you already provisioned on this server — Karst mints nothing.</p>
        <div className="actions">
          <button type="button" onClick={() => setAddDraft(undefined)}>Cancel</button>
          <button className="primary" type="submit" disabled={!addDraft?.uri || !addDraft?.username || !addDraft?.credential}>Add server</button>
        </div>
      </form>
    </Dialog>

    <Dialog open={Boolean(editing)} title="Edit external TURN server" onClose={() => setEditing(undefined)}>
      <form onSubmit={(event) => { event.preventDefault(); void saveEdit(); }}>
        <label>URI<input aria-label="Edit server URI" value={editing?.draft.uri ?? ""} onChange={(event) => setEditing((current) => current && { ...current, draft: { ...current.draft, uri: event.target.value } })} /></label>
        <label>Username<input aria-label="Edit server username" value={editing?.draft.username ?? ""} onChange={(event) => setEditing((current) => current && { ...current, draft: { ...current.draft, username: event.target.value } })} /></label>
        <label>Credential<input aria-label="Edit server credential" type="password" placeholder="Leave blank to keep the current credential" value={editing?.draft.credential ?? ""} onChange={(event) => setEditing((current) => current && { ...current, draft: { ...current.draft, credential: event.target.value } })} /></label>
        <p className="lede">The stored credential is never shown — leave this blank to keep it unchanged, or enter a new one to replace it.</p>
        <div className="actions">
          <button type="button" onClick={() => setEditing(undefined)}>Cancel</button>
          <button className="primary" type="submit" disabled={!editing?.draft.uri || !editing?.draft.username}>Save</button>
        </div>
      </form>
    </Dialog>
  </section>;
}
