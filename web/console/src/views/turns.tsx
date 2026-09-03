// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { useState } from "react";
import { Dialog, EmptyState } from "@karst-net/ui";
import type { TurnServer } from "@karst-net/api-client";
import { api } from "../api";
import { Failure, Notice, Rows, useMutation, useResource } from "../common";

type Draft = { uri: string; region: string };
const blank: Draft = { uri: "", region: "default" };

// turncred.go's own validate() requires a turn: or turns: scheme (RFC 8656
// §3.1 / RFC 7065) and nothing else — this mirrors that check client-side so
// a malformed URI is rejected before a request is made, rather than after.
const uri = /^turns?:/;

export function Turns() {
  const resource = useResource(api.turns);
  const { message, setMessage, run } = useMutation(resource.reload);
  const [draft, setDraft] = useState<Draft>();

  if (resource.loading) return <p>Loading TURN servers…</p>;
  if (resource.error) return <Failure message={resource.error} retry={resource.reload} />;
  const turns = resource.value ?? [];

  const add = async () => {
    if (!draft) return;
    const entry = { uri: draft.uri.trim(), region: draft.region.trim() || "default" };
    if (!uri.test(entry.uri)) { setMessage("The URI must start with turn: or turns:, such as turn:turn.example.com:3478."); return; }
    if (await run(() => api.addTurn(entry), `TURN server ${entry.uri} was added. Nodes pick it up with their next netmap.`)) setDraft(undefined);
  };
  const remove = (turn: TurnServer) => {
    if (!confirm(`Remove the TURN server at ${turn.uri}? Nodes that need TURN as a last-resort fallback lose it once their next netmap arrives.`)) return;
    void run(() => api.removeTurn(turn.id), `TURN server ${turn.uri} was removed.`);
  };

  return <section>
    <h2>TURN servers</h2>
    <p className="lede">ADR-0008 §4's last-resort fallback: every node is told about exactly the TURN servers listed here, for use only when a direct path and every relay have failed.</p>
    <div className="actions"><button className="primary" onClick={() => setDraft(blank)}>Add TURN server</button></div>
    <Notice message={message} />
    {turns.length === 0
      ? <EmptyState title="No TURN servers configured">A deployment with no TURN registry is unaffected: nodes simply have no last-resort fallback beyond direct paths and relays.</EmptyState>
      : <Rows head={<><th>Region</th><th>URI</th><th>Actions</th></>}>
        {turns.map((turn) => <tr key={turn.id}>
          <td>{turn.region}</td>
          <td><code>{turn.uri}</code></td>
          <td><button className="danger" onClick={() => remove(turn)}>Remove</button></td>
        </tr>)}
      </Rows>}

    <Dialog open={Boolean(draft)} title="Add TURN server" onClose={() => setDraft(undefined)}>
      <form onSubmit={(event) => { event.preventDefault(); void add(); }}>
        <label>URI<input aria-label="TURN server URI" placeholder="turn:turn.example.com:3478" value={draft?.uri ?? ""} onChange={(event) => setDraft((current) => current && { ...current, uri: event.target.value })} /></label>
        <p className="lede">A turn: or turns: URI (RFC 8656 §3.1 / RFC 7065). The credential a node uses to authenticate to it is minted per response and never configured here.</p>
        <label>Region<input aria-label="TURN server region" value={draft?.region ?? ""} onChange={(event) => setDraft((current) => current && { ...current, region: event.target.value })} /></label>
        <div className="actions"><button type="button" onClick={() => setDraft(undefined)}>Cancel</button><button className="primary" type="submit">Add TURN server</button></div>
      </form>
    </Dialog>
  </section>;
}
