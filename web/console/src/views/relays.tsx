// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { useState } from "react";
import { Dialog, EmptyState, Observed, Status } from "@karst-net/ui";
import type { Relay } from "@karst-net/api-client";
import { api } from "../api";
import { Failure, Notice, Rows, useMutation, useResource } from "../common";

type Draft = { address: string; tls_server_name: string; identity_key: string; region: string };
const blank: Draft = { address: "", tls_server_name: "", identity_key: "", region: "default" };

// `karstd` parses this with Rust's SocketAddr, which does not resolve names. A
// DNS name here is not a relay that fails to dial — it is a netmap every node
// rejects **in full**, so the whole account loses relaying until someone finds
// it. The name belongs in tls_server_name, which is what the certificate must
// match. Catching it in the form is worth more than any error message can be.
const address = /^(?:\d{1,3}(?:\.\d{1,3}){3}|\[[0-9a-fA-F:]+\]):\d{1,5}$/;

export function Relays() {
  const resource = useResource(api.relays);
  const { message, setMessage, run } = useMutation(resource.reload);
  const [draft, setDraft] = useState<Draft>();

  if (resource.loading) return <p>Loading relays…</p>;
  if (resource.error) return <Failure message={resource.error} retry={resource.reload} />;
  const relays = resource.value ?? [];

  const add = async () => {
    if (!draft) return;
    const entry = { address: draft.address.trim(), tls_server_name: draft.tls_server_name.trim(), identity_key: draft.identity_key.trim(), region: draft.region.trim() || "default" };
    if (!address.test(entry.address)) { setMessage("The address must be an IP address and port, such as 203.0.113.7:443. A DNS name here is rejected by every node, for the whole netmap — put the name in the TLS server name instead."); return; }
    if (!entry.identity_key) { setMessage("The identity key is what a node authenticates the relay by. Copy it from `karst-relay pubkey`."); return; }
    if (await run(() => api.addRelay(entry), `Relay ${entry.address} was added. Nodes pick it up with their next netmap.`)) setDraft(undefined);
  };
  const remove = (relay: Relay) => {
    if (!confirm(`Remove the relay at ${relay.address}? Machines that cannot reach each other directly and have no other relay lose connectivity.`)) return;
    void run(() => api.removeRelay(relay.id), `Relay ${relay.address} was removed.`);
  };

  return <section>
    <h2>Relays</h2>
    <p className="lede">Every node is told about exactly the relays listed here. A relay that is not in this registry is one no node will ever dial.</p>
    <div className="actions"><button className="primary" onClick={() => setDraft(blank)}>Add relay</button></div>
    <Notice message={message} />
    {relays.length === 0
      ? <EmptyState title="No relays configured">The coordination server will publish relay health here when a relay is configured.</EmptyState>
      : <Rows head={<><th>Region</th><th>Address</th><th>Health</th><th>Last confirmed</th><th>Actions</th></>}>
        {relays.map((relay) => <tr key={relay.id}>
          <td>{relay.region}</td>
          <td><code>{relay.address}</code><br /><span className="lede">{relay.tls_server_name}</span></td>
          <td><Status state={relay.health.admission_state === "confirmed" ? "healthy" : relay.health.admission_state === "stale" ? "warning" : "unknown"} label={relay.health.admission_state} /></td>
          <td><Observed at={relay.health.last_confirmed_at} /></td>
          <td><button className="danger" onClick={() => remove(relay)}>Remove</button></td>
        </tr>)}
      </Rows>}
    <p className="lede">Admission health comes from the roster the coordination server rewrites every 25 seconds. A relay that goes <strong>stale</strong> has stopped seeing those rewrites and will admit nobody once its 90-second lease expires.</p>

    <Dialog open={Boolean(draft)} title="Add relay" onClose={() => setDraft(undefined)}>
      <form onSubmit={(event) => { event.preventDefault(); void add(); }}>
        <label>Address<input aria-label="Relay address" placeholder="203.0.113.7:443" value={draft?.address ?? ""} onChange={(event) => setDraft((current) => current && { ...current, address: event.target.value })} /></label>
        <p className="lede">An IP address and port — not a DNS name. Nodes do not resolve this field.</p>
        <label>TLS server name<input aria-label="TLS server name" placeholder="relay.example.com" value={draft?.tls_server_name ?? ""} onChange={(event) => setDraft((current) => current && { ...current, tls_server_name: event.target.value })} /></label>
        <label>Identity key<input aria-label="Relay identity key" placeholder="base64, from `karst-relay pubkey`" value={draft?.identity_key ?? ""} onChange={(event) => setDraft((current) => current && { ...current, identity_key: event.target.value })} /></label>
        <p className="lede">The ML-DSA-87 public key the relay prints as <code>identity_pk</code>. This — not the certificate — is what proves which relay a node is talking to.</p>
        <label>Region<input aria-label="Relay region" value={draft?.region ?? ""} onChange={(event) => setDraft((current) => current && { ...current, region: event.target.value })} /></label>
        <div className="actions"><button type="button" onClick={() => setDraft(undefined)}>Cancel</button><button className="primary" type="submit">Add relay</button></div>
      </form>
    </Dialog>
  </section>;
}
