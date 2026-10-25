// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { useState } from "react";
import { Dialog } from "@karst-net/ui";
import type { Relay } from "@karst-net/api-client";
import { api } from "../api";
import { Failure, useResource } from "../common";

type Draft = { address: string; tls_server_name: string; identity_key: string; region: string; locationId: string };
const blank: Draft = { address: "", tls_server_name: "", identity_key: "", region: "default", locationId: "" };

// `karstd` parses this with Rust's SocketAddr, which does not resolve names. A
// DNS name here is not a relay that fails to dial — it is a netmap every node
// rejects **in full**, so the whole account loses relaying until someone finds
// it. The name belongs in tls_server_name, which is what the certificate must
// match. Catching it in the form is worth more than any error message can be.
const address = /^(?:\d{1,3}(?:\.\d{1,3}){3}|\[[0-9a-fA-F:]+\]):\d{1,5}$/;

export function RelayRegistration({ onClose, onAdded }: { onClose: () => void; onAdded: (relay: Relay) => void }) {
  const locationsResource = useResource(api.locations);
  const [draft, setDraft] = useState<Draft>(blank);
  const [message, setMessage] = useState<string>();
  const [busy, setBusy] = useState(false);
  const locations = locationsResource.value ?? [];

  const add = async () => {
    if (busy) return;
    const entry = { address: draft.address.trim(), tls_server_name: draft.tls_server_name.trim(), identity_key: draft.identity_key.trim(), region: draft.region.trim() || "default" };
    if (!address.test(entry.address)) { setMessage("The address must be an IP address and port, such as 203.0.113.7:443. A DNS name here is rejected by every node, for the whole netmap — put the name in the TLS server name instead."); return; }
    if (!entry.identity_key) { setMessage("The identity key is what a node authenticates the relay by. Copy it from `karst-relay pubkey`."); return; }
    const selected = locations.find((l) => l.id === draft.locationId);
    const location = selected ? { lat: selected.lat, lon: selected.lon, label: selected.label || undefined } : undefined;
    setBusy(true); setMessage(undefined);
    try { onAdded(await api.addRelay({ ...entry, location })); }
    catch (error) { setMessage((error as Error).message); }
    finally { setBusy(false); }
  };

  return <Dialog open title="Add relay" onClose={() => { if (!busy) onClose(); }}>
      <p>Register a running relay, then configure its group access and optional internet egress. Registration alone does not apply group restrictions. In legacy publication mode it can make the relay available account-wide.</p>
      {message && <p role="alert">{message}</p>}
      {locationsResource.error && <Failure message={locationsResource.error} retry={locationsResource.reload} />}
      <form onSubmit={(event) => { event.preventDefault(); void add(); }}>
        <label>Address<input aria-label="Relay address" placeholder="203.0.113.7:443" value={draft.address ?? ""} onChange={(event) => setDraft((current) => ({ ...current, address: event.target.value }))} /></label>
        <p className="lede">An IP address and port — not a DNS name. Nodes do not resolve this field.</p>
        <label>TLS server name<input aria-label="TLS server name" placeholder="relay.example.com" value={draft.tls_server_name ?? ""} onChange={(event) => setDraft((current) => ({ ...current, tls_server_name: event.target.value }))} /></label>
        <label>Identity key<input aria-label="Relay identity key" placeholder="base64, from `karst-relay pubkey`" value={draft.identity_key ?? ""} onChange={(event) => setDraft((current) => ({ ...current, identity_key: event.target.value }))} /></label>
        <p className="lede">The ML-DSA-87 public key the relay prints as <code>identity_pk</code>. This — not the certificate — is what proves which relay a node is talking to.</p>
        <label>Region<input aria-label="Relay region" value={draft.region ?? ""} onChange={(event) => setDraft((current) => ({ ...current, region: event.target.value }))} /></label>
        <label>Location<select aria-label="Relay location" value={draft.locationId ?? ""} onChange={(event) => setDraft((current) => ({ ...current, locationId: event.target.value }))}>
          <option value="">No location</option>
          {locations.map((location) => <option key={location.id} value={location.id}>{location.label || `${location.lat}, ${location.lon}`}</option>)}
        </select></label>
        <p className="lede">Optional. Shown on the NOC map — never inferred from the address, so a relay with no declared location shows there as unplaced rather than a guess.</p>
        <div className="actions"><button type="button" disabled={busy} onClick={onClose}>Cancel</button><button className="primary" type="submit" disabled={busy}>Add relay</button></div>
      </form>
    </Dialog>;
}
