// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { useState } from "react";
import { Dialog } from "@karst-net/ui";
import type { Relay } from "@karst-net/api-client";
import { api } from "../api";
import { parseInstallationReceipt, type InstallationReceipt } from "../relay-installation";
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
  const [receipt, setReceipt] = useState<InstallationReceipt>();
  const [busy, setBusy] = useState(false);
  const locations = locationsResource.value ?? [];

  const add = async () => {
    if (busy) return;
    const entry = { address: draft.address.trim(), tls_server_name: draft.tls_server_name.trim(), identity_key: draft.identity_key.trim(), region: draft.region.trim() || "default" };
    if (!address.test(entry.address)) { setMessage("The address must be an IP address and port, such as 203.0.113.7:443. A DNS name here is rejected by every node, for the whole netmap — put the name in the TLS server name instead."); return; }
    if (!entry.identity_key) { setMessage("The identity key is what a node authenticates the relay by. Copy it from `karst-relay pubkey`."); return; }
    const selected = locations.find((l) => l.id === draft.locationId);
    const location = receipt?.entry.location ?? (selected ? { lat: selected.lat, lon: selected.lon, label: selected.label || undefined } : undefined);
    setBusy(true); setMessage(undefined);
    try {
      if (receipt) {
        // Match the public key itself; the file cannot choose an existing identity by ID.
        const existing = (await api.relays()).find(relay => relay.identity_key === entry.identity_key);
        if (existing) {
          if (existing.address !== entry.address || existing.tls_server_name !== entry.tls_server_name || existing.region !== entry.region) throw new Error("This relay identity is already registered with different endpoint settings. Review its existing registration.");
          onAdded(existing); return;
        }
      }
      onAdded(await api.addRelay({ ...entry, location }));
    }
    catch (error) { setMessage((error as Error).message); }
    finally { setBusy(false); }
  };

  return <Dialog open title="Add relay" onClose={() => { if (!busy) onClose(); }}>
      <p>Register a running relay, then configure its group access and optional internet egress. Registration alone does not apply group restrictions. In legacy publication mode it can make the relay available account-wide.</p>
      {message && <p role="alert">{message}</p>}
      {locationsResource.error && <Failure message={locationsResource.error} retry={locationsResource.reload} />}
      <label>Installation receipt<input type="file" accept=".json,application/json" disabled={busy} onChange={async event => {
        const file = event.target.files?.[0]; event.target.value = "";
        if (!file) return;
        setMessage(undefined); setReceipt(undefined); setDraft(blank);
        try {
          if (file.size > 65536) throw new Error("The installation receipt is too large.");
          const imported = parseInstallationReceipt(await file.text());
          setReceipt(imported); setDraft({ ...imported.entry, locationId: "" });
        } catch (error) { setMessage((error as Error).message); }
      }} /></label>
      <p>A host-generated receipt fills in the public identity and endpoint. Review it before registering. Importing it does not create access grants or prove readiness.</p>
      {receipt && <div role="status"><p>Installation receipt loaded for <strong>{receipt.entry.address}</strong>. Region: {receipt.entry.region}. TLS name: {receipt.entry.tls_server_name}. Location: {receipt.entry.location?.label || "Not named"}.</p><p>Confirm this file came from your control host. Runtime startup is separate from access configuration.</p><button onClick={() => { setReceipt(undefined); setDraft(blank); }}>Use manual registration</button></div>}
      <form onSubmit={(event) => { event.preventDefault(); void add(); }}>
        <div hidden={Boolean(receipt)}><label>Address<input aria-label="Relay address" placeholder="203.0.113.7:443" value={draft.address ?? ""} onChange={(event) => setDraft((current) => ({ ...current, address: event.target.value }))} /></label>
        <p className="lede">An IP address and port — not a DNS name. Nodes do not resolve this field.</p>
        <label>TLS server name<input aria-label="TLS server name" placeholder="relay.example.com" value={draft.tls_server_name ?? ""} onChange={(event) => setDraft((current) => ({ ...current, tls_server_name: event.target.value }))} /></label>
        <label>Identity key<input aria-label="Relay identity key" placeholder="base64, from `karst-relay pubkey`" value={draft.identity_key ?? ""} onChange={(event) => setDraft((current) => ({ ...current, identity_key: event.target.value }))} /></label>
        <p className="lede">The ML-DSA-87 public key the relay prints as <code>identity_pk</code>. This — not the certificate — is what proves which relay a node is talking to.</p>
        <label>Region<input aria-label="Relay region" value={draft.region ?? ""} onChange={(event) => setDraft((current) => ({ ...current, region: event.target.value }))} /></label>
        <label>Location<select aria-label="Relay location" value={draft.locationId ?? ""} onChange={(event) => setDraft((current) => ({ ...current, locationId: event.target.value }))}>
          <option value="">No location</option>
          {locations.map((location) => <option key={location.id} value={location.id}>{location.label || `${location.lat}, ${location.lon}`}</option>)}
        </select></label>
        <p className="lede">Optional. Shown on the NOC map — never inferred from the address, so a relay with no declared location shows there as unplaced rather than a guess.</p></div>
        <div className="actions"><button type="button" disabled={busy} onClick={onClose}>Cancel</button><button className="primary" type="submit" disabled={busy}>{receipt ? "Register installed relay" : "Add relay"}</button></div>
      </form>
    </Dialog>;
}
