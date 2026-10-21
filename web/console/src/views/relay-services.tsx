// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { useState } from "react";
import { Dialog, EmptyState, Status } from "@karst-net/ui";
import type { RelayService } from "@karst-net/api-client";
import { api } from "../api";
import { Failure, Notice, Rows, useMutation, useResource } from "../common";
import { Relays } from "./relays";
import { Turns } from "./turns";

export function RelayServices() {
  const [view, setView] = useState<"services" | "ponor" | "turn">("services");
  return <section>
    <h2>Relays</h2>
    <nav aria-label="Relay configuration" className="actions">
      <button aria-pressed={view === "services"} onClick={() => setView("services")}>Services</button>
      <button aria-pressed={view === "ponor"} onClick={() => setView("ponor")}>Ponor endpoints</button>
      <button aria-pressed={view === "turn"} onClick={() => setView("turn")}>TURN backends</button>
    </nav>
    {view === "services" && <Services />}
    {view === "ponor" && <Relays />}
    {view === "turn" && <Turns />}
  </section>;
}

async function loadServices() {
  const [services, ponor, turn] = await Promise.all([api.relayServices(), api.relays(), api.turns()]);
  return { services, ponor, turn };
}

function Services() {
  const resource = useResource(loadServices);
  const { message, setMessage, run } = useMutation(resource.reload);
  const [draft, setDraft] = useState<RelayService>();
  const [saving, setSaving] = useState(false);
  if (resource.loading) return <p>Loading Relay services…</p>;
  if (resource.error) return <Failure message={resource.error} retry={resource.reload} />;
  const { services, ponor, turn } = resource.value ?? { services: [], ponor: [], turn: [] };

  const add = async () => {
    if (!draft || saving) return;
    const service: RelayService = { id: draft.id.trim(), ponor_id: draft.ponor_id };
    if (!/^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$/.test(service.id)) {
      setMessage("Use 1–64 letters, digits, underscores or hyphens for the service name, starting with a letter or digit."); return;
    }
    if (!ponor.some((entry) => entry.id === service.ponor_id)) { setMessage("Choose a registered Ponor endpoint."); return; }
    if (draft.turn_id) {
      if (!turn.some((entry) => entry.id === draft.turn_id)) { setMessage("Choose a registered TURN backend."); return; }
      if (!draft.backend_kind || !draft.backend_operator?.trim()) { setMessage("Choose the TURN deployment type and identify its operator."); return; }
      service.turn_id = draft.turn_id;
      service.backend_kind = draft.backend_kind;
      service.backend_operator = draft.backend_operator.trim();
    }
    setSaving(true);
    if (await run(() => api.addRelayService(service), `Relay service ${service.id} was added.`)) setDraft(undefined);
    setSaving(false);
  };
  const remove = (service: RelayService) => {
    if (!confirm(`Remove the ${service.id} service association? Its endpoints remain registered and running.`)) return;
    void run(() => api.removeRelayService(service.id), `Relay service ${service.id} association was removed.`);
  };

  return <section>
    <h3>Services</h3>
    <p>Group a Ponor endpoint and optional TURN backend under one service name. Choose each backend explicitly, including who operates TURN.</p>
    <p className="lede">Associations organize existing endpoints. Endpoint publishing and credentials still use the backend controls. Removing an association leaves those endpoints running.</p>
    <div className="actions"><button className="primary" onClick={() => { setMessage(undefined); setDraft({ id: "", ponor_id: "" }); }}>Add service</button><button onClick={resource.reload}>Refresh services</button></div>
    {!draft && <Notice message={message} />}
    {services.length === 0 ? <EmptyState title="No Relay services configured">Existing endpoints continue operating. Register backends in the Ponor and TURN views, then choose their association here.</EmptyState> :
      <Rows head={<><th>Service</th><th>Ponor</th><th>TURN</th><th>TURN operator</th><th>Actions</th></>}>
        {services.map((service) => {
          const p = ponor.find((entry) => entry.id === service.ponor_id);
          const t = turn.find((entry) => entry.id === service.turn_id);
          return <tr key={service.id}>
            <td>{service.id}</td>
            <td><code>{p?.address ?? service.ponor_id}</code><br />
              {!service.ponor_present || !p ? <Status state="warning" label="Ponor registration missing" /> :
                <><span>Registered</span><br /><Status state={p.health.admission_state === "confirmed" ? "healthy" : p.health.admission_state === "stale" ? "warning" : "unknown"} label={`Ponor admission: ${p.health.admission_state}`} /></>}
            </td>
            <td>{service.turn_id ? <><code>{t?.uri ?? service.turn_id}</code><br />
              {!service.turn_present || !t ? <Status state="warning" label="TURN registration missing" /> : <span>Registered · runtime health unavailable</span>}
            </> : "Not configured"}</td>
            <td>{service.turn_id ? <>{service.backend_operator}<br /><span className="lede">{service.backend_kind === "external" ? "External provider" : "Coturn companion"}</span></> : "—"}</td>
            <td><button onClick={() => remove(service)}>Remove association</button></td>
          </tr>;
        })}
      </Rows>}
    <Dialog open={Boolean(draft)} title="Add Relay service" onClose={() => { if (!saving) setDraft(undefined); }}>
      <form onSubmit={(event) => { event.preventDefault(); void add(); }}>
        {draft && <Notice message={message} />}
        <label>Service name<input required maxLength={64} value={draft?.id ?? ""} onChange={(event) => setDraft((current) => current && { ...current, id: event.target.value })} /></label>
        <label>Ponor endpoint<select required value={draft?.ponor_id ?? ""} onChange={(event) => setDraft((current) => current && { ...current, ponor_id: event.target.value })}>
          <option value="">Choose an endpoint</option>{ponor.map((entry) => <option key={entry.id} value={entry.id}>{entry.address} ({entry.region})</option>)}
        </select></label>
        <label>TURN backend<select value={draft?.turn_id ?? ""} onChange={(event) => setDraft((current) => current && { ...current, turn_id: event.target.value || undefined, backend_kind: undefined, backend_operator: undefined })}>
          <option value="">None</option>{turn.map((entry) => <option key={entry.id} value={entry.id}>{entry.uri} ({entry.region})</option>)}
        </select></label>
        {draft?.turn_id && <>
          <label>TURN deployment<select required value={draft.backend_kind ?? ""} onChange={(event) => setDraft((current) => current && { ...current, backend_kind: event.target.value as RelayService["backend_kind"] })}>
            <option value="">Choose deployment type</option><option value="external">External provider</option><option value="coturn-companion">Coturn companion</option>
          </select></label>
          <label>TURN operator<input required maxLength={256} value={draft.backend_operator ?? ""} onChange={(event) => setDraft((current) => current && { ...current, backend_operator: event.target.value })} /></label>
        </>}
        <div className="actions"><button type="button" disabled={saving} onClick={() => setDraft(undefined)}>Cancel</button><button className="primary" type="submit" disabled={saving}>{saving ? "Saving…" : "Create service"}</button></div>
      </form>
    </Dialog>
  </section>;
}
