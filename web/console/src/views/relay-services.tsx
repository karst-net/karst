// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { useState } from "react";
import { Dialog, EmptyState, Status } from "@karst-net/ui";
import type { RelayService } from "@karst-net/api-client";
import { api } from "../api";
import { Failure, Notice, Rows, useMutation, usePolledResource } from "../common";
import { Relays } from "./relays";

export function RelayServices() {
  const [view, setView] = useState<"services" | "ponor">("services");
  return <section>
    <h2>Relays</h2>
    <nav aria-label="Relay configuration" className="actions">
      <button aria-pressed={view === "services"} onClick={() => setView("services")}>Services</button>
      <button aria-pressed={view === "ponor"} onClick={() => setView("ponor")}>Ponor endpoints</button>
    </nav>
    {view === "services" && <Services />}
    {view === "ponor" && <Relays />}
  </section>;
}

async function loadServices() {
  const [services, ponor, publication] = await Promise.all([api.relayServices(), api.relays(), api.relayPublication()]);
  return { services, ponor, publication };
}

function Services() {
  const resource = usePolledResource(loadServices, 60_000);
  const { message, setMessage, run } = useMutation(resource.reload);
  const [draft, setDraft] = useState<RelayService>();
  const [saving, setSaving] = useState(false);
  const [preview, setPreview] = useState<RelayService[]>();
  const [acknowledged, setAcknowledged] = useState(false);
  const [modeDraft, setModeDraft] = useState<{ service: RelayService; ponor: boolean }>();
  const [modeAcknowledged, setModeAcknowledged] = useState(false);
  if (resource.loading) return <p>Loading Relay services…</p>;
  if (resource.error) return <Failure message={resource.error} retry={resource.reload} />;
  const { services, ponor, publication } = resource.value ?? { services: [], ponor: [], publication: { mode: "legacy" } };

  const add = async () => {
    if (!draft || saving) return;
    const service: RelayService = { id: draft.id.trim(), ponor_id: draft.ponor_id };
    if (!/^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$/.test(service.id)) {
      setMessage("Use 1–64 letters, digits, underscores or hyphens for the service name, starting with a letter or digit."); return;
    }
    if (!ponor.some((entry) => entry.id === service.ponor_id)) { setMessage("Choose a registered Ponor endpoint."); return; }
    setSaving(true);
    if (await run(() => api.addRelayService(service), `Relay service ${service.id} was added.`)) setDraft(undefined);
    setSaving(false);
  };
  const remove = (service: RelayService) => {
    if (!confirm(`Remove the ${service.id} service association? ${publication.mode === "services" ? "Endpoints used only by this service will be withdrawn from clients. " : ""}Backend processes and registry records remain intact.`)) return;
    void run(() => api.removeRelayService(service.id), `Relay service ${service.id} association was removed.`);
  };

  return <section>
    <h3>Services</h3>
    <p>Associate a Ponor endpoint under one service name. Choose the backend explicitly.</p>
    <p>Endpoint publication: <strong>{publication.mode === "services" ? "Relay services" : "Legacy registries"}</strong>.</p>
    <p className="lede">{publication.mode === "services" ? "Service changes update the endpoints sent to clients. An empty service list publishes no Relay endpoints. Backend processes remain independently managed." : "Associations are staged while legacy registries publish endpoints. Preview the service list before switching publication."}</p>
    <div className="actions">
      <button disabled={saving} onClick={async () => { setMessage(undefined); setSaving(true); try { setPreview(await api.previewRelayPublication()); setAcknowledged(false); } catch (error) { setMessage((error as Error).message); } finally { setSaving(false); } }}>Preview service publication</button>
      {publication.mode === "services" && <button disabled={saving} onClick={async () => { if (!confirm("Return to legacy registry publication? Previously unassociated legacy endpoints may become available to clients again.")) return; setSaving(true); await run(() => api.setRelayPublication("legacy"), "Legacy registry publication restored."); setSaving(false); }}>Restore legacy publication</button>}
    </div>
    <div className="actions"><button className="primary" onClick={() => { setMessage(undefined); setDraft({ id: "", ponor_id: "" }); }}>Add service</button><button onClick={resource.reload}>Refresh services</button></div>
    {!draft && !modeDraft && preview === undefined && <Notice message={message} />}
    {services.length === 0 ? <EmptyState title="No Relay services configured">Existing endpoints continue operating. Register a backend in the Ponor view, then choose its association here.</EmptyState> :
      <Rows head={<><th>Service</th><th>Ponor</th><th>Actions</th></>}>
        {services.map((service) => {
          const p = ponor.find((entry) => entry.id === service.ponor_id);
          return <tr key={service.id}>
            <td>{service.id}</td>
            <td><code>{p?.address ?? service.ponor_id}</code><br />
              {service.ponor_disabled ? <Status state="unknown" label="Ponor disabled" /> : !service.ponor_present || !p ? <Status state="warning" label="Ponor registration missing" /> :
                <><span>Registered</span><br /><Status state={p.health.admission_state === "confirmed" ? "healthy" : p.health.admission_state === "stale" ? "warning" : "unknown"} label={`Ponor admission: ${p.health.admission_state}`} /></>}
            </td>
            <td><button disabled={saving} onClick={() => { setMessage(undefined); setModeAcknowledged(false); setModeDraft({ service, ponor: !service.ponor_disabled }); }}>Change modes</button><button onClick={() => remove(service)}>Remove association</button></td>
          </tr>;
        })}
      </Rows>}
    <Dialog open={Boolean(modeDraft)} title="Change Relay modes" onClose={() => { if (!saving) setModeDraft(undefined); }}>
      {modeDraft && <><Notice message={message} />
        <p>Service: <strong>{modeDraft.service.id}</strong></p>
        <p>{publication.mode === "services" ? "Mode changes update endpoints sent to clients. Shared endpoints remain available while another service enables them." : "This mode is staged while legacy registries still publish endpoints. Switch to service publication to apply it to clients."}</p>
        <label><input type="checkbox" checked={modeDraft.ponor} onChange={(event) => setModeDraft({ ...modeDraft, ponor: event.target.checked })} />Enable Ponor</label>
        <label><input type="checkbox" checked={modeAcknowledged} onChange={(event) => setModeAcknowledged(event.target.checked)} />I understand mode changes may interrupt client connectivity.</label>
        <div className="actions"><button disabled={saving} onClick={() => setModeDraft(undefined)}>Cancel</button><button disabled={!modeAcknowledged || saving} onClick={async () => { setSaving(true); if (await run(() => api.setRelayServiceModes(modeDraft.service.id, modeDraft.ponor), `Relay modes for ${modeDraft.service.id} were updated.`)) setModeDraft(undefined); setSaving(false); }}>Apply modes</button></div>
      </>}
    </Dialog>
    <Dialog open={preview !== undefined} title="Preview service publication" onClose={() => { if (!saving) setPreview(undefined); }}>
      {preview !== undefined && <Notice message={message} />}
      <p>These service associations will replace the legacy endpoint selection. Configuration is validated again when applied. This can interrupt connectivity for clients that need an omitted backend.</p>
      {preview?.length ? <ul>{preview.map((service) => <li key={service.id}><strong>{service.id}</strong>: Ponor <code>{ponor.find((entry) => entry.id === service.ponor_id)?.address ?? service.ponor_id}</code>{service.ponor_disabled ? " (disabled)" : ""}</li>)}</ul> : <p>No services: all Relay endpoints will be withdrawn from clients.</p>}
      <label><input type="checkbox" checked={acknowledged} onChange={(event) => setAcknowledged(event.target.checked)} />I understand this changes client connectivity.</label>
      <div className="actions"><button disabled={saving} onClick={() => setPreview(undefined)}>Cancel</button><button disabled={!acknowledged || saving} onClick={async () => { setSaving(true); if (await run(() => api.setRelayPublication("services"), "Relay service publication enabled.")) setPreview(undefined); setSaving(false); }}>Publish services</button></div>
    </Dialog>
    <Dialog open={Boolean(draft)} title="Add Relay service" onClose={() => { if (!saving) setDraft(undefined); }}>
      <form onSubmit={(event) => { event.preventDefault(); void add(); }}>
        {draft && <Notice message={message} />}
        <label>Service name<input required maxLength={64} value={draft?.id ?? ""} onChange={(event) => setDraft((current) => current && { ...current, id: event.target.value })} /></label>
        <label>Ponor endpoint<select required value={draft?.ponor_id ?? ""} onChange={(event) => setDraft((current) => current && { ...current, ponor_id: event.target.value })}>
          <option value="">Choose an endpoint</option>{ponor.map((entry) => <option key={entry.id} value={entry.id}>{entry.address} ({entry.region})</option>)}
        </select></label>
        <div className="actions"><button type="button" disabled={saving} onClick={() => setDraft(undefined)}>Cancel</button><button className="primary" type="submit" disabled={saving}>{saving ? "Saving…" : "Create service"}</button></div>
      </form>
    </Dialog>
  </section>;
}
