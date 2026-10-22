// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { useState } from "react";
import { Dialog, EmptyState, Observed, Status } from "@karst-net/ui";
import type { RelayService } from "@karst-net/api-client";
import { api } from "../api";
import { Failure, Notice, Rows, useMutation, usePolledResource } from "../common";
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
  const [services, ponor, turn, publication] = await Promise.all([api.relayServices(), api.relays(), api.turns(), api.relayPublication()]);
  return { services, ponor, turn, publication };
}

function Services() {
  const resource = usePolledResource(loadServices, 60_000);
  const { message, setMessage, run } = useMutation(resource.reload);
  const [draft, setDraft] = useState<RelayService>();
  const [saving, setSaving] = useState(false);
  const [preview, setPreview] = useState<RelayService[]>();
  const [acknowledged, setAcknowledged] = useState(false);
  const [modeDraft, setModeDraft] = useState<{ service: RelayService; ponor: boolean; turn: boolean }>();
  const [modeAcknowledged, setModeAcknowledged] = useState(false);
  if (resource.loading) return <p>Loading Relay services…</p>;
  if (resource.error) return <Failure message={resource.error} retry={resource.reload} />;
  const { services, ponor, turn, publication } = resource.value ?? { services: [], ponor: [], turn: [], publication: { mode: "legacy" } };

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
    if (!confirm(`Remove the ${service.id} service association? ${publication.mode === "services" ? "Endpoints used only by this service will be withdrawn from clients. " : ""}Backend processes and registry records remain intact.`)) return;
    void run(() => api.removeRelayService(service.id), `Relay service ${service.id} association was removed.`);
  };

  return <section>
    <h3>Services</h3>
    <p>Group a Ponor endpoint and optional TURN backend under one service name. Choose each backend explicitly, including who operates TURN.</p>
    <p>Endpoint publication: <strong>{publication.mode === "services" ? "Relay services" : "Legacy registries"}</strong>.</p>
    <p className="lede">{publication.mode === "services" ? "Service changes update the endpoints sent to clients. An empty service list publishes no Relay endpoints. Backend processes remain independently managed." : "Associations are staged while legacy registries publish endpoints. Preview the service list before switching publication."}</p>
    <div className="actions">
      <button disabled={saving} onClick={async () => { setMessage(undefined); setSaving(true); try { setPreview(await api.previewRelayPublication()); setAcknowledged(false); } catch (error) { setMessage((error as Error).message); } finally { setSaving(false); } }}>Preview service publication</button>
      {publication.mode === "services" && <button disabled={saving} onClick={async () => { if (!confirm("Return to legacy registry publication? Previously unassociated legacy endpoints may become available to clients again.")) return; setSaving(true); await run(() => api.setRelayPublication("legacy"), "Legacy registry publication restored."); setSaving(false); }}>Restore legacy publication</button>}
    </div>
    <div className="actions"><button className="primary" onClick={() => { setMessage(undefined); setDraft({ id: "", ponor_id: "" }); }}>Add service</button><button onClick={resource.reload}>Refresh services</button></div>
    {!draft && !modeDraft && preview === undefined && <Notice message={message} />}
    {services.length === 0 ? <EmptyState title="No Relay services configured">Existing endpoints continue operating. Register backends in the Ponor and TURN views, then choose their association here.</EmptyState> :
      <Rows head={<><th>Service</th><th>Ponor</th><th>TURN</th><th>TURN operator</th><th>Actions</th></>}>
        {services.map((service) => {
          const p = ponor.find((entry) => entry.id === service.ponor_id);
          const t = turn.find((entry) => entry.id === service.turn_id);
          return <tr key={service.id}>
            <td>{service.id}</td>
            <td><code>{p?.address ?? service.ponor_id}</code><br />
              {service.ponor_disabled ? <Status state="unknown" label="Ponor disabled" /> : !service.ponor_present || !p ? <Status state="warning" label="Ponor registration missing" /> :
                <><span>Registered</span><br /><Status state={p.health.admission_state === "confirmed" ? "healthy" : p.health.admission_state === "stale" ? "warning" : "unknown"} label={`Ponor admission: ${p.health.admission_state}`} /></>}
            </td>
            <td>{service.turn_id ? <><code>{t?.uri ?? service.turn_id}</code><br />
              {service.turn_disabled ? <Status state="unknown" label="TURN disabled" /> : !service.turn_present || !t ? <Status state="warning" label="TURN registration missing" /> : <><span>Registered</span><br />
                <Status state={service.turn_health?.state === "ready" ? "healthy" : !service.turn_health || service.turn_health.state === "unknown" ? "unknown" : "warning"} label={`TURN allocation: ${service.turn_health?.state.replaceAll("_", " ") ?? "not observed"}`} />
                {service.turn_health?.observed_at && <><br /><Observed at={service.turn_health.observed_at} />{service.turn_health.duration_ms !== undefined && <span> · {service.turn_health.duration_ms} ms</span>}</>}
                {service.turn_health?.state === "stale" && <><br /><span>Last result: {service.turn_health.last_result?.replaceAll("_", " ")}</span></>}
              </>}
            </> : "Not configured"}</td>
            <td>{service.turn_id ? <>{service.backend_operator}<br /><span className="lede">{service.backend_kind === "external" ? "External provider" : "Coturn companion"}</span></> : "—"}</td>
            <td><button disabled={saving} onClick={() => { setMessage(undefined); setModeAcknowledged(false); setModeDraft({ service, ponor: !service.ponor_disabled, turn: Boolean(service.turn_id) && !service.turn_disabled }); }}>Change modes</button><button onClick={() => remove(service)}>Remove association</button></td>
          </tr>;
        })}
      </Rows>}
    <p className="lede">TURN allocation readiness is measured from control using a short-lived credential. It tests admission, not encrypted delivery or every client's path. Checks run about once a minute; observations become stale after three minutes.</p>
    <Dialog open={Boolean(modeDraft)} title="Change Relay modes" onClose={() => { if (!saving) setModeDraft(undefined); }}>
      {modeDraft && <><Notice message={message} />
        <p>Service: <strong>{modeDraft.service.id}</strong></p>
        <p>{publication.mode === "services" ? "Mode changes update endpoints sent to clients. Shared endpoints remain available while another service enables them." : "These modes are staged while legacy registries still publish endpoints. Switch to service publication to apply them to clients."}</p>
        <p>Disabling TURN pauses subsequent readiness probes for this association. Backend processes remain running. TURN publication requires an enabled Ponor bootstrap endpoint in this account.</p>
        <label><input type="checkbox" checked={modeDraft.ponor} onChange={(event) => setModeDraft({ ...modeDraft, ponor: event.target.checked })} />Enable Ponor</label>
        <label><input type="checkbox" checked={modeDraft.turn} disabled={!modeDraft.service.turn_id} onChange={(event) => setModeDraft({ ...modeDraft, turn: event.target.checked })} />Enable TURN</label>
        <label><input type="checkbox" checked={modeAcknowledged} onChange={(event) => setModeAcknowledged(event.target.checked)} />I understand mode changes may interrupt client connectivity.</label>
        <div className="actions"><button disabled={saving} onClick={() => setModeDraft(undefined)}>Cancel</button><button disabled={!modeAcknowledged || saving} onClick={async () => { setSaving(true); if (await run(() => api.setRelayServiceModes(modeDraft.service.id, modeDraft.ponor, modeDraft.turn), `Relay modes for ${modeDraft.service.id} were updated.`)) setModeDraft(undefined); setSaving(false); }}>Apply modes</button></div>
      </>}
    </Dialog>
    <Dialog open={preview !== undefined} title="Preview service publication" onClose={() => { if (!saving) setPreview(undefined); }}>
      {preview !== undefined && <Notice message={message} />}
      <p>These service associations will replace the legacy endpoint selection. Configuration is validated again when applied. This can interrupt connectivity for clients that need an omitted backend.</p>
      {preview?.length ? <ul>{preview.map((service) => <li key={service.id}><strong>{service.id}</strong>: Ponor <code>{ponor.find((entry) => entry.id === service.ponor_id)?.address ?? service.ponor_id}</code>{service.ponor_disabled ? " (disabled)" : ""}; TURN {service.turn_id ? <><code>{turn.find((entry) => entry.id === service.turn_id)?.uri ?? service.turn_id}</code> ({service.turn_disabled ? "disabled; " : ""}{service.backend_operator})</> : "not configured"}</li>)}</ul> : <p>No services: all Relay endpoints will be withdrawn from clients.</p>}
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
