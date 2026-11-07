// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { useEffect, useState } from "react";
import { Dialog, EmptyState, Observed, Status } from "@karst-net/ui";
import type { Relay, RelayAllocation, RelayService } from "@karst-net/api-client";
import { api, type ManagedRelayService } from "../api";
import { RelayReadiness } from "./relay-readiness";
import { RelayAccess } from "./relay-access";
import { AllocateRelay } from "./relay-allocation";
import { Failure, Notice, Rows, useMutation, usePolledResource } from "../common";
import { allocationStatus } from "../relay-allocation-status";
import { RelayInstallation } from "./relay-installation";
import { RelayRegistration } from "./relay-registration";

export function RelayServices() {
  const resource = usePolledResource(async () => { const [services, publication] = await Promise.all([api.relayServices(), api.relayPublication()]); return { services, publication }; }, 60_000);
  const endpoints = usePolledResource(api.relays, 60_000);
  const groups = usePolledResource(api.groups, 60_000);
  const gateways = usePolledResource(api.gateways, 15_000);
  const admission = usePolledResource(api.relayAdmissionTargets, 15_000);
  const allocations = usePolledResource(api.relayAllocations, 15_000);
  const [now, setNow] = useState(Date.now());
  useEffect(() => { const timer = setInterval(() => setNow(Date.now()), 5_000); return () => clearInterval(timer); }, []);
  const reload = () => { resource.reload(); endpoints.reload(); groups.reload(); gateways.reload(); admission.reload(); allocations.reload(); setNow(Date.now()); };
  const { message, setMessage, run } = useMutation(reload);
  // One "Add relay" entry point (ADR-0067), not three differently shaped
  // pages: "choice" is the branching question, the other three steps are
  // today's unchanged dialogs, just reached from here instead of their
  // own buttons. "install" can hand off directly into "register" once its
  // own handoff is downloaded (RelayInstallation's onContinue).
  const [addRelayStep, setAddRelayStep] = useState<"choice" | "register" | "install" | "allocate">();
  const [relayId, setRelayId] = useState<string>();
  const [details, setDetails] = useState<Relay>();
  const [saving, setSaving] = useState(false);
  const [configuring, setConfiguring] = useState<ManagedRelayService | "new">();
  const [preview, setPreview] = useState<RelayService[]>();
  const [acknowledged, setAcknowledged] = useState(false);
  const [modeDraft, setModeDraft] = useState<{ service: RelayService; ponor: boolean }>();
  const [modeAcknowledged, setModeAcknowledged] = useState(false);
  if (resource.loading || endpoints.loading) return <p>Loading relays…</p>;
  const { services, publication } = resource.value ?? { services: [], publication: { mode: "legacy" } };
  const ponor = endpoints.value ?? [];
  const unconfigured = ponor.filter(endpoint => !services.some(service => service.ponor_id === endpoint.id));

  const remove = (service: RelayService) => {
    if (!confirm(`Remove the ${service.id} service association? ${publication.mode === "services" ? "Endpoints used only by this service will be withdrawn from clients. " : ""}Backend processes and registry records remain intact.`)) return;
    void run(() => api.removeRelayService(service.id), `Relay service ${service.id} association was removed.`);
  };
  const deprovisionAllocation = (allocation: RelayAllocation) => {
    if (!allocation.id || allocation.revision === undefined) return;
    if (!confirm(`Deprovision the ${allocation.name} allocation? This withdraws its access grant before the host is destroyed.`)) return;
    void run(() => api.deprovisionRelayAllocation(allocation.id!, allocation.revision!), `${allocation.name} deprovisioning requested.`);
  };
  const removeAllocation = (allocation: RelayAllocation) => {
    if (!allocation.id || allocation.revision === undefined) return;
    if (!confirm(`Remove the ${allocation.name} allocation record?`)) return;
    void run(() => api.deleteRelayAllocation(allocation.id!, allocation.revision!), `${allocation.name} allocation record was removed.`);
  };

  return <section>
    <h2>Relays</h2>
    <p>Manage relay endpoints, group access, internet egress and health in one place. Ponor is the relay transport; a service stores the endpoint's access and publication settings.</p>
    <div className="actions"><button className="primary" onClick={() => setAddRelayStep("choice")}>Add relay</button><button onClick={reload}>Refresh relays</button></div>
    <p className="lede">One workflow covers all three situations: a relay already running somewhere, a host with nothing on it yet, or no host at all. <strong>Add relay</strong> asks which applies, then takes you through the right steps — only the last one, provisioning a new host, actually creates anything.</p>
    {resource.error && <Failure message={resource.error} retry={resource.reload} />}
    {endpoints.error && <Failure message={endpoints.error} retry={endpoints.reload} />}
    {admission.error && services.some(service => service.access_managed) && <p role="alert">Admission writer observations unavailable: {admission.error}</p>}
    {gateways.error && services.some(service => service.exit_ipv4 || service.exit_ipv6) && <p role="alert">Gateway observations unavailable: {gateways.error}</p>}
    <p className="lede">Operational status shows the last reported observations, separate from saved configuration. Writer refresh does not prove a particular policy revision has reached the relay. Gateway readiness is self-reported, and clients still choose whether to use internet egress.</p>
    <details><summary>Advanced publication and legacy settings</summary>
    <p>Endpoint publication: <strong>{resource.error ? "Unknown" : publication.mode === "services" ? "Configured relays" : "Legacy registries"}</strong>.</p>
    <p className="lede">{resource.error ? "Publication status could not be loaded." : publication.mode === "services" ? "Only enabled, associated endpoints are sent to clients." : "Legacy registry endpoints are published account-wide. Preview the configured relays before switching publication."}</p>
    <div className="actions">
      <button disabled={saving || Boolean(resource.error)} onClick={async () => { setMessage(undefined); setSaving(true); try { setPreview(await api.previewRelayPublication()); setAcknowledged(false); } catch (error) { setMessage((error as Error).message); } finally { setSaving(false); } }}>Preview service publication</button>
      {publication.mode === "services" && <button disabled={saving || Boolean(resource.error)} onClick={async () => { if (!confirm("Return to legacy registry publication? Previously unassociated legacy endpoints may become available to clients again.")) return; setSaving(true); await run(() => api.setRelayPublication("legacy"), "Legacy registry publication restored."); setSaving(false); }}>Restore legacy publication</button>}
    </div>
    </details>
    {!modeDraft && !details && !addRelayStep && preview === undefined && <Notice message={message} />}
    {!resource.error && !endpoints.error && services.length === 0 && ponor.length === 0 ? <EmptyState title="No relays configured">Add a running relay, then choose its allowed groups and optional internet egress.</EmptyState> :
      <Rows head={<><th>Relay</th><th>Endpoint and health</th><th>Access</th><th>Operational status</th><th>Actions</th></>}>
        {services.map((service) => {
          const p = ponor.find((entry) => entry.id === service.ponor_id);
          return <tr key={`service-${service.id}`}>
            <td>{service.id}</td>
            <td><code>{p?.address ?? service.ponor_id}</code><br />
              {service.ponor_disabled ? <Status state="unknown" label="Relay disabled" /> : endpoints.error ? <Status state="unknown" label="Endpoint health unavailable" /> : !service.ponor_present || !p ? <Status state="warning" label="Endpoint registration missing" /> :
                <><span>Registered</span><br /><Status state={p.health.admission_state === "confirmed" ? "healthy" : p.health.admission_state === "stale" ? "warning" : "unknown"} label={`Admission: ${p.health.admission_state}`} /></>}
            </td>
            <td>{resource.error ? "Unknown" : service.access_managed ? <>Allowed groups: {service.allowed_groups?.length ?? 0}<br />{groups.error ? "Group names unavailable" : service.allowed_groups?.map(id => groups.value?.find(group => group.id === id)?.name ?? "Unavailable group").join(", ")}<br />Internet egress: {service.exit_ipv4 || service.exit_ipv6 ? [service.exit_ipv4 && "IPv4", service.exit_ipv6 && "IPv6"].filter(Boolean).join(", ") : "Disabled"}</> : "Legacy account-wide access"}</td>
            <td>{resource.error ? "Configuration unavailable" : <RelayReadiness service={service} targets={admission.value} inventory={gateways.value} targetError={admission.error} gatewayError={gateways.error} now={now} />}</td>
            <td>{p && <button onClick={() => { setMessage(undefined); setDetails(p); }}>Endpoint details</button>}<button disabled={Boolean(resource.error || endpoints.error)} onClick={() => setConfiguring(service)}>Configure access to {service.id}</button><button disabled={saving || Boolean(resource.error)} onClick={() => { setMessage(undefined); setModeAcknowledged(false); setModeDraft({ service, ponor: !service.ponor_disabled }); }}>Change availability</button><button disabled={Boolean(resource.error)} onClick={() => remove(service)}>Remove configuration</button></td>
          </tr>;
        })}
        {!endpoints.error && unconfigured.map(endpoint => <tr key={`endpoint-${endpoint.id}`}>
          <td>{endpoint.region || "Unnamed relay"}<br /><span className="lede">{resource.error ? "Configuration unavailable" : "Not configured"}</span></td>
          <td><code>{endpoint.address}</code><br /><Status state={endpoint.health.admission_state === "confirmed" ? "healthy" : endpoint.health.admission_state === "stale" ? "warning" : "unknown"} label={`Admission: ${endpoint.health.admission_state}`} /></td>
          <td>{resource.error ? "Unknown" : publication.mode === "legacy" ? "Legacy account-wide access" : "Not published"}</td>
          <td>Configure group access to track managed admission and egress.</td>
          <td><button onClick={() => { setMessage(undefined); setDetails(endpoint); }}>Endpoint details</button><button disabled={Boolean(resource.error)} onClick={() => { setRelayId(endpoint.id); setConfiguring("new"); }}>Configure relay</button></td>
        </tr>)}
      </Rows>}

    <h3>Relay allocations</h3>
    <p className="lede">ADR-0063: name a host, pick its infrastructure connection and location, and choose the permitted groups — provisioning and granting access happen in the background. Internet egress is not yet supported by this workflow.</p>
    {allocations.error && <Failure message={allocations.error} retry={allocations.reload} />}
    {!allocations.error && (allocations.value ?? []).length === 0
      ? <EmptyState title="No relay allocations">Use Add relay — "No, provision one for me" — to provision a new host through a real infrastructure connection.</EmptyState>
      : <Rows head={<><th>Name</th><th>Location</th><th>Permitted groups</th><th>Status</th><th>Actions</th></>}>
        {(allocations.value ?? []).map(allocation => {
          const status = allocationStatus(allocation);
          const canDeprovision = allocation.state === "ready" || allocation.state === "failed";
          const canRemove = allocation.state === "requested" || allocation.state === "deprovisioned";
          return <tr key={`allocation-${allocation.id}`}>
            <td>{allocation.name}</td>
            <td>{allocation.infra_connection_id}: <code>{allocation.location}</code></td>
            <td>{groups.error ? "Group names unavailable" : allocation.permitted_groups.map(id => groups.value?.find(group => group.id === id)?.name ?? "Unavailable group").join(", ")}</td>
            <td><Status state={status.state} label={status.label} /></td>
            <td>{canDeprovision && <button onClick={() => deprovisionAllocation(allocation)}>Deprovision</button>}{canRemove && <button className="danger" onClick={() => removeAllocation(allocation)}>Remove</button>}</td>
          </tr>;
        })}
      </Rows>}

    {addRelayStep === "choice" && <Dialog open title="Add relay" onClose={() => setAddRelayStep(undefined)}>
      <p>Is this relay already running somewhere?</p>
      <div className="actions">
        <button className="primary" onClick={() => setAddRelayStep("register")}>Yes — register it</button>
        <button onClick={() => setAddRelayStep("install")}>I have a host, but nothing is running on it yet</button>
        <button onClick={() => setAddRelayStep("allocate")}>No, provision one for me</button>
      </div>
      <p className="lede">Installing generates a script for an existing control host, then still finishes by registering the result. Provisioning is the only one of the three that creates anything, through an already-configured infrastructure connection.</p>
      <div className="actions"><button onClick={() => setAddRelayStep(undefined)}>Cancel</button></div>
    </Dialog>}
    {addRelayStep === "install" && <RelayInstallation onClose={() => setAddRelayStep(undefined)} onContinue={() => setAddRelayStep("register")} />}
    {addRelayStep === "register" && <RelayRegistration onClose={() => setAddRelayStep(undefined)} onAdded={endpoint => { setAddRelayStep(undefined); reload(); setRelayId(endpoint.id); setConfiguring(services.find(service => service.ponor_id === endpoint.id) ?? "new"); setMessage("Endpoint registered. Configure group access to complete setup."); }} />}
    {addRelayStep === "allocate" && <AllocateRelay onClose={() => setAddRelayStep(undefined)} onAllocated={() => { setAddRelayStep(undefined); reload(); setMessage("Relay allocation requested. It will show as pending until it registers and access is granted."); }} />}
    <Dialog open={Boolean(details)} title="Relay endpoint details" onClose={() => setDetails(undefined)}>
      {details && <><Notice message={message} /><dl><dt>Address</dt><dd>{details.address}</dd><dt>TLS server name</dt><dd>{details.tls_server_name}</dd><dt>Region</dt><dd>{details.region}</dd><dt>Location</dt><dd>{details.location?.label || (details.location ? `${details.location.lat}, ${details.location.lon}` : "No location")}</dd><dt>Last confirmed</dt><dd><Observed at={details.health.last_confirmed_at} /></dd></dl>
      <p>Health is the relay's signed report. A stale report does not prove the process stopped forwarding traffic.</p>
      {services.some(service => service.ponor_id === details.id) ? <p>Remove all relay configurations using this endpoint before deleting its registration.</p> : <button className="danger" disabled={Boolean(resource.error)} onClick={async () => { if (!confirm(`Remove the endpoint at ${details.address}? Clients relying on it may lose connectivity. The running process will remain intact.`)) return; if (await run(() => api.removeRelay(details.id), "Relay endpoint removed.")) setDetails(undefined); }}>Remove endpoint</button>}
      <button onClick={() => setDetails(undefined)}>Close</button></>}
    </Dialog>
    {configuring && <RelayAccess relayId={relayId} service={configuring === "new" ? undefined : configuring} onClose={() => { setConfiguring(undefined); setRelayId(undefined); }} onSaved={() => { setConfiguring(undefined); setRelayId(undefined); reload(); setMessage("Relay configuration saved. Operational observations below show reported admission and forwarding status."); }} />}
    <Dialog open={Boolean(modeDraft)} title="Change relay availability" onClose={() => { if (!saving) setModeDraft(undefined); }}>
      {modeDraft && <><Notice message={message} />
        <p>Relay: <strong>{modeDraft.service.id}</strong></p>
        <p>{publication.mode === "services" ? "Mode changes update endpoints sent to clients. Shared endpoints remain available while another service enables them." : "This mode is staged while legacy registries still publish endpoints. Switch to service publication to apply it to clients."}</p>
        <label><input type="checkbox" checked={modeDraft.ponor} onChange={(event) => setModeDraft({ ...modeDraft, ponor: event.target.checked })} />Enable relay</label>
        <label><input type="checkbox" checked={modeAcknowledged} onChange={(event) => setModeAcknowledged(event.target.checked)} />I understand mode changes may interrupt client connectivity.</label>
        <div className="actions"><button disabled={saving} onClick={() => setModeDraft(undefined)}>Cancel</button><button disabled={!modeAcknowledged || saving} onClick={async () => { setSaving(true); if (await run(() => api.setRelayServiceModes(modeDraft.service.id, modeDraft.ponor), `Relay modes for ${modeDraft.service.id} were updated.`)) setModeDraft(undefined); setSaving(false); }}>Apply availability</button></div>
      </>}
    </Dialog>
    <Dialog open={preview !== undefined} title="Preview service publication" onClose={() => { if (!saving) setPreview(undefined); }}>
      {preview !== undefined && <Notice message={message} />}
      <p>These service associations will replace the legacy endpoint selection. Configuration is validated again when applied. This can interrupt connectivity for clients that need an omitted backend.</p>
      {preview?.length ? <ul>{preview.map((service) => <li key={`service-${service.id}`}><strong>{service.id}</strong>: Ponor <code>{ponor.find((entry) => entry.id === service.ponor_id)?.address ?? service.ponor_id}</code>{service.ponor_disabled ? " (disabled)" : ""}</li>)}</ul> : <p>No services: all Relay endpoints will be withdrawn from clients.</p>}
      <label><input type="checkbox" checked={acknowledged} onChange={(event) => setAcknowledged(event.target.checked)} />I understand this changes client connectivity.</label>
      <div className="actions"><button disabled={saving} onClick={() => setPreview(undefined)}>Cancel</button><button disabled={!acknowledged || saving} onClick={async () => { setSaving(true); if (await run(() => api.setRelayPublication("services"), "Relay service publication enabled.")) setPreview(undefined); setSaving(false); }}>Publish services</button></div>
    </Dialog>
  </section>;
}
