// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { useState } from "react";
import { Dialog } from "@karst-net/ui";
import { api, type ManagedRelayService } from "../api";
import { Failure, useResource } from "../common";
import { GroupPicker } from "./access";

export function RelayAccess({ service, relayId, onClose, onSaved }: { service?: ManagedRelayService; relayId?: string; onClose: () => void; onSaved: () => void }) {
  const groups = useResource(api.groups);
  const relays = useResource(api.relays);
  const targets = useResource(api.relayAdmissionTargets);
  const publication = useResource(api.relayPublication);
  const policySchema = useResource(api.policySchema);
  const scopedGatewaySupported = Boolean((policySchema.value?.properties as { grants?: { items?: { properties?: { gateway?: unknown } } } } | undefined)?.grants?.items?.properties?.gateway);
  const machines = useResource(async () => { const result = await api.nodes(); while (result.next_cursor) { const next = await api.nodes(result.next_cursor); result.items.push(...next.items); result.next_cursor = next.next_cursor; } return result; });
  const [draft, setDraft] = useState<ManagedRelayService>(service ? { id: service.id, ponor_id: service.ponor_id, access_managed: true, allowed_groups: service.allowed_groups ?? [], gateway_handle: service.gateway_handle ?? "", exit_ipv4: service.exit_ipv4 ?? false, exit_ipv6: service.exit_ipv6 ?? false, metric: service.metric || 9999, revision: service.revision ?? 0 } : { id: "", ponor_id: relayId ?? "", access_managed: true, allowed_groups: [], metric: 9999 });
  const [busy, setBusy] = useState(false);
  const [review, setReview] = useState(false);
  const [acknowledged, setAcknowledged] = useState(false);
  const [message, setMessage] = useState<string>();
  const supported = targets.value?.some(target => target.relay_id === draft.ponor_id) ?? false;
  const ready = publication.value?.mode === "services" && supported && (draft.allowed_groups?.length ?? 0) > 0 && Boolean(draft.id.trim()) && (!(draft.exit_ipv4 || draft.exit_ipv6) || Boolean(scopedGatewaySupported && draft.gateway_handle && machines.value?.items.some(node => node.handle === draft.gateway_handle)));
  const save = async () => {
    setBusy(true); setMessage(undefined);
    try { if (service) await api.setRelayAccess(draft); else await api.addRelayService({ ...draft, id: draft.id.trim() }); onSaved(); }
    catch (error) { setMessage((error as Error).message); setReview(false); }
    finally { setBusy(false); }
  };
  return <Dialog open title={service ? `Configure access to ${service.id}` : "Configure a relay"} onClose={() => { if (!busy) onClose(); }}>
    {message && <p role="alert">{message}</p>}
    {groups.error && <Failure message={groups.error} retry={groups.reload} />}
    {relays.error && <Failure message={relays.error} retry={relays.reload} />}
    {targets.error && <Failure message={targets.error} retry={targets.reload} />}
    {policySchema.error && <Failure message={policySchema.error} retry={policySchema.reload} />}
    {(draft.exit_ipv4 || draft.exit_ipv6) && !policySchema.loading && !scopedGatewaySupported && <p role="alert">Upgrade the control service to support destination-scoped Gateway ingress before configuring internet egress.</p>}
    {publication.error && <Failure message={publication.error} retry={publication.reload} />}
    {publication.value?.mode === "legacy" && <p role="status">Preview and enable service publication on the Relays page before applying group access. Existing relay publication stays unchanged until then.</p>}
    {!review ? <form onSubmit={event => { event.preventDefault(); setReview(true); setAcknowledged(false); }}>
      <label>Relay name<input required maxLength={draft.exit_ipv4 || draft.exit_ipv6 ? 40 : 64} disabled={Boolean(service)} value={draft.id} onChange={event => setDraft({ ...draft, id: event.target.value })} /></label>
      <label>Registered relay<select aria-label="Registered relay" required disabled={Boolean(service)} value={draft.ponor_id} onChange={event => setDraft({ ...draft, ponor_id: event.target.value })}><option value="">Choose a relay</option>{relays.value?.map(relay => <option key={relay.id} value={relay.id}>{relay.address} — {relay.region}</option>)}</select></label>
      <p>This configures an already running relay. Register its endpoint first if it is missing. Creating cloud or cluster workloads is not supported here.</p>
      {draft.ponor_id && !supported && !targets.loading && <p role="alert">This backend has no live admission-management connection. Group restrictions cannot be applied until its identity-bound roster writer is available.</p>}
      <GroupPicker label="Groups allowed to use this relay" groups={groups.value ?? []} value={draft.allowed_groups ?? []} onChange={allowed_groups => setDraft({ ...draft, allowed_groups })} />
      <fieldset><legend>Internet egress</legend><label><input type="checkbox" checked={draft.exit_ipv4 ?? false} onChange={event => setDraft({ ...draft, exit_ipv4: event.target.checked })} />Offer internet access over IPv4</label><label><input type="checkbox" checked={draft.exit_ipv6 ?? false} onChange={event => setDraft({ ...draft, exit_ipv6: event.target.checked })} />Offer internet access over IPv6</label></fieldset>
      {(draft.exit_ipv4 || draft.exit_ipv6) && <><label>Enrolled Gateway machine<select aria-label="Enrolled Gateway machine" required value={draft.gateway_handle ?? ""} onChange={event => setDraft({ ...draft, gateway_handle: event.target.value })}><option value="">Choose the machine providing internet egress</option>{machines.value?.items.filter(node => node.platform.toLowerCase().includes("linux")).map(node => <option key={node.handle} value={node.handle}>{node.name}</option>)}</select></label>{machines.error && <Failure message={machines.error} retry={machines.reload} />}<p>Select the enrolled Linux machine explicitly. The relay process forwards encrypted traffic; this machine provides internet egress. Forwarding readiness and each client's exit consent still apply.</p><details><summary>Advanced settings</summary><label>Route priority<input type="number" min={1} max={9999} value={draft.metric ?? 9999} onChange={event => setDraft({ ...draft, metric: Number(event.target.value) })} /></label></details></>}
      <div className="actions"><button type="button" disabled={busy} onClick={onClose}>Cancel</button><button type="submit" disabled={!ready || busy || groups.loading}>Review relay configuration</button></div>
    </form> : <>
      <p>Relay: <strong>{draft.id}</strong>. Allowed groups: {draft.allowed_groups?.map(id => groups.value?.find(group => group.id === id)?.name ?? "Unavailable group").join(", ")}.</p>
      <p>Internet egress: {draft.exit_ipv4 ? "IPv4 " : ""}{draft.exit_ipv6 ? "IPv6 " : ""}{!draft.exit_ipv4 && !draft.exit_ipv6 ? "Disabled" : `through ${machines.value?.items.find(node => node.handle === draft.gateway_handle)?.name ?? "the selected Gateway"}`}.</p>
      <p>{(draft.exit_ipv4 || draft.exit_ipv6) && "The selected groups gain destination-only forwarding through the Gateway. This grants no access to services on the Gateway machine. Upgrade the Gateway agent to support scoped ingress before applying. "}Applying changes updates admission on the next roster refresh and may disconnect existing clients. Exit routes are offers requiring local client consent. Configuration is saved atomically; running readiness is reported separately.</p>
      <label><input type="checkbox" checked={acknowledged} onChange={event => setAcknowledged(event.target.checked)} />I reviewed the allowed groups and internet access.</label>
      <div className="actions"><button disabled={busy} onClick={() => setReview(false)}>Back</button><button className="primary" disabled={busy || !acknowledged || !ready} onClick={() => void save()}>Apply relay configuration</button></div>
    </>}
  </Dialog>;
}
