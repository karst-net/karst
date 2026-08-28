// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { useState } from "react";
import { Dialog, EmptyState, Observed, Status } from "@karst-net/ui";
import { api, type SetupKey, type SetupKeyDraft } from "../api";
import { Failure, Notice, Rows, idList, useMutation, useResource } from "../common";

const blank: SetupKeyDraft = { name: "", type: "one-off", expires_in: 86_400, usage_limit: 1, auto_groups: [], ephemeral: false };
const days = [["1 day", 86_400], ["7 days", 604_800], ["30 days", 2_592_000], ["90 days", 7_776_000]] as const;

const keyState = (key: SetupKey) => key.state ?? (key.revoked ? "revoked" : "valid");
const stateStatus = (state: string) => state === "valid" ? "healthy" : state === "revoked" ? "danger" : "warning";

export function Keys() {
  const resource = useResource(api.setupKeys);
  const { message, setMessage, run } = useMutation(resource.reload);
  const [draft, setDraft] = useState<SetupKeyDraft>();
  const [created, setCreated] = useState<SetupKey>();

  if (resource.loading) return <p>Loading auth keys…</p>;
  if (resource.error) return <Failure message={resource.error} retry={resource.reload} />;
  const keys = resource.value ?? [];

  const create = async () => {
    if (!draft) return;
    try {
      const key = await api.createSetupKey({ ...draft, name: draft.name.trim() || "First node" });
      setCreated(key);
      setMessage("Copy this key now. It will not be shown again.");
      resource.reload();
    } catch (error) { setMessage((error as Error).message); }
  };
  const revoke = (key: SetupKey) => {
    if (!confirm(`Revoke ${key.name}? Machines already enrolled with it keep working; the key stops admitting new ones.`)) return;
    void run(() => api.revokeSetupKey(key), `${key.name} was revoked.`);
  };
  const remove = (key: SetupKey) => {
    if (!confirm(`Delete ${key.name}? Revoking is usually what you want — a deleted key leaves no record that it existed.`)) return;
    void run(() => api.deleteSetupKey(key.id), `${key.name} was deleted.`);
  };

  return <section>
    <h2>Auth keys</h2>
    <p className="lede">A key is how a machine enrols. Store it securely and use it only for the enrolment command.</p>
    <div className="actions"><button className="primary" onClick={() => { setCreated(undefined); setDraft(blank); }}>Create auth key</button></div>
    <Notice message={message} />
    {created && <label>New auth key<input aria-label="New auth key" readOnly value={created.key} /></label>}
    <h3>Existing keys</h3>
    {keys.length === 0
      ? <EmptyState title="No auth keys">Create a short-lived, one-time key for your first node.</EmptyState>
      : <Rows head={<><th>Name</th><th>Type</th><th>State</th><th>Uses</th><th>Expires</th><th>Auto-groups</th><th>Actions</th></>}>
        {keys.map((key) => <tr key={key.id}>
          <td><strong>{key.name}</strong></td>
          <td>{key.type}</td>
          <td><Status state={stateStatus(keyState(key))} label={keyState(key)} /></td>
          <td>{key.used_times ?? 0}{key.usage_limit ? ` / ${key.usage_limit}` : " / ∞"}</td>
          <td><Observed at={key.expires} /></td>
          <td>{(key.auto_groups ?? []).join(", ") || "—"}</td>
          <td><div className="actions">
            {!key.revoked && <button onClick={() => revoke(key)}>Revoke</button>}
            <button className="danger" onClick={() => remove(key)}>Delete</button>
          </div></td>
        </tr>)}
      </Rows>}

    <Dialog open={Boolean(draft) && !created} title="Create auth key" onClose={() => setDraft(undefined)}>
      <form onSubmit={(event) => { event.preventDefault(); void create(); }}>
        <label>Key name<input aria-label="Key name" placeholder="laptop-alice" value={draft?.name ?? ""} onChange={(event) => setDraft((current) => current && { ...current, name: event.target.value })} /></label>
        <label>Type<select aria-label="Key type" value={draft?.type ?? "one-off"} onChange={(event) => setDraft((current) => current && { ...current, type: event.target.value as SetupKeyDraft["type"], usage_limit: event.target.value === "one-off" ? 1 : 0 })}>
          <option value="one-off">One-off — a single machine</option>
          <option value="reusable">Reusable — many machines</option>
        </select></label>
        <label>Expires in<select aria-label="Expires in" value={draft?.expires_in ?? 86_400} onChange={(event) => setDraft((current) => current && { ...current, expires_in: Number(event.target.value) })}>{days.map(([label, seconds]) => <option key={seconds} value={seconds}>{label}</option>)}</select></label>
        {draft?.type === "reusable" && <label>Usage limit (0 for unlimited)<input aria-label="Usage limit (0 for unlimited)" type="number" min={0} value={draft.usage_limit} onChange={(event) => setDraft((current) => current && { ...current, usage_limit: Number(event.target.value) })} /></label>}
        <label>Auto-assign group IDs<input aria-label="Key auto-assign group IDs" placeholder="group-sre" value={(draft?.auto_groups ?? []).join(", ")} onChange={(event) => setDraft((current) => current && { ...current, auto_groups: idList(event.target.value) })} /></label>
        {/* An ephemeral peer is removed after it goes offline. Right for CI
            runners and autoscaled workloads, wrong for a laptop — which is why
            it is a deliberate checkbox rather than a property of the key type. */}
        <label><input type="checkbox" checked={draft?.ephemeral ?? false} onChange={(event) => setDraft((current) => current && { ...current, ephemeral: event.target.checked })} /> Ephemeral — remove the machine automatically once it goes offline</label>
        <div className="actions"><button type="button" onClick={() => setDraft(undefined)}>Cancel</button><button className="primary" type="submit">Issue auth key</button></div>
      </form>
    </Dialog>

    <Dialog open={Boolean(created)} title="Auth key issued" onClose={() => { setCreated(undefined); setDraft(undefined); }}>
      <p>Copy this key now. It will not be shown again.</p>
      <label>Auth key<input aria-label="Issued auth key" readOnly value={created?.key ?? ""} /></label>
      <p className="lede">Put it in <code>/etc/karst/karstd.toml</code> under <code>[control] setup_key</code> on the machine you are enrolling, then start <code>karstd</code>.</p>
      <div className="actions"><button className="primary" onClick={() => { setCreated(undefined); setDraft(undefined); }}>Done</button></div>
    </Dialog>
  </section>;
}
