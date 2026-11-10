// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { useState } from "react";
import { Dialog, EmptyState, Status } from "@karst-net/ui";
import type { RolloutComponent, RolloutPlan } from "@karst-net/api-client";
import { api, type RolloutComponentDraft } from "../api";
import { Failure, Notice, Rows, useMutation, usePolledResource } from "../common";
import { rolloutStatus } from "../rollout-status";

/** The single prod Nomad job's three Karst-authored task groups, in
 * ADR-0066's default apply order. Fixed in v1's own UI -- the API itself
 * accepts any contiguous sequence, but nothing in this account's single
 * deployment needs a different order yet. */
const componentOrder: Array<{ name: RolloutComponent["name"]; label: string }> = [
  { name: "control", label: "Control" },
  { name: "relay_job", label: "Estavelle (this job's task group)" },
  { name: "console", label: "Console" },
];

type Draft = { target_release: string; maintenance_window_note: string; byComponent: Record<string, { target_digest: string; verification_ref: string; requires_relay_lifecycle_schema: string; requires_gateway_ingress_schema: string }> };

function emptyDraft(): Draft {
  return {
    target_release: "", maintenance_window_note: "",
    byComponent: Object.fromEntries(componentOrder.map(c => [c.name, { target_digest: "", verification_ref: "", requires_relay_lifecycle_schema: "", requires_gateway_ingress_schema: "" }])),
  };
}

function toComponentDrafts(draft: Draft): RolloutComponentDraft[] {
  return componentOrder.map((component, sequence) => {
    const input = draft.byComponent[component.name];
    return {
      name: component.name, sequence,
      target_digest: input.target_digest.trim(), verification_ref: input.verification_ref.trim(),
      requires_relay_lifecycle_schema: input.requires_relay_lifecycle_schema.trim() ? Number(input.requires_relay_lifecycle_schema) : undefined,
      requires_gateway_ingress_schema: input.requires_gateway_ingress_schema.trim() ? Number(input.requires_gateway_ingress_schema) : undefined,
    };
  });
}

/** ADR-0066/#484: an admin-tracked, sequenced rollout plan for the single
 * prod Nomad job's control/estavelle/console task groups. Control computes and
 * tracks this plan -- including a live fleet-compatibility preview -- but
 * never calls Nomad, a registry, or cosign itself. The operator still runs
 * deploy/nomad/prod/README.md's documented steps by hand and marks each
 * component applied once they have. */
export function Rollouts() {
  const plans = usePolledResource(api.rollouts, 30_000);
  const { message, setMessage, run } = useMutation(plans.reload);
  const [creating, setCreating] = useState<Draft>();
  const [detail, setDetail] = useState<RolloutPlan>();
  const [overrideChecked, setOverrideChecked] = useState(false);
  const [reasonDrafts, setReasonDrafts] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);

  const openDetail = async (plan: RolloutPlan) => {
    setMessage(undefined);
    try { setDetail(await api.rollout(plan.id!)); } catch (error) { setMessage((error as Error).message); }
  };
  const refreshDetail = async () => { if (detail?.id) setDetail(await api.rollout(detail.id)); };

  const createPlan = async () => {
    if (!creating) return;
    setBusy(true); setMessage(undefined);
    try {
      const created = await api.createRollout({ target_release: creating.target_release.trim(), maintenance_window_note: creating.maintenance_window_note.trim() || undefined, components: toComponentDrafts(creating) });
      setCreating(undefined);
      plans.reload();
      setDetail(created);
      setMessage(`Rollout plan for ${created.target_release} saved. Review its compatibility preview before starting.`);
    } catch (error) { setMessage((error as Error).message); }
    finally { setBusy(false); }
  };

  const start = async () => {
    if (!detail?.id || detail.revision === undefined) return;
    const blocking = (detail.compatibility ?? []).some(c => c.blocking);
    if (blocking && !overrideChecked) { setMessage("Review the blocking compatibility rows and check the override before starting."); return; }
    setBusy(true);
    try {
      const updated = await api.startRollout(detail.id, detail.revision, true, blocking, detail.maintenance_window_note);
      setDetail(updated); plans.reload();
      setMessage(`Rollout for ${updated.target_release} started. Run the documented steps for ${componentOrder[0].label} first, then mark it applied.`);
    } catch (error) { setMessage((error as Error).message); }
    finally { setBusy(false); }
  };

  const markApplied = async (name: string) => {
    if (!detail?.id || detail.revision === undefined) return;
    setBusy(true);
    try {
      const updated = await api.markRolloutComponentApplied(detail.id, name, detail.revision);
      setDetail(updated); plans.reload();
      setMessage(updated.note || `${name} marked applied.`);
    } catch (error) { setMessage((error as Error).message); }
    finally { setBusy(false); }
  };

  const markFailed = async (name: string) => {
    if (!detail?.id || detail.revision === undefined) return;
    const reason = (reasonDrafts[name] ?? "").trim();
    if (!reason) { setMessage("A failure reason is required."); return; }
    setBusy(true);
    try {
      const updated = await api.markRolloutComponentFailed(detail.id, name, detail.revision, reason);
      setDetail(updated); plans.reload();
      setMessage(`${name} marked failed.`);
    } catch (error) { setMessage((error as Error).message); }
    finally { setBusy(false); }
  };

  const rollBack = async () => {
    if (!detail?.id || detail.revision === undefined) return;
    if (!confirm("Roll back this plan? This only records that you reverted the deployment by hand -- restore the previous verified digest and rerun the documented nomad steps yourself.")) return;
    void run(async () => { setDetail(await api.rollBackRollout(detail.id!, detail.revision!)); }, "Rollback recorded.");
  };

  const deletePlan = (plan: RolloutPlan) => {
    if (!plan.id || plan.revision === undefined) return;
    if (!confirm(`Abandon the ${plan.target_release} plan? It has not been started.`)) return;
    void run(() => api.deleteRollout(plan.id!, plan.revision!), "Plan removed.");
  };

  const nextPendingSequence = detail ? Math.min(...detail.components.filter(c => c.status === "pending").map(c => c.sequence), Infinity) : Infinity;

  return <section>
    <h3>Component rollout plans</h3>
    <p className="lede">ADR-0066: select a target release, review its fleet-compatibility preview, then run the documented <code>cosign</code>/<code>nomad</code> steps yourself and mark each component applied in sequence. Control tracks and gates this; it never executes the rollout itself.</p>
    <div className="actions"><button className="primary" onClick={() => { setMessage(undefined); setCreating(emptyDraft()); }}>New rollout plan</button><button onClick={plans.reload}>Refresh</button></div>
    {!detail && <Notice message={message} />}
    {plans.error && <Failure message={plans.error} retry={plans.reload} />}
    {!plans.error && (plans.value ?? []).length === 0
      ? <EmptyState title="No rollout plans">Create one to track a verified, sequenced update of control, estavelle and console.</EmptyState>
      : <Rows head={<><th>Target release</th><th>Status</th><th>Actions</th></>}>
        {(plans.value ?? []).map(plan => {
          const status = rolloutStatus(plan);
          return <tr key={plan.id}>
            <td>{plan.target_release}</td>
            <td><Status state={status.state} label={status.label} /></td>
            <td><button onClick={() => void openDetail(plan)}>Details</button>{plan.state === "planned" && <button className="danger" onClick={() => deletePlan(plan)}>Abandon</button>}</td>
          </tr>;
        })}
      </Rows>}

    <Dialog open={Boolean(detail)} title={`Rollout plan: ${detail?.target_release ?? ""}`} onClose={() => { if (!busy) setDetail(undefined); }}>
      {detail && <>
        <Notice message={message} />
        <p>Status: <Status state={rolloutStatus(detail).state} label={rolloutStatus(detail).label} /></p>
        {detail.maintenance_window_note && <p>Maintenance window: {detail.maintenance_window_note}</p>}

        <h4>Fleet compatibility preview</h4>
        {(detail.compatibility ?? []).length === 0
          ? <p className="lede">No component in this plan declares a required capability schema above the account's current baseline.</p>
          : <ul>{(detail.compatibility ?? []).map((c, i) => <li key={i}>
            <Status state={c.blocking ? "danger" : "healthy"} label={`${c.component}: ${c.capability} ${c.required}`} />{c.message && <> — {c.message}</>}
          </li>)}</ul>}
        {detail.state === "planned" && (detail.compatibility ?? []).some(c => c.blocking) &&
          <label><input type="checkbox" checked={overrideChecked} onChange={event => setOverrideChecked(event.target.checked)} />Proceed anyway — I will coordinate upgrading the listed agents during the maintenance window.</label>}

        <h4>Components (apply in order)</h4>
        <Rows head={<><th>Component</th><th>Target digest</th><th>Status</th><th>Actions</th></>}>
          {detail.components.map(component => <tr key={component.name}>
            <td>{componentOrder.find(c => c.name === component.name)?.label ?? component.name}</td>
            <td><code>{component.target_digest}</code></td>
            <td>{component.status}{component.failure_reason ? ` — ${component.failure_reason}` : ""}</td>
            <td>{detail.state === "in_progress" && component.status === "pending" && component.sequence === nextPendingSequence && <>
              <button disabled={busy} onClick={() => void markApplied(component.name)}>Mark applied</button>
              <input aria-label={`Failure reason for ${component.name}`} placeholder="Failure reason" value={reasonDrafts[component.name] ?? ""} onChange={event => setReasonDrafts(current => ({ ...current, [component.name]: event.target.value }))} />
              <button className="danger" disabled={busy} onClick={() => void markFailed(component.name)}>Mark failed</button>
            </>}</td>
          </tr>)}
        </Rows>
        <p className="lede">Run the documented <code>cosign verify</code> / <code>nomad job plan</code>/<code>run</code>/<code>status</code> steps for a component yourself before marking it applied — this dialog never runs them for you.</p>

        <div className="actions">
          {detail.state === "planned" && <button className="primary" disabled={busy} onClick={() => void start()}>Start rollout</button>}
          {(detail.state === "in_progress" || detail.state === "completed" || detail.state === "failed") && <button className="danger" disabled={busy} onClick={() => void rollBack()}>Roll back</button>}
          <button disabled={busy} onClick={async () => { await refreshDetail(); }}>Refresh</button>
          <button disabled={busy} onClick={() => setDetail(undefined)}>Close</button>
        </div>
      </>}
    </Dialog>

    <Dialog open={Boolean(creating)} title="New rollout plan" onClose={() => { if (!busy) setCreating(undefined); }}>
      {creating && <form onSubmit={event => { event.preventDefault(); void createPlan(); }}>
        <Notice message={message} />
        <label>Target release<input required value={creating.target_release} onChange={event => setCreating({ ...creating, target_release: event.target.value })} /></label>
        <label>Maintenance window (optional, advisory only)<input value={creating.maintenance_window_note} onChange={event => setCreating({ ...creating, maintenance_window_note: event.target.value })} /></label>
        {componentOrder.map(component => {
          const input = creating.byComponent[component.name];
          const setField = (field: keyof typeof input, value: string) => setCreating({ ...creating, byComponent: { ...creating.byComponent, [component.name]: { ...input, [field]: value } } });
          return <fieldset key={component.name}><legend>{component.label}</legend>
            <label>Target digest<input required placeholder="sha256:…" value={input.target_digest} onChange={event => setField("target_digest", event.target.value)} /></label>
            <label>Verification reference<input required placeholder="cosign verify output / timestamp" value={input.verification_ref} onChange={event => setField("verification_ref", event.target.value)} /></label>
            {component.name === "control" && <>
              <label>Requires Estavelle lifecycle schema (optional)<input type="number" min={0} value={input.requires_relay_lifecycle_schema} onChange={event => setField("requires_relay_lifecycle_schema", event.target.value)} /></label>
              <label>Requires Aven ingress schema (optional)<input type="number" min={0} value={input.requires_gateway_ingress_schema} onChange={event => setField("requires_gateway_ingress_schema", event.target.value)} /></label>
            </>}
          </fieldset>;
        })}
        <div className="actions"><button type="button" disabled={busy} onClick={() => setCreating(undefined)}>Cancel</button><button className="primary" type="submit" disabled={busy}>Save plan</button></div>
      </form>}
    </Dialog>
  </section>;
}
