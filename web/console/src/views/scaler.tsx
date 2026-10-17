// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { useState } from "react";
import { Dialog, EmptyState } from "@karst-net/ui";
import type { AllowedRegion } from "@karst-net/api-client";
import { api } from "../api";
import { Failure, Notice, Rows, useMutation, useResource } from "../common";

type Draft = { provider: string; region: string };
const blank: Draft = { provider: "", region: "" };

export function Scaler() {
  const resource = useResource(api.scalerRecommendations);
  const regions = useResource(api.allowedRegions);
  const { message, setMessage, run } = useMutation(regions.reload);
  const [draft, setDraft] = useState<Draft>();

  if (resource.loading) return <p>Loading Advisor recommendations…</p>;
  if (resource.error) return <Failure message={resource.error} retry={resource.reload} />;
  const data = resource.value;
  const pools = data?.recommendation.pools ?? [];

  const add = async () => {
    if (!draft) return;
    const provider = draft.provider.trim(), region = draft.region.trim();
    if (!provider || !region) { setMessage("Both provider and region are required."); return; }
    const entry = { provider, region };
    if (await run(() => api.addAllowedRegion(entry), `${provider}/${region} was added to the region allowlist.`)) setDraft(undefined);
  };
  const remove = (entry: AllowedRegion) => {
    if (!confirm(`Revoke ${entry.provider}/${entry.region} from the region allowlist?`)) return;
    void run(() => api.removeAllowedRegion(entry.provider, entry.region), `${entry.provider}/${entry.region} was revoked.`);
  };

  return <section>
    <h2>Scaler Advisor</h2>
    <p className="lede">ADR-0045 §7 Phase 1: the Advisor's recommended node count per pool this tick, compared against each pool's own configured floor. Read-only — nothing here actuates a change.</p>
    {pools.length === 0
      ? <EmptyState title="No recommendation yet">karst-scaler advise has not produced a recommendation for any pool.</EmptyState>
      : <Rows head={<><th>Pool</th><th>Recommended</th><th>Configured</th><th>Cost delta</th><th>Binding constraint</th></>}>
        {pools.map((pool) => <tr key={pool.pool_id}>
          <td><code>{pool.pool_id}</code></td>
          <td>{pool.desired_nodes}</td>
          <td>{data?.configured_nodes[pool.pool_id] ?? "—"}</td>
          <td>{pool.cost_delta > 0 ? "+" : ""}{pool.cost_delta.toFixed(2)}</td>
          <td>{pool.binding_constraint}</td>
        </tr>)}
      </Rows>}

    <h3>Allowed regions</h3>
    <p className="lede">ADR-0045 §4c's deployment-wide region allowlist: what gets projected into every node's netmap, and which §4b anchor-RTT demand reports are recorded rather than dropped. <strong>This is not the same list karst-scaler's own driver reads to decide where it may actually provision capacity</strong> — that list lives in a separate, operator-maintained file on the scaler host, deliberately kept out of the control plane's trust domain (ADR-0045 §6: the control plane must never gain cloud-account credentials). Adding a region here does not by itself authorize any new spend there.</p>
    {regions.loading ? <p>Loading allowed regions…</p>
      : regions.error ? <Failure message={regions.error} retry={regions.reload} />
      : <>
        <div className="actions"><button className="primary" onClick={() => setDraft(blank)}>Allow a region</button></div>
        <Notice message={message} />
        {(regions.value ?? []).length === 0
          ? <EmptyState title="No regions allowed">A deployment with an empty allowlist projects none to any node — §4c's fail-closed default.</EmptyState>
          : <Rows head={<><th>Provider</th><th>Region</th><th>Actions</th></>}>
            {(regions.value ?? []).map((entry) => <tr key={`${entry.provider}/${entry.region}`}>
              <td>{entry.provider}</td>
              <td><code>{entry.region}</code></td>
              <td><button className="danger" onClick={() => remove(entry)}>Revoke</button></td>
            </tr>)}
          </Rows>}
      </>}

    <Dialog open={Boolean(draft)} title="Allow a region" onClose={() => setDraft(undefined)}>
      <form onSubmit={(event) => { event.preventDefault(); void add(); }}>
        <label>Provider<input aria-label="Region provider" placeholder="aws" value={draft?.provider ?? ""} onChange={(event) => setDraft((current) => current && { ...current, provider: event.target.value })} /></label>
        <label>Region<input aria-label="Region code" placeholder="us-east-1" value={draft?.region ?? ""} onChange={(event) => setDraft((current) => current && { ...current, region: event.target.value })} /></label>
        <p className="lede">Both are free text — not validated against any fixed list of providers or regions. An AWS local zone code (e.g. "us-east-1-bos-1a") is just another region string here, same as any other.</p>
        <div className="actions"><button type="button" onClick={() => setDraft(undefined)}>Cancel</button><button className="primary" type="submit">Allow region</button></div>
      </form>
    </Dialog>
  </section>;
}
