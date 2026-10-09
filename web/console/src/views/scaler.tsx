// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { EmptyState } from "@karst-net/ui";
import { api } from "../api";
import { Failure, Rows, useResource } from "../common";

export function Scaler() {
  const resource = useResource(api.scalerRecommendations);
  if (resource.loading) return <p>Loading Advisor recommendations…</p>;
  if (resource.error) return <Failure message={resource.error} retry={resource.reload} />;
  const data = resource.value;
  const pools = data?.recommendation.pools ?? [];

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
  </section>;
}
