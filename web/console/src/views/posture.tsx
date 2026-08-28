// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { useMemo, useState } from "react";
import type { SessionPosture } from "@karst-net/api-client";
import { Observed, Status } from "@karst-net/ui";
import { api } from "../api";
import { sessionsCsv } from "../csv";
import { filterSessions } from "../posture";
import { Failure, Rows, statusFor, useResource } from "../common";

export function Posture() {
  const aggregate = useResource(api.posture);
  const sessions = useResource(api.sessions);
  const [filter, setFilter] = useState("exceptions");
  const rows = useMemo(() => filterSessions(sessions.value?.items ?? [], filter), [sessions.value, filter]);
  const download = () => {
    const blob = new Blob([sessionsCsv(rows)], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const link = Object.assign(document.createElement("a"), { href: url, download: "karst-crypto-posture.csv" });
    link.click();
    URL.revokeObjectURL(url);
  };
  if (aggregate.loading || sessions.loading) return <p>Loading crypto posture…</p>;
  if (aggregate.error || sessions.error) return <Failure message={aggregate.error ?? sessions.error ?? "Unknown error"} retry={() => { aggregate.reload(); sessions.reload(); }} />;
  const value = aggregate.value;
  return <section>
    <h2>Crypto posture</h2>
    <p className="headline"><strong>{value?.pq_covered_sessions} of {value?.eligible_sessions} eligible sessions PQ-covered</strong><br /><Observed at={value?.as_of} /> · {value?.stale_nodes} nodes have not reported in this window.</p>
    <label htmlFor="session-filter">Show</label> <select id="session-filter" value={filter} onChange={(event) => setFilter(event.target.value)}>
      <option value="exceptions">Exceptions only</option>
      <option value="all">All sessions</option>
      <option value="lattice_only">Lattice-only sessions</option>
      <option value="stale">Stale sessions</option>
      <option value="pq">PQ-covered sessions</option>
    </select> <button onClick={download}>Export CSV</button>
    <Rows head={<><th>Node</th><th>Peer</th><th>Posture</th><th>Negotiated suite</th><th>PSK epoch</th><th>As of</th></>}>
      {rows.map((row: SessionPosture, index: number) => <tr key={`${row.node_handle}-${index}`}>
        <td><code>{row.node_handle}</code></td>
        <td><code>{row.peer_handle}</code></td>
        <td><Status state={statusFor(row.status)} label={row.status.replaceAll("_", " ")} /></td>
        <td>{row.suite ?? "Not reported"}</td>
        <td>{row.psk_epoch ?? "—"}</td>
        <td><Observed at={row.observed_at} /></td>
      </tr>)}
    </Rows>
  </section>;
}
