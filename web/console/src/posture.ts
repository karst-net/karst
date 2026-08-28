// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import type { SessionPosture } from "@karst-net/api-client";

/**
 * Worst first. An auditor's question is "show me what is not compliant"
 * (§5.2), so severity — not handle order — decides what is at the top of the
 * table. `pq` sorts last because a compliant session is the least interesting
 * row on a view whose job is to surface the others.
 */
const severity: Record<SessionPosture["status"], number> = { stale: 0, unknown: 1, lattice_only: 2, pq: 3 };

/** Every status that is not a covered, currently-reported session. */
export const isException = (row: SessionPosture) => row.status !== "pq";

/**
 * "exceptions" is the default the view opens on and is deliberately the union
 * of every non-compliant category, not one of them: defaulting to
 * lattice-only alone hides stale sessions, which are also exceptions, behind a
 * filter the auditor would have to know to construct.
 */
export function filterSessions(rows: SessionPosture[], filter: string) {
  const matching = filter === "all" ? rows : filter === "exceptions" ? rows.filter(isException) : rows.filter((row) => row.status === filter);
  return [...matching].sort((a, b) => severity[a.status] - severity[b.status]);
}
