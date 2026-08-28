// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

export function sessionsCsv(rows: Array<{ node_handle: string; peer_handle: string; status: string; suite?: string | null; psk_epoch?: number | null; observed_at: string }>) {
  const quote = (value: unknown) => `"${String(value ?? "").replaceAll('"', '""')}"`;
  return [["node", "peer", "status", "suite", "PSK epoch", "observed at"], ...rows.map((row) => [row.node_handle, row.peer_handle, row.status, row.suite, row.psk_epoch, row.observed_at])].map((row) => row.map(quote).join(",")).join("\n");
}
