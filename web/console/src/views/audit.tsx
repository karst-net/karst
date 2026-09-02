// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { useState } from "react";
import { Dialog, EmptyState, Observed, Status } from "@karst-net/ui";
import { api } from "../api";
import { Failure, Notice, Rows, useResource } from "../common";

export function Audit() {
  const [filters, setFilters] = useState<{ actor: string; action: string }>({ actor: "", action: "" });
  const [applied, setApplied] = useState<{ actor: string; action: string }>({ actor: "", action: "" });
  const resource = useResource(() => api.audit({ actor: applied.actor || undefined, action: applied.action || undefined }), [applied]);
  const [message, setMessage] = useState<string>();
  const [verified, setVerified] = useState<Awaited<ReturnType<typeof api.auditVerify>>>();
  const [sink, setSink] = useState<{ kind: string; endpoint: string }>();

  if (resource.loading) return <p>Loading audit log…</p>;
  if (resource.error) return <Failure message={resource.error} retry={resource.reload} />;
  const entries = resource.value?.items ?? [];

  const verify = async () => {
    try {
      const result = await api.auditVerify();
      setVerified(result);
      setMessage(result.valid ? `Chain verified to sequence ${result.head.sequence}.` : `Chain verification FAILED at sequence ${result.first_bad_sequence}. Treat every entry after it as untrusted and preserve the database before doing anything else.`);
    } catch (error) { setMessage((error as Error).message); }
  };
  const exportLog = async (format: "json" | "csv") => {
    try {
      const isJSON = format === "json";
      const exported = isJSON ? JSON.stringify(await api.auditExport("json"), null, 2) : await api.auditExport("csv");
      const blob = new Blob([exported], { type: isJSON ? "application/json" : "text/csv" });
      const url = URL.createObjectURL(blob);
      const link = Object.assign(document.createElement("a"), { href: url, download: `karst-audit-log.${format}` });
      link.click();
      URL.revokeObjectURL(url);
      setMessage(`Exported audit entries as ${format.toUpperCase()}, hashes included.`);
    } catch (error) { setMessage((error as Error).message); }
  };
  const addSink = async () => {
    if (!sink) return;
    try { await api.addAuditSink(sink.kind, sink.endpoint.trim()); setMessage(`Audit events will be forwarded to ${sink.endpoint}.`); setSink(undefined); }
    catch (error) { setMessage((error as Error).message); }
  };

  return <section>
    <h2>Audit log</h2>
    <p className="lede">Append-only and hash-chained. Entries cannot be edited here — that is what makes the chain worth verifying. {resource.value?.anchor.last_anchored_sequence == null ? "This audit log has not yet been Bedrock-anchored." : `${resource.value.anchor.entries_since_anchor} entries have accrued since Bedrock anchored sequence ${resource.value.anchor.last_anchored_sequence}.`}</p>
    {resource.value?.anchor.contradicts_anchor && <p>
      <Status state="danger" label="audit log contradicts its Bedrock anchor" />
      {" "}This log no longer matches the head an authority signed into the Bedrock chain (ADR-0016) — the server has truncated or rewritten history since. Preserve the database and investigate before trusting anything in it.
    </p>}
    <div className="actions">
      <label>Actor<input aria-label="Filter by actor" placeholder="user-sre" value={filters.actor} onChange={(event) => setFilters({ ...filters, actor: event.target.value })} /></label>
      <label>Action<input aria-label="Filter by action" placeholder="policy.write" value={filters.action} onChange={(event) => setFilters({ ...filters, action: event.target.value })} /></label>
      <button onClick={() => setApplied(filters)}>Apply filters</button>
      <button onClick={() => { setFilters({ actor: "", action: "" }); setApplied({ actor: "", action: "" }); }}>Clear</button>
      <button onClick={() => void verify()}>Verify chain</button>
      <button onClick={() => void exportLog("json")}>Export JSON</button>
      <button onClick={() => void exportLog("csv")}>Export CSV</button>
      <button onClick={() => setSink({ kind: "webhook", endpoint: "" })}>Add SIEM sink</button>
    </div>
    <Notice message={message} />
    {verified && <p><Status state={verified.valid ? "healthy" : "danger"} label={verified.valid ? `chain intact to ${verified.head.sequence}` : `chain broken at ${verified.first_bad_sequence}`} /></p>}
    {entries.length
      ? <Rows head={<><th>Time</th><th>Actor</th><th>Action</th><th>Target</th><th>Detail</th></>}>
        {entries.map((entry) => <tr key={entry.sequence}>
          <td><Observed at={entry.created_at} /></td>
          <td>{entry.actor}</td>
          <td>{entry.action}</td>
          <td><code>{entry.target}</code></td>
          <td>{entry.detail ?? "—"}</td>
        </tr>)}
      </Rows>
      : <EmptyState title="No audit events">Administrative events will appear here as changes are made.</EmptyState>}

    <Dialog open={Boolean(sink)} title="Add SIEM sink" onClose={() => setSink(undefined)}>
      <form onSubmit={(event) => { event.preventDefault(); void addSink(); }}>
        <label>Kind<select aria-label="Sink kind" value={sink?.kind ?? "webhook"} onChange={(event) => setSink((current) => current && { ...current, kind: event.target.value })}><option value="webhook">Webhook</option><option value="syslog">Syslog</option></select></label>
        <label>Endpoint<input aria-label="Sink endpoint" placeholder="https://siem.example.test/ingest" value={sink?.endpoint ?? ""} onChange={(event) => setSink((current) => current && { ...current, endpoint: event.target.value })} /></label>
        <p className="lede">Forwarding is a copy, not a move. The chain here stays authoritative, because a sink you cannot verify cannot be the record of record.</p>
        <div className="actions"><button type="button" onClick={() => setSink(undefined)}>Cancel</button><button className="primary" type="submit">Add sink</button></div>
      </form>
    </Dialog>
  </section>;
}
