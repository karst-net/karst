// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { useRef, useState } from "react";
import { Observed } from "@karst-net/ui";
import { api, ApiError } from "../api";
import { Failure, Notice, Rows, useResource } from "../common";

export function Bedrock() {
  const resource = useResource(api.bedrock);
  const nodes = useResource(api.nodes);
  const log = useResource(api.bedrockLog);
  const requests = useResource(api.bedrockRequests);
  const [message, setMessage] = useState<string>();
  const [acknowledged, setAcknowledged] = useState(false);
  const [override, setOverride] = useState<string[]>();
  const [exchanging, setExchanging] = useState(false);
  const responseInput = useRef<HTMLInputElement>(null);
  const bootstrapInput = useRef<HTMLInputElement>(null);

  const reloadSigningState = () => { requests.reload(); log.reload(); resource.reload(); nodes.reload(); };

  const exportRequest = async () => {
    setExchanging(true);
    try {
      const bundle = await api.exportBedrockRequest();
      const binary = atob(bundle.payload);
      const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
      const url = URL.createObjectURL(new Blob([bytes], { type: "application/json" }));
      const link = document.createElement("a");
      link.href = url;
      link.download = "bedrock-request.json";
      link.click();
      URL.revokeObjectURL(url);
      setMessage("Downloaded the offline signing request. Sign it with karst-bedrock, then import the response below.");
      reloadSigningState();
    } catch (error) { setMessage(`Could not export a signing request: ${(error as Error).message}`); }
    finally { setExchanging(false); }
  };

  const exportAuditAnchor = async () => {
    setExchanging(true);
    try {
      const bundle = await api.exportAuditAnchor();
      const binary = atob(bundle.payload);
      const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
      const url = URL.createObjectURL(new Blob([bytes], { type: "application/json" }));
      const link = document.createElement("a");
      link.href = url;
      link.download = "karst-audit-anchor-request.json";
      link.click();
      URL.revokeObjectURL(url);
      setMessage("Downloaded the audit-anchor request. Sign it with karst-bedrock, then import the response below.");
      reloadSigningState();
    } catch (error) { setMessage(`Could not export an audit-anchor request: ${(error as Error).message}`); }
    finally { setExchanging(false); }
  };

  const importResponse = async (file: File | undefined) => {
    if (!file) return;
    setExchanging(true);
    try {
      const bytes = new Uint8Array(await file.arrayBuffer());
      let binary = "";
      for (const byte of bytes) binary += String.fromCharCode(byte);
      await api.importBedrockResponse({ format: "bedrock-signed-bundle-v1", payload: btoa(binary) });
      setMessage("Signed response imported. The log and network-lock status have been refreshed.");
      reloadSigningState();
    } catch (error) { setMessage(`Could not import the signed response: ${(error as Error).message}`); }
    finally { setExchanging(false); }
  };

  const importBootstrap = async (file: File | undefined) => {
    if (!file) return;
    setExchanging(true);
    try {
      const bytes = new Uint8Array(await file.arrayBuffer());
      let binary = "";
      for (const byte of bytes) binary += String.fromCharCode(byte);
      await api.importBedrockBootstrap({ format: "bedrock-log-v1", payload: btoa(binary) });
      setMessage("Root-signed genesis imported. You can now export node-sign requests.");
      reloadSigningState();
    } catch (error) { setMessage(`Could not import the root-signed genesis: ${(error as Error).message}`); }
    finally { setExchanging(false); }
  };

  // The server decides who is cut off, from the signed Bedrock log, and PUT
  // /bedrock/mode requires the acknowledgement to equal that set exactly.
  // Deriving it here from liveness would be a different set and a certain 409:
  // a node can be healthy and online and still uncovered by the log.
  const handles = override ?? resource.value?.uncovered_handles ?? [];
  const named = handles.map((handle) => ({ handle, node: (nodes.value?.items ?? []).find((item) => item.handle === handle) }));

  const setMode = async (mode: "off" | "advisory" | "enforcing", success: string) => {
    try { await api.setBedrock(mode, handles); setMessage(success); setOverride(undefined); resource.reload(); log.reload(); }
    catch (error) {
      const required = error instanceof ApiError ? error.requiredCutOff : undefined;
      // The set moved between load and save — a node enrolled, or a signature
      // landed. Re-acknowledge against the new list rather than retrying.
      if (required) { setOverride(required); setAcknowledged(false); setMessage("The list of machines that would be cut off changed while you were reviewing it. Review the updated list and acknowledge it again."); return; }
      setMessage(`Network lock was not changed: ${(error as Error).message}`);
    }
  };

  if (resource.loading || nodes.loading) return <p>Loading network lock…</p>;
  if (resource.error) return <Failure message={resource.error} retry={resource.reload} />;
  const status = resource.value;

  return <section>
    <h2>Network lock</h2>
    <p>Current mode: <strong>{status?.mode}</strong> · quorum {status?.quorum} · {status?.covered_count} machine(s) covered by the signed log.</p>
    <p className="lede">Off: signatures are ignored. Advisory: unsigned machines are reported and still connect. Enforcing: unsigned machines are refused. A node’s own configuration is a floor — a node set to <code>enforcing</code> stays there whatever this says.</p>

    <h3>Acknowledge potential cut-off</h3>
    {named.length
      ? <ul>{named.map(({ handle, node }) => <li key={handle}>{node?.name ?? "Unknown machine"} — <code>{handle}</code>{node ? ` (${node.posture.status.replaceAll("_", " ")})` : " (not in this account's machine list)"}</li>)}</ul>
      : <p>No nodes are currently expected to be cut off.</p>}
    <p>Enforcing network lock may disconnect the machines above. Review this list before continuing.</p>
    <label><input type="checkbox" checked={acknowledged} onChange={(event) => setAcknowledged(event.target.checked)} /> I understand these machines may be cut off.</label>
    <div className="actions">
      <button className="danger" disabled={!acknowledged} onClick={() => void setMode("enforcing", "Network lock is enforcing.")}>Enable network lock</button>
      {/* Advisory and off cannot cut anyone off, so neither is gated on the
          acknowledgement — the server only requires it for enforcing. Gating
          them anyway would make the safe direction harder than the dangerous
          one, which is the wrong way round for an incident. */}
      <button disabled={status?.mode === "advisory"} onClick={() => void setMode("advisory", "Network lock is advisory. Unsigned machines are reported and still connect.")}>Set advisory</button>
      <button disabled={status?.mode === "off"} onClick={() => void setMode("off", "Network lock is off. Signatures are no longer enforced.")}>Turn off</button>
    </div>
    <Notice message={message} />

    <h3>Bootstrap network lock</h3>
    <p className="lede">Once, after the root quorum has created and signed the genesis log offline, import that one-entry bundle here. This action cannot replace an existing Bedrock history.</p>
    <div className="actions">
      <button disabled={exchanging} onClick={() => bootstrapInput.current?.click()}>Import root-signed genesis</button>
      <input ref={bootstrapInput} aria-label="Root-signed genesis bundle" type="file" accept="application/octet-stream,.bedrock" hidden onChange={(event) => void importBootstrap(event.target.files?.[0])} />
    </div>

    <h3>Pending signing requests</h3>
    <div className="actions">
      <button disabled={exchanging} onClick={() => void exportRequest()}>Create and export node-sign request</button>
      <button disabled={exchanging} onClick={() => void exportAuditAnchor()}>Create and export audit-anchor request</button>
      <button disabled={exchanging} onClick={() => responseInput.current?.click()}>Import signed response</button>
      <input ref={responseInput} aria-label="Signed Bedrock response bundle" type="file" accept="application/json" hidden onChange={(event) => void importResponse(event.target.files?.[0])} />
    </div>
    {requests.error ? <p>Signing requests are unavailable: {requests.error}</p>
      : (requests.value ?? []).length === 0 ? <p>Nothing is waiting for an authority signature.</p>
        : <Rows head={<><th>Request</th><th>Payload hash</th><th>Raised</th></>}>
          {(requests.value ?? []).map((item) => <tr key={item.id}>
            <td><code>{item.id}</code></td>
            <td><code>{item.payload_hash}</code></td>
            <td><Observed at={item.created_at} /></td>
          </tr>)}
        </Rows>}
    <p className="lede">Requests are signed offline with <code>karst-bedrock sign</code> on a machine that never touches this server, then imported. The console cannot sign; that is the point of it.</p>

    <h3>Signed log</h3>
    {log.error ? <p>The log is unavailable: {log.error}</p>
      : (log.value?.items ?? []).length === 0 ? <p>The log is empty. Nothing has been signed for this account yet.</p>
        : <Rows head={<><th>Sequence</th><th>Operation</th><th>Tier</th><th>Subject</th><th>Signed</th></>}>
          {(log.value?.items ?? []).map((entry) => <tr key={entry.sequence}>
            <td>{entry.sequence}</td>
            <td>{entry.op}</td>
            <td>{entry.tier}</td>
            <td><code>{entry.subject}</code></td>
            <td><Observed at={entry.signed_at} /></td>
          </tr>)}
        </Rows>}
  </section>;
}
