// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { useEffect, useMemo, useState } from "react";
import type { Node } from "@karst-net/api-client";
import { Dialog, EmptyState, Observed, Status, type StatusState } from "@karst-net/ui";
import { api, type MeshDomain } from "../api";
import { Failure, formatBytes, Notice, Rows, statusFor, useMutation, useResource } from "../common";

type Paths = Awaited<ReturnType<typeof api.nodePaths>>;

// Exhaustive — a new path kind must be given a tier here rather than fall
// through as a warning by accident.
const PATH_STATUS: Record<Paths["paths"][number]["kind"], StatusState> = {
  direct: "healthy",
  relay: "warning",
  turn: "warning",
  unreachable: "warning",
};

export function Machines() {
  const resource = useResource(api.nodes);
  const { message, setMessage, run } = useMutation(resource.reload);
  const [filter, setFilter] = useState("");
  const [renaming, setRenaming] = useState<{ node: Node; name: string }>();
  const [moving, setMoving] = useState<{ node: Node; domainId: string }>();
  const [paths, setPaths] = useState<{ node: Node; value?: Paths; error?: string }>();
  const [domains, setDomains] = useState<MeshDomain[]>([]);
  useEffect(() => {
    let active = true;
    // Best-effort, same posture as setup.tsx's picker: an account-wide
    // Domains grant isn't required to use this page at all, so a refusal
    // here just means the "Domain" column reads "Account root" for
    // everything and the move dialog offers no domain to move into.
    api.domains().then((list) => { if (active) setDomains(list); }).catch(() => { /* column stays root-only */ });
    return () => { active = false; };
  }, []);
  const domainPath = (domainId?: string) => domains.find((d) => d.id === domainId)?.path;

  const nodes = resource.value?.items ?? [];
  const shown = useMemo(() => {
    const needle = filter.trim().toLowerCase();
    if (!needle) return nodes;
    return nodes.filter((node) => [node.name, node.handle, node.user_id, ...node.tags].some((field) => field?.toLowerCase().includes(needle)));
  }, [nodes, filter]);

  if (resource.loading) return <p>Loading machines…</p>;
  if (resource.error) return <Failure message={resource.error} retry={resource.reload} />;

  const deprovision = (node: Node) => {
    if (!confirm(`Deprovision ${node.name}? Its node keys will expire and sessions will be dropped.`)) return;
    void run(() => api.deprovision(node.handle), `${node.name} was deprovisioned.`);
  };
  const rename = async () => {
    if (!renaming) return;
    const name = renaming.name.trim();
    if (!name) { setMessage("A machine needs a name."); return; }
    if (await run(() => api.renameNode(renaming.node.handle, name), `${renaming.node.name} is now named ${name}.`)) setRenaming(undefined);
  };
  const move = async () => {
    if (!moving) return;
    const label = domainPath(moving.domainId) ?? "the account root";
    if (await run(() => api.setNodeDomain(moving.node.handle, moving.domainId), `${moving.node.name} is now in ${label}.`)) setMoving(undefined);
  };
  const showPaths = async (node: Node) => {
    setPaths({ node });
    try { setPaths({ node, value: await api.nodePaths(node.handle) }); }
    catch (error) { setPaths({ node, error: (error as Error).message }); }
  };
  return <section>
    <h2>Machines</h2>
    <p className="lede">Connection state always includes its last observation time. Add a device by creating an enrollment invitation.</p>
    <div className="actions">
      <button className="primary" onClick={() => { location.hash = "/setup"; }}>Add machine</button>
      <label>Filter<input aria-label="Filter machines" placeholder="name, handle, owner or tag" value={filter} onChange={(event) => setFilter(event.target.value)} /></label>
    </div>
    <Notice message={message} />
    {nodes.length === 0
      ? <EmptyState title="No machines yet">Create an invitation, then install Karst and paste it into setup on the device.</EmptyState>
      : shown.length === 0
        ? <EmptyState title="No machines match that filter">Clear the filter to see all {nodes.length} machines.</EmptyState>
        : <Rows head={<><th>Name</th><th>Domain</th><th>Owner</th><th>Tags</th><th>Crypto posture</th><th>Observed</th><th>Actions</th></>}>
          {shown.map((node) => <tr key={node.handle}>
            <td><strong>{node.name}</strong><br /><code>{node.dns_label}</code></td>
            <td>{domainPath(node.domain_id) ?? (node.domain_id ? <span className="lede">Unknown domain</span> : <span className="lede">Account root</span>)}</td>
            <td>{node.user_id}</td>
            <td>{node.tags.join(", ") || "—"}</td>
            <td><Status state={statusFor(node.posture.status)} label={node.posture.status.replaceAll("_", " ")} /></td>
            <td><Observed at={node.last_seen_at} /></td>
            <td><div className="actions">
              <button onClick={() => setRenaming({ node, name: node.name })}>Rename</button>
              <button onClick={() => setMoving({ node, domainId: node.domain_id ?? "" })}>Move</button>
              <button onClick={() => void showPaths(node)}>Paths</button>
              <button className="danger" onClick={() => deprovision(node)}>Deprovision</button>
            </div></td>
          </tr>)}
        </Rows>}
    <p className="lede">Tags, expiry and the enabled flag are set by the coordination server and are not editable here — the contract accepts a name and a domain and nothing else on a node, so a form offering the rest would fail on save.</p>

    <Dialog open={Boolean(renaming)} title="Rename machine" onClose={() => setRenaming(undefined)}>
      <form onSubmit={(event) => { event.preventDefault(); void rename(); }}>
        <label>Machine name<input aria-label="Machine name" value={renaming?.name ?? ""} onChange={(event) => setRenaming((current) => current && { ...current, name: event.target.value })} /></label>
        <p className="lede">The handle <code>{renaming?.node.handle}</code> is derived from the node’s identity key and never changes.</p>
        <div className="actions"><button type="button" onClick={() => setRenaming(undefined)}>Cancel</button><button className="primary" type="submit">Save name</button></div>
      </form>
    </Dialog>

    <Dialog open={Boolean(moving)} title="Move machine" onClose={() => setMoving(undefined)}>
      <form onSubmit={(event) => { event.preventDefault(); void move(); }}>
        <label>Domain<select aria-label="Domain" value={moving?.domainId ?? ""} onChange={(event) => setMoving((current) => current && { ...current, domainId: event.target.value })}>
          <option value="">Account root (no domain)</option>
          {domains.map((domain) => <option key={domain.id} value={domain.id}>{domain.path}</option>)}
        </select></label>
        <p className="lede">{moving && (() => {
          const target = domainPath(moving.domainId);
          const qualified = target ? `${moving.node.name}.${target}` : moving.node.name;
          return <>Moving changes how this machine resolves on the mesh: it will become reachable as <code>{qualified}</code>. This is not a network change on the device itself, only where it is named.</>;
        })()}</p>
        <div className="actions"><button type="button" onClick={() => setMoving(undefined)}>Cancel</button><button className="primary" type="submit">Move</button></div>
      </form>
    </Dialog>

    <Dialog open={Boolean(paths)} title={`Paths — ${paths?.node.name ?? ""}`} onClose={() => setPaths(undefined)}>
      {paths?.error ? <p role="alert">{paths.error}</p> : !paths?.value ? <p>Loading paths…</p> : paths.value.paths.length === 0
        ? <p>No paths observed. The machine has not reached another peer in this window.</p>
        : <Rows head={<><th>Peer</th><th>Kind</th><th>Endpoint</th><th>Sent</th><th>Received</th><th>Observed</th></>}>
          {paths.value.paths.map((path, index) => <tr key={index}>
            <td><code>{path.peer_handle}</code></td>
            <td><Status state={PATH_STATUS[path.kind]} label={path.kind} /></td>
            <td>{path.endpoint ? <code>{path.endpoint}</code> : path.relay_id ? <>via relay <code>{path.relay_id}</code></> : "—"}</td>
            <td>{formatBytes(path.tx_bytes)}</td>
            <td>{formatBytes(path.rx_bytes)}</td>
            <td><Observed at={path.observed_at} /></td>
          </tr>)}
        </Rows>}
      <p className="lede">Sent/received are running totals for this session, as this machine last reported them — not a live rate.</p>
      <div className="actions"><button onClick={() => setPaths(undefined)}>Close</button></div>
    </Dialog>

  </section>;
}
