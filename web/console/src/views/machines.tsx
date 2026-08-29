// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { useMemo, useState } from "react";
import type { Node } from "@karst-net/api-client";
import { Dialog, EmptyState, Observed, Status } from "@karst-net/ui";
import { api } from "../api";
import { Failure, Notice, Rows, statusFor, useMutation, useResource } from "../common";

type Paths = Awaited<ReturnType<typeof api.nodePaths>>;

export function Machines() {
  const resource = useResource(api.nodes);
  const { message, setMessage, run } = useMutation(resource.reload);
  const [filter, setFilter] = useState("");
  const [renaming, setRenaming] = useState<{ node: Node; name: string }>();
  const [paths, setPaths] = useState<{ node: Node; value?: Paths; error?: string }>();
  const [enrollment, setEnrollment] = useState<{ name: string; key?: string }>();

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
  const showPaths = async (node: Node) => {
    setPaths({ node });
    try { setPaths({ node, value: await api.nodePaths(node.handle) }); }
    catch (error) { setPaths({ node, error: (error as Error).message }); }
  };
  // A machine is not created here and cannot be: it enrolls itself with a key.
  // The honest "add" flow is therefore to mint the key and hand over the
  // command, rather than a form that pretends the server can conjure a node.
  const mintEnrollmentKey = async () => {
    const name = enrollment?.name.trim() || "New machine";
    try {
      const created = await api.createSetupKey({ name, type: "one-off", expires_in: 86_400, usage_limit: 1, auto_groups: [], ephemeral: false });
      setEnrollment({ name, key: created.key });
      setMessage(`Auth key issued for ${name}. It is single-use and expires in 24 hours.`);
    } catch (error) { setMessage((error as Error).message); }
  };

  return <section>
    <h2>Machines</h2>
    <p className="lede">Connection state always includes its last observation time. A machine joins by enrolling with an auth key; it is never created here.</p>
    <div className="actions">
      <button className="primary" onClick={() => setEnrollment({ name: "" })}>Add machine</button>
      <label>Filter<input aria-label="Filter machines" placeholder="name, handle, owner or tag" value={filter} onChange={(event) => setFilter(event.target.value)} /></label>
    </div>
    <Notice message={message} />
    {nodes.length === 0
      ? <EmptyState title="No machines yet">Create an auth key, install Karst on a node, and enroll it to see it here.</EmptyState>
      : shown.length === 0
        ? <EmptyState title="No machines match that filter">Clear the filter to see all {nodes.length} machines.</EmptyState>
        : <Rows head={<><th>Name</th><th>Owner</th><th>Tags</th><th>Crypto posture</th><th>Observed</th><th>Actions</th></>}>
          {shown.map((node) => <tr key={node.handle}>
            <td><strong>{node.name}</strong><br /><code>{node.handle}</code></td>
            <td>{node.user_id}</td>
            <td>{node.tags.join(", ") || "—"}</td>
            <td><Status state={statusFor(node.posture.status)} label={node.posture.status.replaceAll("_", " ")} /></td>
            <td><Observed at={node.last_seen_at} /></td>
            <td><div className="actions">
              <button onClick={() => setRenaming({ node, name: node.name })}>Rename</button>
              <button onClick={() => void showPaths(node)}>Paths</button>
              <button className="danger" onClick={() => deprovision(node)}>Deprovision</button>
            </div></td>
          </tr>)}
        </Rows>}
    <p className="lede">Tags, expiry and the enabled flag are set by the coordination server and are not editable here — the contract accepts a name and nothing else on a node, so a form offering the rest would fail on save.</p>

    <Dialog open={Boolean(renaming)} title="Rename machine" onClose={() => setRenaming(undefined)}>
      <form onSubmit={(event) => { event.preventDefault(); void rename(); }}>
        <label>Machine name<input aria-label="Machine name" value={renaming?.name ?? ""} onChange={(event) => setRenaming((current) => current && { ...current, name: event.target.value })} /></label>
        <p className="lede">The handle <code>{renaming?.node.handle}</code> is derived from the node’s identity key and never changes.</p>
        <div className="actions"><button type="button" onClick={() => setRenaming(undefined)}>Cancel</button><button className="primary" type="submit">Save name</button></div>
      </form>
    </Dialog>

    <Dialog open={Boolean(paths)} title={`Paths — ${paths?.node.name ?? ""}`} onClose={() => setPaths(undefined)}>
      {paths?.error ? <p role="alert">{paths.error}</p> : !paths?.value ? <p>Loading paths…</p> : paths.value.paths.length === 0
        ? <p>No paths observed. The machine has not reached another peer in this window.</p>
        : <Rows head={<><th>Peer</th><th>Kind</th><th>Endpoint</th><th>Observed</th></>}>
          {paths.value.paths.map((path, index) => <tr key={index}>
            <td><code>{path.peer_handle}</code></td>
            <td><Status state={path.kind === "direct" ? "healthy" : "warning"} label={path.kind} /></td>
            <td>{path.endpoint ? <code>{path.endpoint}</code> : path.relay_id ? <>via relay <code>{path.relay_id}</code></> : "—"}</td>
            <td><Observed at={path.observed_at} /></td>
          </tr>)}
        </Rows>}
      <div className="actions"><button onClick={() => setPaths(undefined)}>Close</button></div>
    </Dialog>

    <Dialog open={Boolean(enrollment)} title="Add a machine" onClose={() => { setEnrollment(undefined); resource.reload(); }}>
      {enrollment?.key
        ? <>
          <p>Run this on the machine you are adding. The key is single-use and is not shown again.</p>
          <label>Enrollment key<input aria-label="Enrollment key" readOnly value={enrollment.key} /></label>
          <p className="lede">Put it in <code>/etc/karst/karstd.toml</code> under <code>[control] setup_key</code>, then start <code>karstd</code>. The machine appears in this list once it has enrolled.</p>
        </>
        : <form onSubmit={(event) => { event.preventDefault(); void mintEnrollmentKey(); }}>
          <p>Issues a single-use auth key valid for 24 hours. Name it for the machine it is meant for, so an unused key can be recognized later.</p>
          <label>Machine name<input aria-label="New machine name" placeholder="laptop-alice" value={enrollment?.name ?? ""} onChange={(event) => setEnrollment({ name: event.target.value })} /></label>
          <div className="actions"><button type="button" onClick={() => setEnrollment(undefined)}>Cancel</button><button className="primary" type="submit">Issue auth key</button></div>
        </form>}
      {enrollment?.key && <div className="actions"><button onClick={() => { setEnrollment(undefined); resource.reload(); }}>Done</button></div>}
    </Dialog>
  </section>;
}
