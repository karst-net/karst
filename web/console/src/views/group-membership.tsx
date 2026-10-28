// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { useEffect, useState } from "react";
import { Dialog } from "@karst-net/ui";
import { api, ApiError, type GroupSnapshot } from "../api";
import { loadGroupDependencies, type GroupDependencyReview } from "../group-dependencies";

export function GroupMembership({ id, onClose, onSaved }: { id: string; onClose: () => void; onSaved: () => void }) {
  const [snapshot, setSnapshot] = useState<GroupSnapshot>();
  const [machines, setMachines] = useState<Array<{ id: string; name: string }>>([]);
  const [selected, setSelected] = useState<string[]>([]);
  const [impact, setImpact] = useState<GroupDependencyReview>();
  const [reviewing, setReviewing] = useState(false);
  const [acknowledged, setAcknowledged] = useState(false);
  const [busy, setBusy] = useState(true);
  const [conflicted, setConflicted] = useState(false);
  const [error, setError] = useState<string>();
  const reload = async () => {
    setBusy(true); setError(undefined); setConflicted(false); setReviewing(false); setAcknowledged(false); setSnapshot(undefined);
    try {
      const [current, available] = await Promise.all([api.groupForEdit(id), api.groupPeers()]);
      setSnapshot(current); setMachines(available); setSelected(current.group.peers?.map(peer => peer.id) ?? []);
    } catch (error) { setError((error as Error).message); }
    finally { setBusy(false); }
  };
  useEffect(() => { void reload(); }, [id]);
  const currentRevision = async () => {
    if ((await api.groupForEdit(id)).revision !== snapshot?.revision) {
      setConflicted(true); setAcknowledged(false); throw new Error("This group changed since you opened it. Reload the latest group and review your changes again.");
    }
  };
  const review = async () => {
    setBusy(true); setError(undefined);
    try { await currentRevision(); setImpact(await loadGroupDependencies(id)); setReviewing(true); setAcknowledged(false); }
    catch (error) { setError((error as Error).message); }
    finally { setBusy(false); }
  };
  const save = async () => {
    if (!snapshot || !impact || !acknowledged || conflicted) return;
    setBusy(true); setError(undefined);
    try {
      await currentRevision();
      const current = await loadGroupDependencies(id);
      if (current.fingerprint !== impact.fingerprint) {
        setImpact(current); setAcknowledged(false); setError("The group's assignments changed. Review the updated impact before applying."); return;
      }
      await api.setGroupMembers(snapshot, selected); onSaved();
    } catch (error) {
      if (error instanceof ApiError && error.status === 412) setConflicted(true);
      setAcknowledged(false); setError((error as Error).message);
    } finally { setBusy(false); }
  };
  const original = snapshot?.group.peers?.map(peer => peer.id) ?? [];
  const added = selected.filter(id => !original.includes(id));
  const removed = original.filter(id => !selected.includes(id));
  const name = (id: string) => machines.find(machine => machine.id === id)?.name ?? snapshot?.group.peers?.find(machine => machine.id === id)?.name ?? "Unavailable machine";
  const editable = snapshot && (snapshot.group.issued ?? "api") === "api" && snapshot.group.name !== "All";
  return <Dialog open title={snapshot ? `Members of ${snapshot.group.name}` : "Group membership"} onClose={() => { if (!busy) onClose(); }}>
    {busy && <p>Loading group information…</p>}
    {error && <p role="alert">{error}</p>}
    {snapshot && !editable && <p>This group is built in or managed by an identity provider. Edit its membership at its source.</p>}
    {snapshot && editable && (!reviewing ? <>
      <p>Select machines, then review how their group access will change.</p>
      <fieldset disabled={busy || conflicted}><legend>Machines</legend>{machines.map(machine => <label key={machine.id}><input type="checkbox" checked={selected.includes(machine.id)} onChange={event => setSelected(event.target.checked ? [...selected, machine.id] : selected.filter(id => id !== machine.id))} />{machine.name}</label>)}</fieldset>
      <button disabled={busy || conflicted || added.length + removed.length === 0} onClick={() => void review()}>Review membership changes</button>
    </> : <>
      <h3>Machines gaining group access</h3>{added.length ? <ul>{added.map(id => <li key={id}>{name(id)}</li>)}</ul> : <p>None</p>}
      <h3>Machines losing group access</h3>{removed.length ? <ul>{removed.map(id => <li key={id}>{name(id)}</li>)}</ul> : <p>None</p>}
      <h3>Group assignments</h3>{impact?.dependencies.length ? <ul>{impact.dependencies.map(item => <li key={item.key}><a href={item.href}>{item.label}</a></li>)}</ul> : <p>No assignments found in the console's supported resource forms.</p>}
      <p>Changes affect access supplied by this group. Other groups and legacy rules may still allow access. Relay admission converges on the next roster refresh; internet egress still requires client consent and Gateway readiness.</p>
      <label><input type="checkbox" disabled={busy || conflicted} checked={acknowledged} onChange={event => setAcknowledged(event.target.checked)} />I reviewed the machines and group assignments.</label>
      <div className="actions"><button disabled={busy} onClick={() => { setReviewing(false); setAcknowledged(false); }}>Back</button><button className="primary" disabled={busy || conflicted || !acknowledged} onClick={() => void save()}>Apply membership changes</button></div>
    </>)}
    <div className="actions"><button disabled={busy} onClick={onClose}>Cancel</button><button disabled={busy} onClick={() => void reload()}>Reload latest group</button></div>
    {conflicted && <p>Reloading replaces this draft with the current membership. No changes from this form have been saved.</p>}
  </Dialog>;
}
