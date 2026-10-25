// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { useEffect, useState } from "react";
import { Dialog } from "@karst-net/ui";
import { api } from "../api";
import { loadGroupDependencies, type GroupDependencyReview } from "../group-dependencies";

export function GroupDeletion({ id, onClose, onDeleted }: { id: string; onClose: () => void; onDeleted: (name: string) => void }) {
  const [review, setReview] = useState<GroupDependencyReview>();
  const [busy, setBusy] = useState(true);
  const [error, setError] = useState<string>();
  const [acknowledged, setAcknowledged] = useState(false);
  const refresh = async () => {
    setBusy(true); setError(undefined); setAcknowledged(false); setReview(undefined);
    try { setReview(await loadGroupDependencies(id)); }
    catch (error) { setError((error as Error).message); }
    finally { setBusy(false); }
  };
  useEffect(() => { void refresh(); }, [id]);
  const remove = async () => {
    if (!review || !acknowledged || busy || review.dependencies.length) return;
    setBusy(true); setError(undefined);
    try {
      const current = await loadGroupDependencies(id);
      if (current.fingerprint !== review.fingerprint) {
        setReview(current); setAcknowledged(false); setError("The group or its access changed. Review the updated impact before deleting."); return;
      }
      await api.deleteGroup(id); onDeleted(current.group.name);
    } catch (error) { setAcknowledged(false); setError((error as Error).message); }
    finally { setBusy(false); }
  };
  const editable = review && (review.group.issued ?? "api") === "api" && review.group.name !== "All";
  const blocked = !review || !editable || review.dependencies.length > 0;
  return <Dialog open title="Review group deletion" onClose={() => { if (!busy) onClose(); }}>
    {busy && <p>Checking group dependencies…</p>}
    {error && <p role="alert">{error}</p>}
    {review && <>
      <p>Delete <strong>{review.group.name}</strong>?</p>
      <p>{review.group.peers_count} machines belong to this group. Deleting the group removes their membership; the machines remain enrolled.</p>
      {(review.group.peers?.length ?? 0) > 0 && <details><summary>Affected machines</summary><ul>{review.group.peers?.map(peer => <li key={peer.id}>{peer.name}</li>)}</ul></details>}
      {!editable && <p>This group is built in or managed by an identity provider and cannot be deleted here.</p>}
      {review.dependencies.length > 0 ? <><h3>Resolve these dependencies first</h3><ul>{review.dependencies.map(dependency => <li key={dependency.key}><a href={dependency.href}>{dependency.label}</a></li>)}</ul><p>Update or remove these assignments in their owning forms, then refresh this review. Access grants and relay restrictions are not deleted automatically.</p></> : <p>No dependencies found in access grants, relays, Gateway routes, DNS, user assignments or active invitations. The server also checks inherited management settings when deleting.</p>}
      {review.history.length > 0 && <><h3>Retained invitation history</h3><ul>{review.history.map((entry, index) => <li key={index}>{entry}</li>)}</ul><p>These invitations can no longer enroll machines. Their history remains after group deletion.</p></>}
      <label><input type="checkbox" disabled={Boolean(blocked || busy)} checked={acknowledged} onChange={event => setAcknowledged(event.target.checked)} />I reviewed the impact and want to delete this group.</label>
    </>}
    <div className="actions"><button disabled={busy} onClick={onClose}>Cancel</button><button disabled={busy} onClick={() => void refresh()}>Refresh review</button><button className="danger" disabled={Boolean(blocked || busy || !acknowledged)} onClick={() => void remove()}>Delete group</button></div>
  </Dialog>;
}
