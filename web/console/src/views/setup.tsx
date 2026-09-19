// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.
import { useEffect, useState } from "react";
import { api, type DeviceInvitation, type Group, type MeshDomain } from "../api";

export function Setup({ go }: { go: (route: string) => void }) {
  const [groups, setGroups] = useState<Group[]>([]);
  const [domains, setDomains] = useState<MeshDomain[]>([]);
  const [invitations, setInvitations] = useState<DeviceInvitation[]>([]);
  const [selected, setSelected] = useState<string[]>([]);
  const [domainId, setDomainId] = useState("");
  const [name, setName] = useState("");
  const [invitation, setInvitation] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState(false);
  const refresh = async () => setInvitations(await api.invitations());
  useEffect(() => {
    let active = true;
    Promise.all([api.groups(), api.invitations()]).then(([allGroups, allInvitations]) => {
      if (active) { setGroups(allGroups.filter(group => group.name !== "All")); setInvitations(allInvitations); }
    }).catch(() => { if (active) setError("Could not load invitations. Refresh to try again."); });
    // Best-effort and separate from the load above: a user delegated
    // admin of one subdomain (ADR-0032) can still issue invitations
    // without seeing every domain, and a permission refusal here should
    // not block the invitation form itself -- it only means "root only"
    // in the picker below, which is exactly what worked before domains
    // existed at all.
    api.domains().then(list => { if (active) setDomains(list); }).catch(() => { /* picker just stays root-only */ });
    return () => { active = false; };
  }, []);
  async function create() {
    setError(""); setBusy(true); setInvitation(""); setCopied(false);
    try {
      if (location.protocol !== "https:") throw new Error("Open the administrative console over HTTPS before creating an invitation.");
      const metadata = await api.enrollmentMetadata();
      const grant = await api.createInvitation(name.trim(), selected, domainId);
      if (!grant.credential) throw new Error("The server did not return an invitation credential.");
      const payload = JSON.stringify({ server: location.origin, ...metadata, setup_key: grant.credential });
      const bytes = new TextEncoder().encode(payload);
      const encoded = btoa(Array.from(bytes, byte => String.fromCharCode(byte)).join(""))
        .replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
      setInvitation(`karst-invite-v1:${encoded}`);
      setInvitations(previous => [{ ...grant, credential: undefined }, ...previous]);
    } catch (e) { setError(e instanceof Error ? e.message : "Could not create an invitation."); }
    finally { setBusy(false); }
  }
  async function revoke(id: string) {
    setBusy(true); setError("");
    try { await api.revokeInvitation(id); await refresh(); }
    catch { setError("Could not revoke the invitation. Try again."); }
    finally { setBusy(false); }
  }
  return <section><h2>Add device</h2>
    <p>Create an invitation for one device. The recipient installs Karst and pastes it into setup. No account or identity-provider login is needed.</p>
    {error && <p role="alert">{error}</p>}
    <form onSubmit={event => { event.preventDefault(); void create(); }}>
      <label>Device name<input value={name} maxLength={100} required onChange={event => setName(event.target.value)} /></label>
      <p className="lede">This becomes the device's real name on the mesh — how other devices address it — not just a label in this list.{domainId && (() => { const chosen = domains.find(d => d.id === domainId); return chosen ? <> It will resolve as <code>{name.trim() || "…"}.{chosen.path}</code>.</> : null; })()}</p>
      {domains.length > 0 && <label>Domain<select aria-label="Domain" value={domainId} onChange={event => setDomainId(event.target.value)}>
        <option value="">Account root (no domain)</option>
        {domains.map(domain => <option key={domain.id} value={domain.id}>{domain.path}</option>)}
      </select></label>}
      <fieldset><legend>Access groups</legend>
        {groups.map(group => <label key={group.id}><input type="checkbox" checked={selected.includes(group.id)} onChange={event => setSelected(previous => event.target.checked ? [...previous, group.id] : previous.filter(id => id !== group.id))} />{group.name}</label>)}
        {groups.length === 0 && <p>Create an access group before issuing an invitation. <button type="button" onClick={() => go("groups")}>Manage groups</button></p>}
      </fieldset>
      <p>The invitation expires in 24 hours and can enroll one device. Its access groups cannot be changed after issuance.</p>
      <button disabled={busy || !name.trim() || selected.length === 0}>Create invitation</button>
    </form>
    {invitation && <section aria-label="New invitation">
      <p>Share this invitation privately with the recipient. It is displayed only now.</p>
      <label>Enrollment invitation<textarea aria-label="Enrollment invitation" readOnly value={invitation} spellCheck={false} /></label>
      <button onClick={() => { void navigator.clipboard.writeText(invitation).then(() => setCopied(true)).catch(() => setError("Copy failed. Select and copy the invitation above.")); }}>{copied ? "Copied" : "Copy invitation"}</button>
      <button onClick={() => setInvitation("")}>Dismiss invitation</button>
    </section>}
    <h3>Invitations</h3>
    <button disabled={busy} onClick={() => { void refresh().catch(() => setError("Could not refresh invitations.")); }}>Refresh status</button>
    <ul>{invitations.map(item => <li key={item.id}>{item.name}{item.domain_id && (() => { const d = domains.find(x => x.id === item.domain_id); return d ? <>.{d.path}</> : null; })()} — {item.state} — expires {new Date(item.expires_at).toLocaleString()}
      {item.state === "pending" && <button disabled={busy} onClick={() => { void revoke(item.id); }}>Revoke {item.name}</button>}
    </li>)}</ul>
    <p>Network policy and any required Bedrock approval determine when a registered device can connect.</p>
    <button onClick={() => go("machines")}>View machines</button>
  </section>;
}
