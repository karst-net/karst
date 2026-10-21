// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { SoftwareVersions } from "./software-versions";
import { useState } from "react";
import { Dialog, EmptyState, Observed } from "@karst-net/ui";
import type { InfrastructureConnection } from "@karst-net/api-client";
import { api, type Token } from "../api";
import { Failure, Notice, Rows, useMutation, useResource } from "../common";

const expiries = [["30 days", 30], ["90 days", 90], ["365 days", 365]] as const;

type ConnectionType = InfrastructureConnection["type"];
type ConnectionMode = InfrastructureConnection["mode"];

type ConnectionDraft = {
  type: ConnectionType;
  mode: ConnectionMode;
  label: string;
  awsAccessKeyId: string; awsSecretAccessKey: string; awsSessionToken: string;
  azureTenantId: string; azureClientId: string; azureClientSecret: string; azureSubscriptionId: string;
  gcpProjectId: string; gcpServiceAccountKey: string;
  kubeconfig: string;
  nomadAddress: string; nomadRegion: string; nomadNamespace: string; nomadToken: string;
  nomadCaCert: string; nomadClientCert: string; nomadClientKey: string;
  lat: string; lon: string; locationLabel: string;
};
const blankConnectionDraft: ConnectionDraft = {
  type: "aws", mode: "read_only", label: "",
  awsAccessKeyId: "", awsSecretAccessKey: "", awsSessionToken: "",
  azureTenantId: "", azureClientId: "", azureClientSecret: "", azureSubscriptionId: "",
  gcpProjectId: "", gcpServiceAccountKey: "",
  kubeconfig: "",
  nomadAddress: "", nomadRegion: "", nomadNamespace: "", nomadToken: "",
  nomadCaCert: "", nomadClientCert: "", nomadClientKey: "",
  lat: "", lon: "", locationLabel: "",
};

/** Builds the type-shaped secret object infraconnections.CreateRequest
 *  expects -- see server/management/internals/karst/infraconnections/
 *  {aws,azure,gcp,kubernetes,nomad}.go for the exact field names each
 *  type's validator requires. Throws a plain Error with user-facing text
 *  on a malformed GCP key, since that is the one field a paste error is
 *  likely in. */
function connectionSecretFor(draft: ConnectionDraft): Record<string, unknown> {
  switch (draft.type) {
    case "aws":
      return { access_key_id: draft.awsAccessKeyId.trim(), secret_access_key: draft.awsSecretAccessKey.trim(), session_token: draft.awsSessionToken.trim() || undefined };
    case "azure":
      return { tenant_id: draft.azureTenantId.trim(), client_id: draft.azureClientId.trim(), client_secret: draft.azureClientSecret.trim(), subscription_id: draft.azureSubscriptionId.trim() };
    case "gcp":
      try { return { project_id: draft.gcpProjectId.trim(), service_account_key: JSON.parse(draft.gcpServiceAccountKey) }; }
      catch { throw new Error("The service account key must be the exact JSON contents of the downloaded key file."); }
    case "kubernetes":
      return { kubeconfig: draft.kubeconfig };
    case "nomad":
      return {
        address: draft.nomadAddress.trim(), region: draft.nomadRegion.trim() || undefined, namespace: draft.nomadNamespace.trim() || undefined,
        token: draft.nomadToken.trim() || undefined, ca_cert: draft.nomadCaCert.trim() || undefined,
        client_cert: draft.nomadClientCert.trim() || undefined, client_key: draft.nomadClientKey.trim() || undefined,
      };
    default:
      throw new Error(`Unknown connection type ${draft.type}`);
  }
}

export function Settings() {
  const me = useResource(api.currentUser);
  const account = useResource(api.account);
  const tokens = useResource(() => me.value ? api.tokens(me.value.id) : Promise.resolve([] as Token[]), [me.value?.id]);
  const { message, setMessage, run } = useMutation(tokens.reload);
  const [draft, setDraft] = useState<{ name: string; expires_in: number }>();
  const [issued, setIssued] = useState<string>();
  const controlPlaneLocation = useResource(api.controlPlaneLocation);
  const { message: locationMessage, setMessage: setLocationMessage, run: runLocation } = useMutation(controlPlaneLocation.reload);
  const [locationDraft, setLocationDraft] = useState<{ lat: string; lon: string; label: string }>();
  const tutorialMode = useResource(api.tutorialMode);
  // An optimistic override: the checkbox must flip the instant it's clicked
  // rather than waiting on a round trip, or a fast double-click (or a test)
  // sees the click appear to do nothing. Cleared back to the server's value
  // whenever a fresh fetch completes; reset to the pre-toggle value on error.
  const [tutorialOverride, setTutorialOverride] = useState<boolean>();
  const tutorialEnabled = tutorialOverride ?? tutorialMode.value?.enabled ?? true;
  const [tutorialSaving, setTutorialSaving] = useState(false);
  const infraConnections = useResource(api.infrastructureConnections);
  const { message: connectionMessage, setMessage: setConnectionMessage, run: runConnection } = useMutation(infraConnections.reload);
  const [connectionDraft, setConnectionDraft] = useState<ConnectionDraft>();

  if (me.loading) return <p>Loading settings…</p>;
  if (me.error) return <Failure message={me.error} retry={me.reload} />;
  const user = me.value;

  const create = async () => {
    if (!draft || !user) return;
    const name = draft.name.trim();
    if (!name) { setMessage("A token needs a name — it is the only way to tell two of them apart later."); return; }
    try {
      const created = await api.createToken(user.id, name, draft.expires_in);
      setIssued(created.plain_token);
      setDraft(undefined);
      setMessage("Copy this token now. It is not stored and will not be shown again.");
      tokens.reload();
    } catch (error) { setMessage((error as Error).message); }
  };
  const remove = (token: Token) => {
    if (!user) return;
    if (!confirm(`Revoke ${token.name}? Anything using it stops working immediately.`)) return;
    void run(() => api.deleteToken(user.id, token.id), `${token.name} was revoked.`);
  };
  const saveControlPlaneLocation = async () => {
    if (!locationDraft) return;
    const lat = Number(locationDraft.lat), lon = Number(locationDraft.lon);
    if (!Number.isFinite(lat) || lat < -90 || lat > 90) { setLocationMessage("Latitude must be a number between -90 and 90."); return; }
    if (!Number.isFinite(lon) || lon < -180 || lon > 180) { setLocationMessage("Longitude must be a number between -180 and 180."); return; }
    const label = locationDraft.label.trim() || undefined;
    if (await runLocation(() => api.setControlPlaneLocation({ lat, lon, label }), "The control plane's location was declared.")) setLocationDraft(undefined);
  };
  const toggleTutorialMode = async (enabled: boolean) => {
    setTutorialOverride(enabled);
    setTutorialSaving(true);
    try { await api.setTutorialMode(enabled); tutorialMode.reload(); }
    catch { setTutorialOverride(!enabled); }
    finally { setTutorialSaving(false); }
  };
  const addConnection = async () => {
    if (!connectionDraft) return;
    let secret: Record<string, unknown>;
    try { secret = connectionSecretFor(connectionDraft); }
    catch (e) { setConnectionMessage(e instanceof Error ? e.message : "Invalid credential."); return; }
    let lat: number | undefined, lon: number | undefined;
    if ((connectionDraft.type === "kubernetes" || connectionDraft.type === "nomad") && (connectionDraft.lat.trim() || connectionDraft.lon.trim())) {
      lat = Number(connectionDraft.lat); lon = Number(connectionDraft.lon);
      if (!Number.isFinite(lat) || lat < -90 || lat > 90) { setConnectionMessage("Latitude must be a number between -90 and 90."); return; }
      if (!Number.isFinite(lon) || lon < -180 || lon > 180) { setConnectionMessage("Longitude must be a number between -180 and 180."); return; }
    }
    const entry = {
      type: connectionDraft.type, mode: connectionDraft.mode, label: connectionDraft.label.trim() || undefined, secret,
      lat, lon, location_label: connectionDraft.locationLabel.trim() || undefined,
    };
    if (await runConnection(() => api.createInfrastructureConnection(entry), `${connectionDraft.label || connectionDraft.type} was added.`)) setConnectionDraft(undefined);
  };
  const removeConnection = (connection: InfrastructureConnection) => {
    if (!confirm(`Remove ${connection.label || connection.type}? Any Authorized Locations entries already added from it stay as plain declared points.`)) return;
    void runConnection(() => api.deleteInfrastructureConnection(connection.id), `${connection.label || connection.type} was removed.`);
  };

  return <section>
    <h2>Settings</h2>
    {(user?.role === "admin" || user?.role === "owner") && <SoftwareVersions />}
    <h3>Signed in as</h3>
    <Rows head={<><th>Name</th><th>Email</th><th>Role</th><th>User ID</th></>}>
      <tr><td>{user?.name}</td><td>{user?.email}</td><td>{user?.role}</td><td><code>{user?.id}</code></td></tr>
    </Rows>

    <h3>Personal access tokens</h3>
    <p className="lede">A token authenticates the API as you, with your permissions. Prefer one token per automation, so that revoking one does not break the others.</p>
    <div className="actions"><button className="primary" onClick={() => { setIssued(undefined); setDraft({ name: "", expires_in: 30 }); }}>Create token</button></div>
    <Notice message={message} />
    {issued && <label>New personal access token<input aria-label="New personal access token" readOnly value={issued} /></label>}
    {tokens.error ? <Failure message={tokens.error} retry={tokens.reload} />
      : (tokens.value ?? []).length === 0
        ? <EmptyState title="No personal access tokens">Create one to script against the control API.</EmptyState>
        : <Rows head={<><th>Name</th><th>Created</th><th>Expires</th><th>Last used</th><th>Actions</th></>}>
          {(tokens.value ?? []).map((token) => <tr key={token.id}>
            <td><strong>{token.name}</strong></td>
            <td><Observed at={token.created_at} /></td>
            <td><Observed at={token.expiration_date} /></td>
            <td>{token.last_used ? <Observed at={token.last_used} /> : "Never"}</td>
            <td><button className="danger" onClick={() => remove(token)}>Revoke</button></td>
          </tr>)}
        </Rows>}

    <h3>Organization</h3>
    {account.loading ? <p>Loading organization…</p> : account.error
      ? <Failure message={account.error} retry={account.reload} />
      : account.value && <Rows head={<><th>Organization ID</th><th>Domain</th><th>Created</th></>}>
        <tr><td><code>{account.value.id}</code></td><td>{account.value.domain || "—"}</td><td><Observed at={account.value.created_at} /></td></tr>
      </Rows>}
    <p className="lede">Single sign-on, SCIM provisioning and webhooks are configured on the coordination server rather than here — they are server startup configuration, and a console that pretended to own them would be editing a file it cannot read. See <code>management.json</code> and the getting-started guide.</p>

    <h3>Control plane location</h3>
    <p className="lede">Where this account's control plane is, shown on the NOC map. Optional, operator-declared — never inferred. There is no per-replica placement registry yet (see ADR-0054), so this is one declared point for the account, not one per replica.</p>
    {controlPlaneLocation.loading ? <p>Loading…</p> : controlPlaneLocation.error
      ? <Failure message={controlPlaneLocation.error} retry={controlPlaneLocation.reload} />
      : <>
        <p>{controlPlaneLocation.value ? (controlPlaneLocation.value.label || `${controlPlaneLocation.value.lat}, ${controlPlaneLocation.value.lon}`) : <span className="lede">No location declared</span>}</p>
        <div className="actions"><button onClick={() => setLocationDraft({ lat: controlPlaneLocation.value ? String(controlPlaneLocation.value.lat) : "", lon: controlPlaneLocation.value ? String(controlPlaneLocation.value.lon) : "", label: controlPlaneLocation.value?.label ?? "" })}>{controlPlaneLocation.value ? "Edit location" : "Set location"}</button></div>
      </>}
    <Notice message={locationMessage} />

    <h3>Guidance text</h3>
    <p className="lede">Shows a short "what is this, what does it talk to" explanation on each page, for admins who are new to Karst's components. On by default.</p>
    {tutorialMode.loading ? <p>Loading…</p> : tutorialMode.error
      ? <Failure message={tutorialMode.error} retry={tutorialMode.reload} />
      : <label><input type="checkbox" checked={tutorialEnabled} disabled={tutorialSaving} onChange={(event) => void toggleTutorialMode(event.target.checked)} /> Show guidance text on each page</label>}

    <h3>Infrastructure Connections</h3>
    <p className="lede">Lets Authorized Locations offer real regions, local zones, Kubernetes namespaces, and Nomad datacenters instead of typing coordinates by hand. "Read-only" connections can only ever discover (list regions/namespaces/datacenters) — they cannot place an order or create a workload. "Read-write" connections may make one further live change — enabling an AWS Local Zone that exists but isn't opted into use yet — and can incur costs; nothing else in Karst uses them to create or change infrastructure yet. Secrets are encrypted at rest and never shown again once saved. Status shows whether the last discovery call succeeded.</p>
    <div className="actions"><button className="primary" onClick={() => setConnectionDraft(blankConnectionDraft)}>Add infrastructure connection</button></div>
    <Notice message={connectionMessage} />
    {infraConnections.loading ? <p>Loading infrastructure connections…</p> : infraConnections.error
      ? <Failure message={infraConnections.error} retry={infraConnections.reload} />
      : (infraConnections.value ?? []).length === 0
        ? <EmptyState title="No infrastructure connections configured">Add one to pick real regions, namespaces, or datacenters in Authorized Locations.</EmptyState>
        : <Rows head={<><th>Type</th><th>Mode</th><th>Label</th><th>Status</th><th>Added</th><th>Actions</th></>}>
          {(infraConnections.value ?? []).map((connection) => <tr key={connection.id}>
            <td>{connection.type.toUpperCase()}</td>
            <td>{connection.mode === "read_write" ? "Read-write (may make live changes and incur costs)" : "Read-only"}</td>
            <td>{connection.label || <span className="lede">—</span>}</td>
            <td>{connection.status === "error" ? connection.last_error : connection.status === "ok" ? "OK" : <span className="lede">Not yet validated</span>}</td>
            <td><Observed at={connection.created_at} /></td>
            <td><button className="danger" onClick={() => removeConnection(connection)}>Remove</button></td>
          </tr>)}
        </Rows>}

    <Dialog open={Boolean(connectionDraft)} title="Add infrastructure connection" onClose={() => setConnectionDraft(undefined)}>
      <form onSubmit={(event) => { event.preventDefault(); void addConnection(); }}>
        <label>Connection type<select aria-label="Connection type" value={connectionDraft?.type ?? "aws"} onChange={(event) => setConnectionDraft((current) => current && { ...current, type: event.target.value as ConnectionType })}>
          <option value="aws">AWS</option>
          <option value="azure">Azure</option>
          <option value="gcp">GCP</option>
          <option value="kubernetes">Kubernetes</option>
          <option value="nomad">Nomad</option>
        </select></label>
        <label>Mode<select aria-label="Connection mode" value={connectionDraft?.mode ?? "read_only"} onChange={(event) => setConnectionDraft((current) => current && { ...current, mode: event.target.value as ConnectionMode })}>
          <option value="read_only">Read-only (status/discovery only)</option>
          <option value="read_write">Read-write (may make live changes — e.g. enabling an AWS local zone — and can incur costs)</option>
        </select></label>
        <label>Label<input aria-label="Connection label" placeholder="prod-aws" value={connectionDraft?.label ?? ""} onChange={(event) => setConnectionDraft((current) => current && { ...current, label: event.target.value })} /></label>

        {connectionDraft?.type === "aws" && <>
          <label>Access key ID<input aria-label="AWS access key ID" value={connectionDraft.awsAccessKeyId} onChange={(event) => setConnectionDraft((current) => current && { ...current, awsAccessKeyId: event.target.value })} /></label>
          <label>Secret access key<input aria-label="AWS secret access key" type="password" value={connectionDraft.awsSecretAccessKey} onChange={(event) => setConnectionDraft((current) => current && { ...current, awsSecretAccessKey: event.target.value })} /></label>
          <label>Session token (optional)<input aria-label="AWS session token" type="password" value={connectionDraft.awsSessionToken} onChange={(event) => setConnectionDraft((current) => current && { ...current, awsSessionToken: event.target.value })} /></label>
        </>}
        {connectionDraft?.type === "azure" && <>
          <label>Tenant ID<input aria-label="Azure tenant ID" value={connectionDraft.azureTenantId} onChange={(event) => setConnectionDraft((current) => current && { ...current, azureTenantId: event.target.value })} /></label>
          <label>Client ID<input aria-label="Azure client ID" value={connectionDraft.azureClientId} onChange={(event) => setConnectionDraft((current) => current && { ...current, azureClientId: event.target.value })} /></label>
          <label>Client secret<input aria-label="Azure client secret" type="password" value={connectionDraft.azureClientSecret} onChange={(event) => setConnectionDraft((current) => current && { ...current, azureClientSecret: event.target.value })} /></label>
          <label>Subscription ID<input aria-label="Azure subscription ID" value={connectionDraft.azureSubscriptionId} onChange={(event) => setConnectionDraft((current) => current && { ...current, azureSubscriptionId: event.target.value })} /></label>
        </>}
        {connectionDraft?.type === "gcp" && <>
          <label>Project ID<input aria-label="GCP project ID" value={connectionDraft.gcpProjectId} onChange={(event) => setConnectionDraft((current) => current && { ...current, gcpProjectId: event.target.value })} /></label>
          <label>Service account key (JSON)<textarea aria-label="GCP service account key JSON" rows={6} value={connectionDraft.gcpServiceAccountKey} onChange={(event) => setConnectionDraft((current) => current && { ...current, gcpServiceAccountKey: event.target.value })} placeholder='{"type": "service_account", ...}' /></label>
        </>}
        {connectionDraft?.type === "kubernetes" && <>
          <label>Kubeconfig<textarea aria-label="Kubeconfig" rows={6} value={connectionDraft.kubeconfig} onChange={(event) => setConnectionDraft((current) => current && { ...current, kubeconfig: event.target.value })} placeholder={"apiVersion: v1\nkind: Config\n..."} /></label>
          <p className="lede">Only the kubeconfig's current-context cluster is used.</p>
        </>}
        {connectionDraft?.type === "nomad" && <>
          <label>Address<input aria-label="Nomad address" placeholder="https://nomad.internal:4646" value={connectionDraft.nomadAddress} onChange={(event) => setConnectionDraft((current) => current && { ...current, nomadAddress: event.target.value })} /></label>
          <label>Region (optional)<input aria-label="Nomad region" placeholder="us-east" value={connectionDraft.nomadRegion} onChange={(event) => setConnectionDraft((current) => current && { ...current, nomadRegion: event.target.value })} /></label>
          <label>Namespace (optional)<input aria-label="Nomad namespace" placeholder="prod" value={connectionDraft.nomadNamespace} onChange={(event) => setConnectionDraft((current) => current && { ...current, nomadNamespace: event.target.value })} /></label>
          <label>ACL token (optional)<input aria-label="Nomad ACL token" type="password" value={connectionDraft.nomadToken} onChange={(event) => setConnectionDraft((current) => current && { ...current, nomadToken: event.target.value })} /></label>
          <label>CA certificate (optional, PEM)<textarea aria-label="Nomad CA certificate" rows={4} value={connectionDraft.nomadCaCert} onChange={(event) => setConnectionDraft((current) => current && { ...current, nomadCaCert: event.target.value })} placeholder={"-----BEGIN CERTIFICATE-----\n..."} /></label>
          <label>Client certificate (optional, PEM)<textarea aria-label="Nomad client certificate" rows={4} value={connectionDraft.nomadClientCert} onChange={(event) => setConnectionDraft((current) => current && { ...current, nomadClientCert: event.target.value })} placeholder={"-----BEGIN CERTIFICATE-----\n..."} /></label>
          <label>Client key (optional, PEM)<textarea aria-label="Nomad client key" rows={4} value={connectionDraft.nomadClientKey} onChange={(event) => setConnectionDraft((current) => current && { ...current, nomadClientKey: event.target.value })} placeholder={"-----BEGIN PRIVATE KEY-----\n..."} /></label>
        </>}
        {(connectionDraft?.type === "kubernetes" || connectionDraft?.type === "nomad") && <>
          <p className="lede">A private cluster or scheduler environment has no provider-supplied location — declare one below if you'd like it to appear on the NOC map and feed Authorized Locations.</p>
          <label>Latitude (optional)<input aria-label="Connection latitude" placeholder="37.7749" value={connectionDraft.lat} onChange={(event) => setConnectionDraft((current) => current && { ...current, lat: event.target.value })} /></label>
          <label>Longitude (optional)<input aria-label="Connection longitude" placeholder="-122.4194" value={connectionDraft.lon} onChange={(event) => setConnectionDraft((current) => current && { ...current, lon: event.target.value })} /></label>
          <label>Location label (optional)<input aria-label="Connection location label" placeholder="homelab" value={connectionDraft.locationLabel} onChange={(event) => setConnectionDraft((current) => current && { ...current, locationLabel: event.target.value })} /></label>
        </>}

        <div className="actions"><button type="button" onClick={() => setConnectionDraft(undefined)}>Cancel</button><button className="primary" type="submit">Add connection</button></div>
      </form>
    </Dialog>

    <Dialog open={Boolean(locationDraft)} title="Declare the control plane's location" onClose={() => setLocationDraft(undefined)}>
      <form onSubmit={(event) => { event.preventDefault(); void saveControlPlaneLocation(); }}>
        <label>Latitude<input aria-label="Control plane latitude" placeholder="37.7749" value={locationDraft?.lat ?? ""} onChange={(event) => setLocationDraft((current) => current && { ...current, lat: event.target.value })} /></label>
        <label>Longitude<input aria-label="Control plane longitude" placeholder="-122.4194" value={locationDraft?.lon ?? ""} onChange={(event) => setLocationDraft((current) => current && { ...current, lon: event.target.value })} /></label>
        <label>Location label<input aria-label="Control plane location label" placeholder="Control room" value={locationDraft?.label ?? ""} onChange={(event) => setLocationDraft((current) => current && { ...current, label: event.target.value })} /></label>
        <div className="actions"><button type="button" onClick={() => setLocationDraft(undefined)}>Cancel</button><button className="primary" type="submit">Save location</button></div>
      </form>
    </Dialog>

    <Dialog open={Boolean(draft)} title="Create personal access token" onClose={() => setDraft(undefined)}>
      <form onSubmit={(event) => { event.preventDefault(); void create(); }}>
        <label>Token name<input aria-label="Token name" placeholder="ci-deploy" value={draft?.name ?? ""} onChange={(event) => setDraft((current) => current && { ...current, name: event.target.value })} /></label>
        <label>Expires in<select aria-label="Token expires in" value={draft?.expires_in ?? 30} onChange={(event) => setDraft((current) => current && { ...current, expires_in: Number(event.target.value) })}>{expiries.map(([label, value]) => <option key={value} value={value}>{label}</option>)}</select></label>
        <div className="actions"><button type="button" onClick={() => setDraft(undefined)}>Cancel</button><button className="primary" type="submit">Create token</button></div>
      </form>
    </Dialog>
  </section>;
}
