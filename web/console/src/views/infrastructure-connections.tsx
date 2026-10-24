// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { useState } from "react";
import { Dialog, EmptyState, Observed } from "@karst-net/ui";
import type { InfrastructureConnection } from "@karst-net/api-client";
import { api } from "../api";
import { Failure, Notice, Rows, useMutation, useResource } from "../common";
import { TutorialHint } from "../tutorial";

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
  lxdAddress: string; lxdProject: string;
  lxdServerCert: string; lxdClientCert: string; lxdClientKey: string;
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
  lxdAddress: "", lxdProject: "",
  lxdServerCert: "", lxdClientCert: "", lxdClientKey: "",
  lat: "", lon: "", locationLabel: "",
};

/** Builds the type-shaped secret object infraconnections.CreateRequest
 *  expects -- see server/management/internals/karst/infraconnections/
 *  {aws,azure,gcp,kubernetes,nomad,lxd}.go for the exact field names each
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
    case "lxd":
      return {
        address: draft.lxdAddress.trim(), project: draft.lxdProject.trim() || undefined,
        server_cert: draft.lxdServerCert.trim() || undefined,
        client_cert: draft.lxdClientCert.trim() || undefined, client_key: draft.lxdClientKey.trim() || undefined,
      };
    default:
      throw new Error(`Unknown connection type ${draft.type}`);
  }
}

export function InfrastructureConnections() {
  const infraConnections = useResource(api.infrastructureConnections);
  const { message, setMessage, run } = useMutation(infraConnections.reload);
  const [connectionDraft, setConnectionDraft] = useState<ConnectionDraft>();

  const addConnection = async () => {
    if (!connectionDraft) return;
    let secret: Record<string, unknown>;
    try { secret = connectionSecretFor(connectionDraft); }
    catch (e) { setMessage(e instanceof Error ? e.message : "Invalid credential."); return; }
    let lat: number | undefined, lon: number | undefined;
    if ((connectionDraft.type === "kubernetes" || connectionDraft.type === "nomad" || connectionDraft.type === "lxd") && (connectionDraft.lat.trim() || connectionDraft.lon.trim())) {
      lat = Number(connectionDraft.lat); lon = Number(connectionDraft.lon);
      if (!Number.isFinite(lat) || lat < -90 || lat > 90) { setMessage("Latitude must be a number between -90 and 90."); return; }
      if (!Number.isFinite(lon) || lon < -180 || lon > 180) { setMessage("Longitude must be a number between -180 and 180."); return; }
    }
    const entry = {
      type: connectionDraft.type, mode: connectionDraft.mode, label: connectionDraft.label.trim() || undefined, secret,
      lat, lon, location_label: connectionDraft.locationLabel.trim() || undefined,
    };
    if (await run(() => api.createInfrastructureConnection(entry), `${connectionDraft.label || connectionDraft.type} was added.`)) setConnectionDraft(undefined);
  };
  const removeConnection = (connection: InfrastructureConnection) => {
    if (!confirm(`Remove ${connection.label || connection.type}? Any Authorized Locations entries already added from it stay as plain declared points.`)) return;
    void run(() => api.deleteInfrastructureConnection(connection.id), `${connection.label || connection.type} was removed.`);
  };

  return <section>
    <h2>Infrastructure connections</h2>
    <TutorialHint>Lets Authorized Locations offer real regions, local zones, Kubernetes namespaces, Nomad datacenters, and LXD cluster members instead of typing coordinates by hand. "Read-only" connections can only ever discover (list regions/namespaces/datacenters/cluster-members) — they cannot place an order or create a workload. "Read-write" connections may make one further live change — enabling an AWS Local Zone that exists but isn't opted into use yet — and can incur costs; nothing else in Karst uses them to create or change infrastructure yet. Secrets are encrypted at rest and never shown again once saved. Status shows whether the last discovery call succeeded.</TutorialHint>
    <div className="actions"><button className="primary" onClick={() => setConnectionDraft(blankConnectionDraft)}>Add infrastructure connection</button></div>
    <Notice message={message} />
    {infraConnections.loading ? <p>Loading infrastructure connections…</p> : infraConnections.error
      ? <Failure message={infraConnections.error} retry={infraConnections.reload} />
      : (infraConnections.value ?? []).length === 0
        ? <EmptyState title="No infrastructure connections configured">Add one to pick real regions, namespaces, datacenters, or cluster members in Authorized Locations.</EmptyState>
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
          <option value="lxd">LXD</option>
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
        {connectionDraft?.type === "lxd" && <>
          <label>Address<input aria-label="LXD address" placeholder="https://lxd.internal:8443" value={connectionDraft.lxdAddress} onChange={(event) => setConnectionDraft((current) => current && { ...current, lxdAddress: event.target.value })} /></label>
          <label>Project (optional)<input aria-label="LXD project" placeholder="default" value={connectionDraft.lxdProject} onChange={(event) => setConnectionDraft((current) => current && { ...current, lxdProject: event.target.value })} /></label>
          <label>Server certificate (optional, PEM)<textarea aria-label="LXD server certificate" rows={4} value={connectionDraft.lxdServerCert} onChange={(event) => setConnectionDraft((current) => current && { ...current, lxdServerCert: event.target.value })} placeholder={"-----BEGIN CERTIFICATE-----\n..."} /></label>
          <p className="lede">Pins this LXD server's own certificate, since its default is self-signed with no real CA behind it — paste the server's own cert here rather than a CA's.</p>
          <label>Client certificate (PEM)<textarea aria-label="LXD client certificate" rows={4} value={connectionDraft.lxdClientCert} onChange={(event) => setConnectionDraft((current) => current && { ...current, lxdClientCert: event.target.value })} placeholder={"-----BEGIN CERTIFICATE-----\n..."} /></label>
          {/* Deliberately no illustrative PEM-header placeholder here,
              unlike the cert fields above: a second literal occurrence of
              the private-key PEM marker in this file (Nomad's client key
              field above already has one) trips the secret scanner's
              private-key rule, even though neither is a real key -- see
              the commit message. */}
          <label>Client key (PEM)<textarea aria-label="LXD client key" rows={4} value={connectionDraft.lxdClientKey} onChange={(event) => setConnectionDraft((current) => current && { ...current, lxdClientKey: event.target.value })} placeholder="Paste the client key's PEM contents" /></label>
          <p className="lede">LXD authenticates the client by certificate (<code>lxc config trust add</code>) rather than a token.</p>
        </>}
        {(connectionDraft?.type === "kubernetes" || connectionDraft?.type === "nomad" || connectionDraft?.type === "lxd") && <>
          <p className="lede">A private cluster, scheduler, or hypervisor environment has no provider-supplied location — declare one below if you'd like it to appear on the NOC map and feed Authorized Locations.</p>
          <label>Latitude (optional)<input aria-label="Connection latitude" placeholder="37.7749" value={connectionDraft.lat} onChange={(event) => setConnectionDraft((current) => current && { ...current, lat: event.target.value })} /></label>
          <label>Longitude (optional)<input aria-label="Connection longitude" placeholder="-122.4194" value={connectionDraft.lon} onChange={(event) => setConnectionDraft((current) => current && { ...current, lon: event.target.value })} /></label>
          <label>Location label (optional)<input aria-label="Connection location label" placeholder="homelab" value={connectionDraft.locationLabel} onChange={(event) => setConnectionDraft((current) => current && { ...current, locationLabel: event.target.value })} /></label>
        </>}

        <div className="actions"><button type="button" onClick={() => setConnectionDraft(undefined)}>Cancel</button><button className="primary" type="submit">Add connection</button></div>
      </form>
    </Dialog>
  </section>;
}
