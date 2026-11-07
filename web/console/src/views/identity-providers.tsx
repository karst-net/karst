// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { useState } from "react";
import { Dialog, EmptyState } from "@karst-net/ui";
import { api, type IdentityProvider, type IdentityProviderType } from "../api";
import { Failure, Notice, Rows, useMutation, useResource } from "../common";
import { TutorialHint } from "../tutorial";

const providerTypes: Array<{ value: IdentityProviderType; label: string }> = [
  { value: "oidc", label: "Generic OIDC" },
  { value: "google", label: "Google" },
  { value: "microsoft", label: "Microsoft" },
  { value: "entra", label: "Microsoft Entra (Azure AD)" },
  { value: "okta", label: "Okta" },
  { value: "keycloak", label: "Keycloak" },
  { value: "authentik", label: "Authentik" },
  { value: "zitadel", label: "Zitadel" },
  { value: "pocketid", label: "PocketID" },
  { value: "adfs", label: "Microsoft AD FS" },
];

// Matches types.IdentityProviderType.HasBuiltInIssuer on the server:
// these providers' issuer URL is fixed, so the field is hidden rather than
// asking an admin to type a value the server ignores.
const hasBuiltInIssuer = (type: IdentityProviderType) => type === "google" || type === "microsoft";

type ProviderDraft = { id?: string; type: IdentityProviderType; name: string; issuer: string; client_id: string; client_secret: string };
const blankDraft: ProviderDraft = { type: "oidc", name: "", issuer: "", client_id: "", client_secret: "" };
const draftFor = (provider: IdentityProvider): ProviderDraft => ({ id: provider.id, type: provider.type, name: provider.name, issuer: provider.issuer, client_id: provider.client_id, client_secret: "" });

export function IdentityProviders() {
  const account = useResource(api.account);
  // Skipped while embedded_idp_enabled is unknown or false: a deployment on
  // a single external identity provider has no connectors to list, and the
  // server would otherwise be asked for a resource this page is about to
  // say doesn't apply here.
  const embeddedIdpEnabled = account.value?.embedded_idp_enabled ?? false;
  const providers = useResource(() => embeddedIdpEnabled ? api.identityProviders() : Promise.resolve([]), [embeddedIdpEnabled]);
  const { message, setMessage, run } = useMutation(providers.reload);
  const [draft, setDraft] = useState<ProviderDraft>();

  if (account.loading) return <p>Loading identity providers…</p>;
  if (account.error) return <Failure message={account.error} retry={account.reload} />;

  // SSO configured once, server-wide, via startup config (auth0/okta/
  // keycloak/…) rather than the per-connector embedded-IdP API this page
  // otherwise manages -- see the embedded_idp_enabled comment in api.ts.
  if (!embeddedIdpEnabled) {
    return <section>
      <h2>Identity providers</h2>
      <p className="lede">This deployment signs people in through a single external identity provider configured on the coordination server at startup, not here — a console that pretended to own it would be editing a file it cannot read. See <code>management.json</code> and the getting-started guide. This page manages identity-provider connectors only for deployments using Karst's embedded identity provider.</p>
    </section>;
  }

  const save = async () => {
    if (!draft) return;
    const name = draft.name.trim();
    const clientId = draft.client_id.trim();
    const issuer = hasBuiltInIssuer(draft.type) ? "" : draft.issuer.trim();
    if (!name) { setMessage("Name is required."); return; }
    if (!clientId) { setMessage("Client ID is required."); return; }
    if (!hasBuiltInIssuer(draft.type) && !issuer) { setMessage("Issuer URL is required for this provider type."); return; }
    const payload = { type: draft.type, name, issuer, client_id: clientId, client_secret: draft.client_secret };
    const id = draft.id;
    const op = id ? () => api.updateIdentityProvider(id, payload) : () => api.createIdentityProvider(payload);
    if (await run(op, `${name} was ${id ? "updated" : "added"}.`)) setDraft(undefined);
  };

  const remove = (provider: IdentityProvider) => {
    if (!provider.id) return;
    if (!confirm(`Remove ${provider.name}? People who sign in through it will no longer be able to, unless another connector accepts the same identity.`)) return;
    void run(() => api.deleteIdentityProvider(provider.id!), `${provider.name} was removed.`);
  };

  return <section>
    <h2>Identity providers</h2>
    <TutorialHint>Connectors that let people sign in through an external identity provider instead of a local Karst password. Client secrets are never shown again once saved — editing a connector means re-entering its secret.</TutorialHint>
    <div className="actions"><button className="primary" onClick={() => setDraft(blankDraft)}>Add identity provider</button></div>
    <Notice message={message} />
    {providers.loading ? <p>Loading identity providers…</p> : providers.error
      ? <Failure message={providers.error} retry={providers.reload} />
      : (providers.value ?? []).length === 0
        ? <EmptyState title="No identity providers configured">Add one to let people sign in through an external identity provider.</EmptyState>
        : <Rows head={<><th>Name</th><th>Type</th><th>Issuer</th><th>Client ID</th><th>Actions</th></>}>
          {(providers.value ?? []).map((provider) => <tr key={provider.id}>
            <td>{provider.name}</td>
            <td>{providerTypes.find((candidate) => candidate.value === provider.type)?.label ?? provider.type}</td>
            <td>{provider.issuer || <span className="lede">—</span>}</td>
            <td><code>{provider.client_id}</code></td>
            <td><div className="actions">
              <button onClick={() => setDraft(draftFor(provider))}>Edit</button>
              <button className="danger" onClick={() => remove(provider)}>Remove</button>
            </div></td>
          </tr>)}
        </Rows>}

    <Dialog open={Boolean(draft)} title={draft?.id ? `Edit ${draft.name}` : "Add identity provider"} onClose={() => setDraft(undefined)}>
      <form onSubmit={(event) => { event.preventDefault(); void save(); }}>
        <label>Type<select aria-label="Identity provider type" value={draft?.type ?? "oidc"} disabled={Boolean(draft?.id)} onChange={(event) => setDraft((current) => current && { ...current, type: event.target.value as IdentityProviderType })}>
          {providerTypes.map((type) => <option key={type.value} value={type.value}>{type.label}</option>)}
        </select></label>
        <label>Name<input aria-label="Identity provider name" placeholder="Corporate SSO" value={draft?.name ?? ""} onChange={(event) => setDraft((current) => current && { ...current, name: event.target.value })} /></label>
        {draft && !hasBuiltInIssuer(draft.type) &&
          <label>Issuer URL<input aria-label="Identity provider issuer URL" placeholder="https://login.example.com" value={draft.issuer} onChange={(event) => setDraft((current) => current && { ...current, issuer: event.target.value })} /></label>}
        <label>Client ID<input aria-label="Identity provider client ID" value={draft?.client_id ?? ""} onChange={(event) => setDraft((current) => current && { ...current, client_id: event.target.value })} /></label>
        <label>Client secret<input aria-label="Identity provider client secret" type="password" placeholder={draft?.id ? "Re-enter to keep this connector working" : undefined} value={draft?.client_secret ?? ""} onChange={(event) => setDraft((current) => current && { ...current, client_secret: event.target.value })} /></label>
        {draft?.id && <p className="lede">Not shown for security once saved. Re-entering it is required — leaving it blank clears it.</p>}
        <div className="actions"><button type="button" onClick={() => setDraft(undefined)}>Cancel</button><button className="primary" type="submit">{draft?.id ? "Save identity provider" : "Add identity provider"}</button></div>
      </form>
    </Dialog>
  </section>;
}
