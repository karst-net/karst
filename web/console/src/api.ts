// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import type { EnrollmentMetadata, EnrollmentGrant } from "@karst-net/ui";

import type { AllowedRegion, AuditPage, AvenInventory, BedrockStatus, BillingPayment, BillingPaymentNoticeFeed, ComplianceDraftPreview, ComplianceDraftValidation, ComplianceDraftVersion, ComplianceDraftVersionPage, ComplianceDraftWrite, DeviceUsageReport, DiscoveredResource, Estavelle, EstavelleAlertFeed, EstavelleAllocation, EstavelleCap, EstavelleCapDraft, EstavelleLocation, EstavellePublication, EstavelleService, EstavelleServiceView, EstavelleUsageReport, FirstRunState, GroupLocation, InfrastructureConnection, InfrastructureConnectionCreate, InfrastructureConnectionLaunchDefaults, InfrastructureConnectionNomadLaunchDefaults, InfrastructureConnectionKubernetesLaunchDefaults, Location as NocLocation, LocationCreate, NocComponent, NodeCompliance, NodePage, PolicyPreview, PolicyTestResult, PolicyValidation, PolicyVersion, PolicyVersionPage, PostureAggregate, RolloutComponent, RolloutPlan, ScalerRecommendations, SessionPage, TutorialMode } from "@karst-net/api-client";
import { authenticatedFetch } from "./auth";

const base = "/api/karst/v1";

/** Carries the parsed error body, because the useful part of a 409 is not its message. */
export class ApiError extends Error {
  constructor(message: string, readonly status: number, readonly body: Record<string, unknown>) { super(message); this.name = "ApiError"; }
  get code() { return typeof this.body.code === "string" ? this.body.code : undefined; }
  /** The set PUT /bedrock/mode requires be acknowledged, present on an acknowledgment_mismatch. */
  get requiredCutOff() { return Array.isArray(this.body.required_cut_off_handles) ? this.body.required_cut_off_handles as string[] : undefined; }
}

// One transport for both APIs. The management endpoints used to throw a bare
// Error, which meant a 409 from a group rename arrived at the view with its
// status discarded — indistinguishable from a network failure, and impossible
// to recover from precisely. Everything throws ApiError now.
//
// The shared transport renews expired sessions before sending requests and
// redirects to login when renewal fails or the renewed token is rejected.
async function http<T>(url: string, init?: RequestInit, observe?: (response: Response) => void): Promise<T> {
  const headers = new Headers(init?.headers);
  if (!headers.has("content-type")) headers.set("content-type", "application/json");
  const response = await authenticatedFetch(url, { ...init, headers });
  if (!response.ok) {
    const error = await response.json().catch(() => ({ message: response.statusText })) as Record<string, unknown>;
    throw new ApiError(typeof error.message === "string" ? error.message : "The server rejected this request.", response.status, error);
  }
  observe?.(response);
  return response.status === 204 ? undefined as T : response.json() as Promise<T>;
}

// ADR-0037: which account a request should be scoped to, when the caller
// has switched away from their own. Both APIs ride the fork's shared auth
// middleware, which reads this same ?account= parameter generically -- it is
// not a karst-specific mechanism, so both request() and management() apply
// it. Per-tab, not persisted account-to-account: a stale override surviving
// into a new session (a different login) would silently scope that
// session's requests to whatever account a previous user last switched
// into, which sessionStorage's tab-lifetime avoids.
const activeAccountKey = "karst.activeAccount";

export function getActiveAccountOverride(): string | null {
  try { return sessionStorage.getItem(activeAccountKey); } catch { return null; }
}

export function setActiveAccountOverride(accountId: string | null) {
  try {
    if (accountId) sessionStorage.setItem(activeAccountKey, accountId);
    else sessionStorage.removeItem(activeAccountKey);
  } catch { /* per-viewer convenience only -- a blocked/unavailable sessionStorage just means no override */ }
}

function withAccountOverride(path: string): string {
  const account = getActiveAccountOverride();
  if (!account) return path;
  return `${path}${path.includes("?") ? "&" : "?"}account=${encodeURIComponent(account)}`;
}

const request = <T>(path: string, init?: RequestInit) => http<T>(`${base}${withAccountOverride(path)}`, init);
const management = <T>(path: string, init?: RequestInit) => http<T>(`/api${withAccountOverride(path)}`, init);
const body = (value: unknown) => JSON.stringify(value);

function auditExport(format: "json"): Promise<AuditPage["items"]>;
function auditExport(format: "csv"): Promise<string>;
async function auditExport(format: "json" | "csv"): Promise<AuditPage["items"] | string> {
  const path = `/audit/export?format=${format}`;
  if (format === "json") return request<AuditPage["items"]>(path);
  const response = await authenticatedFetch(`${base}${withAccountOverride(path)}`, { headers: { accept: "text/csv" } });
  if (!response.ok) {
    const error = await response.json().catch(() => ({ message: response.statusText })) as Record<string, unknown>;
    throw new ApiError(typeof error.message === "string" ? error.message : "The server rejected this request.", response.status, error);
  }
  return response.text();
}

// ── the fork's resources ─────────────────────────────────────────────────────
// These live on the management API rather than /karst/v1. Karst owns nodes,
// policy, relays, Bedrock, posture and audit; users, groups, routes and
// nameservers are the fork's and are reused as they are (ADR-0009).

export type DeviceInvitation = {
  id: string; name: string; groups: string[];
  state: "pending" | "redeemed" | "expired" | "revoked";
  expires_at: string; created_at: string; redeemed_at?: string; credential?: string;
  /** The mesh domain (ADR-0032) the enrolling device will be placed in, or absent for the account root. */
  domain_id?: string;
  assigned_user_id?: string; reusable?: boolean; usage_limit?: number; used_times?: number;
};

// A mesh domain (ADR-0032) an admin can place devices into, and organize
// into subdomains. Deliberately not called "zone" (the fork's own DNS zones
// are a different, unrelated feature) or "aquifer" (the relay's own,
// unrelated tenant-isolation concept) — see the ADR for why.
export type MeshDomain = { id: string; parent_id?: string; label: string; path: string; is_root?: boolean; dns_suffix?: string; dns_name?: string; naming_revision?: number };
export type RootRenamePreview = { root_id: string; old_suffix: string; new_suffix: string; revision: string; naming_revision: number; device_count: number; domain_count: number; examples: { before: string; after: string }[]; committed: boolean; convergence: "unobserved" };

// Grants user_id delegated admin rights over domain_id and everything under
// it, without any account-wide role. domain_path is included so the console
// can show what subtree a delegation covers without a second lookup.
export type DomainDelegation = { id: string; domain_id: string; domain_path: string; user_id: string };

export type AccountUser = { id: string; name: string; email: string; role: string; status: string; is_current?: boolean; is_blocked: boolean; auto_groups?: string[]; issued?: string; last_login?: string | null };

export type ManagedEstavelleService = EstavelleService & { access_managed?: boolean; allowed_groups?: string[]; gateway_handle?: string; exit_ipv4?: boolean; exit_ipv6?: boolean; metric?: number; revision?: number };
/** The writable fields of an EstavelleAllocation — everything else on that
 * type (state, revision, failed_step, …) is server-derived and never
 * accepted from callers (karst-openapi.yml's own `readonly` markings). */
export type EstavelleAllocationDraft = { name: string; infra_connection_id: string; location: string; relay_transport: boolean; permitted_groups: string[] };

/** The writable fields of a RolloutComponent/RolloutPlan — status, observed_digest,
 * compatibility, etc. are server-derived (karst-openapi.yml's own `readOnly`
 * markings) and never accepted from callers. ADR-0066/#484. */
export type RolloutComponentDraft = Pick<RolloutComponent, "name" | "sequence" | "current_digest" | "target_digest" | "verification_ref" | "requires_relay_lifecycle_schema" | "requires_gateway_ingress_schema">;
export type RolloutPlanDraft = { target_release: string; maintenance_window_note?: string; components: RolloutComponentDraft[] };
export type Group = { id: string; name: string; peers_count: number; resources_count: number; issued?: string; peers?: Array<{ id: string; name: string }>; resources?: Array<{ id: string; type: string }> };

export type GroupSnapshot = { group: Group; revision: string };

export type Nameserver = { ip: string; ns_type: "udp"; port: number };
export type NameserverGroup = { id: string; name: string; description: string; nameservers: Nameserver[]; enabled: boolean; groups: string[]; primary: boolean; domains: string[]; search_domains_enabled: boolean };
export type NameserverGroupDraft = Omit<NameserverGroup, "id">;

export type NetworkRoute = { id: string; network_id: string; description: string; enabled: boolean; network: string; peer_groups: string[]; groups: string[]; access_control_groups: string[]; metric: number; masquerade: boolean; keep_route: boolean; skip_auto_apply: boolean; dns_zone?: string; pinned_egress_ip?: string };
export type NetworkRouteDraft = Omit<NetworkRoute, "id">;

export type Token = { id: string; name: string; expiration_date: string; created_at: string; last_used?: string | null; plain_token?: string };

export type DnsSettings = { disabled_management_groups: string[] };

// Only the identifying fields the console actually shows, plus
// embedded_idp_enabled -- the one settings field read outside Settings
// itself, since it decides whether identity-provider connectors are
// console-managed (see identity-providers.tsx) or purely server startup
// configuration (Settings' own note). The fork's own `Account` also carries
// a large settings blob (peer login expiration, DNS, JWT groups, …) that is
// not part of Karst's product surface here, so nothing else from that blob
// belongs on these pages even though the endpoint returns it.
export type Account = { id: string; domain: string; created_at: string; created_by: string; embedded_idp_enabled?: boolean };

export type IdentityProviderType = "oidc" | "zitadel" | "entra" | "google" | "okta" | "pocketid" | "microsoft" | "authentik" | "keycloak" | "adfs";
export type IdentityProvider = { id?: string; type: IdentityProviderType; name: string; issuer: string; client_id: string };
/** client_secret is required on every write: the server never returns a
 * stored secret back (IdentityProvider omits it entirely), so there is
 * nothing to preserve client-side on an edit -- re-entering the secret is
 * mandatory, not optional, because the server overwrites it with whatever
 * is sent, blank included. */
export type IdentityProviderDraft = { type: IdentityProviderType; name: string; issuer: string; client_id: string; client_secret: string };

export type BedrockLogEntry = { sequence: number; op: string; tier: string; subject: string; signed_at: string; signers: string[] };
/** An offline signing bundle is intentionally opaque to the console: it is
 * created and signed by the Bedrock CLI, not interpreted or signed here. */
export type BedrockRequest = { id: string; created_at: string; payload_hash: string };
export type BedrockBundle = { format: "bedrock-signed-bundle-v1"; payload: string };
export type BedrockBootstrapBundle = { format: "bedrock-log-v1"; payload: string };

export type SoftwareVersions = {
  control: { version: string; revision: string; artifact_id?: string };
  observed_at?: string;
  deployment_status: "available" | "not_configured" | "unavailable";
  deployment?: { observed_at: string; components: { name: string; image: string; image_id: string; version?: string | null; revision?: string | null; tags: string[]; state: string }[] };
};

export const api = {
  softwareVersions: () => request<SoftwareVersions>("/versions"),
  // ── managed billing ───────────────────────────────────────────────────────
  deviceUsage: (start: string, end: string) => request<DeviceUsageReport>(`/usage/devices?start=${encodeURIComponent(start)}&end=${encodeURIComponent(end)}`),
  estavelleUsage: (start: string, end: string) => request<EstavelleUsageReport>(`/usage/estavelles?start=${encodeURIComponent(start)}&end=${encodeURIComponent(end)}`),
  estavelleAlerts: (period: string) => request<EstavelleAlertFeed>(`/usage/estavelle-alerts?period=${encodeURIComponent(period)}`),
  billingPayment: (period: string) => request<BillingPayment>(`/billing/payments?period=${encodeURIComponent(period)}`),
  billingPaymentNotices: (period: string) => request<BillingPaymentNoticeFeed>(`/billing/payment-notices?period=${encodeURIComponent(period)}`),
  queueBillingPayment: (period: string) => request<BillingPayment>(`/billing/payments?period=${encodeURIComponent(period)}`, { method: "POST" }),
  estavelleCap: (period: string) => request<EstavelleCap>(`/billing/estavelle-cap?period=${encodeURIComponent(period)}`),
  setEstavelleCap: (draft: EstavelleCapDraft) => request<EstavelleCap>("/billing/estavelle-cap", { method: "PUT", body: body(draft) }),

  invitations: () => request<DeviceInvitation[]>("/invitations"),
  // domainId places the enrolling device in that mesh domain (ADR-0032)
  // rather than the account's implicit root; omit it for prior behavior.
  createInvitation: (name: string, groups: string[], domainId: string, forUserId: string, options?: { reusable: boolean; usageLimit: number }) => request<DeviceInvitation>("/invitations", { method: "POST", body: body({ name, groups, domain_id: domainId || undefined, for_user_id: forUserId, reusable: options?.reusable, usage_limit: options?.usageLimit }) }),
  revokeInvitation: (id: string) => request<DeviceInvitation>(`/invitations/${encodeURIComponent(id)}/revoke`, { method: "POST" }),

  // ── mesh domains ───────────────────────────────────────────────────────────
  domains: () => request<MeshDomain[]>("/domains"),
  previewRootRename: (suffix: string) => request<RootRenamePreview>("/domains/root/rename/preview", { method: "POST", body: body({ dns_suffix: suffix }) }),
  commitRootRename: (preview: RootRenamePreview) => request<RootRenamePreview>("/domains/root/rename/commit", { method: "POST", body: body({ dns_suffix: preview.new_suffix, revision: preview.revision, confirm_no_aliases: true }) }),
  // parentId "" creates a top-level domain.
  createDomain: (parentId: string, label: string) => request<MeshDomain>("/domains", { method: "POST", body: body({ parent_id: parentId, label }) }),
  deleteDomain: (id: string) => request<void>(`/domains/${encodeURIComponent(id)}`, { method: "DELETE" }),
  domainDelegations: (domainId: string) => request<DomainDelegation[]>(`/domains/${encodeURIComponent(domainId)}/delegations`),
  delegateDomain: (domainId: string, userId: string) => request<DomainDelegation>(`/domains/${encodeURIComponent(domainId)}/delegations`, { method: "POST", body: body({ user_id: userId }) }),
  revokeDomainDelegation: (bindingId: string) => request<void>(`/domains/delegations/${encodeURIComponent(bindingId)}`, { method: "DELETE" }),
  enrollmentMetadata: () => request<EnrollmentMetadata>("/me/enrollment"),
  enroll: () => request<EnrollmentGrant>("/me/devices/enroll", { method: "POST" }),
  // ── machines ───────────────────────────────────────────────────────────────
  nodes: (cursor?: string) => request<NodePage>(`/nodes?limit=100${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`),
  node: (handle: string) => request<NodePage["items"][number]>(`/nodes/${encodeURIComponent(handle)}`),
  nodePaths: (handle: string) => request<{ observed_at: string; paths: Array<{ peer_handle: string; kind: string; endpoint: string | null; relay_id: string | null; since: string | null; observed_at: string; tx_bytes: number; rx_bytes: number }> }>(`/nodes/${encodeURIComponent(handle)}/paths`),
  // ADR-0055: self-reported device evidence only, no pass/fail verdict.
  nodeCompliance: (handle: string) => request<NodeCompliance>(`/nodes/${encodeURIComponent(handle)}/compliance`),
  // Only name and domain_id (ADR-0032). The contract rejects a PATCH
  // carrying tags, expiry or enabled with "only name and domain_id are
  // currently mutable for a Karst node", so the console offers exactly
  // what the server accepts rather than a form that fails on save.
  renameNode: (handle: string, name: string) => request<NodePage["items"][number]>(`/nodes/${encodeURIComponent(handle)}`, { method: "PATCH", body: body({ name }) }),
  // Use the root domain ID to move a machine back to the account root.
  setNodeDomain: (handle: string, domainId: string) => request<NodePage["items"][number]>(`/nodes/${encodeURIComponent(handle)}`, { method: "PATCH", body: body({ domain_id: domainId }) }),
  deprovision: (handle: string) => request<void>(`/nodes/${encodeURIComponent(handle)}`, { method: "DELETE" }),

  // ── access policy ──────────────────────────────────────────────────────────
  policy: () => request<PolicyVersion>("/policy"),
  policyVersions: () => request<PolicyVersionPage>("/policy/versions?limit=100"),
  policyVersion: (version: number) => request<PolicyVersion>(`/policy/versions/${version}`),
  validate: (document: string) => request<PolicyValidation>("/policy/validate", { method: "POST", body: body({ document }) }),
  preview: (document: string) => request<PolicyPreview>("/policy/preview", { method: "POST", body: body({ document }) }),
  testPolicy: (document: string) => request<{ passed: boolean; results: Array<{ name: string; passed: boolean; message: string }> }>("/policy/test", { method: "POST", body: body({ document }) }),
  // A JSON Schema (2020-12) describing the policy document shape, for the
  // editor's autocomplete and inline lint. Static per server version, not
  // per account — safe to fetch once and keep for the life of the view.
  policySchema: () => request<Record<string, unknown>>("/policy/schema"),
  savePolicy: (document: string, version: number) => request<PolicyVersion>("/policy", { method: "PUT", headers: { "if-match": String(version) }, body: body({ document }) }),
  rollbackPolicy: (version: number, currentVersion: number) => request<PolicyVersion>(`/policy/rollback/${version}`, { method: "POST", headers: { "if-match": String(currentVersion) } }),

  // ── compliance guardrails (ADR-0055, #363) ──────────────────────────────────
  complianceDraft: () => request<ComplianceDraftVersion>("/compliance/draft"),
  complianceDraftVersions: () => request<ComplianceDraftVersionPage>("/compliance/draft/versions?limit=100"),
  complianceDraftVersion: (version: number) => request<ComplianceDraftVersion>(`/compliance/draft/versions/${version}`),
  validateComplianceDraft: (draft: ComplianceDraftWrite) => request<ComplianceDraftValidation>("/compliance/draft/validate", { method: "POST", body: body(draft) }),
  previewComplianceDraft: (draft: ComplianceDraftWrite) => request<ComplianceDraftPreview>("/compliance/draft/preview", { method: "POST", body: body(draft) }),
  testComplianceDraft: (draft: ComplianceDraftWrite) => request<PolicyTestResult>("/compliance/draft/test", { method: "POST", body: body(draft) }),
  saveComplianceDraft: (draft: ComplianceDraftWrite, version: number) => request<ComplianceDraftVersion>("/compliance/draft", { method: "PUT", headers: { "if-match": String(version) }, body: body(draft) }),
  rollbackComplianceDraft: (version: number, currentVersion: number) => request<ComplianceDraftVersion>(`/compliance/draft/rollback/${version}`, { method: "POST", headers: { "if-match": String(currentVersion) } }),

  // ── network lock ───────────────────────────────────────────────────────────
  bedrock: () => request<BedrockStatus>("/bedrock"),
  setBedrock: (mode: "off" | "advisory" | "enforcing", handles: string[]) => request<BedrockStatus>("/bedrock/mode", { method: "PUT", body: body({ mode, acknowledged_cut_off_handles: handles }) }),
  bedrockLog: () => request<{ items: BedrockLogEntry[]; next_cursor: string | null }>("/bedrock/log?limit=100"),
  bedrockRequests: () => request<BedrockRequest[]>("/bedrock/requests"),
  exportBedrockRequest: () => request<BedrockBundle>("/bedrock/requests/export", { method: "POST" }),
  exportAuditAnchor: () => request<BedrockBundle>("/bedrock/audit-anchor/export", { method: "POST" }),
  importBedrockResponse: (bundle: BedrockBundle) => request<void>("/bedrock/responses/import", { method: "POST", body: body(bundle) }),
  importBedrockBootstrap: (bundle: BedrockBootstrapBundle) => request<void>("/bedrock/bootstrap/import", { method: "POST", body: body(bundle) }),

  // ── posture, audit ─────────────────────────────────────────────────────────
  posture: () => request<PostureAggregate>("/posture"),
  sessions: () => request<SessionPage>("/posture/sessions?limit=200"),
  audit: (filters: { actor?: string; action?: string } = {}) => {
    const query = new URLSearchParams({ limit: "100" });
    if (filters.actor) query.set("actor", filters.actor);
    if (filters.action) query.set("action", filters.action);
    return request<AuditPage>(`/audit?${query}`);
  },
  auditVerify: () => request<{ valid: boolean; first_bad_sequence: number | null; head: { sequence: number; hash: string } }>("/audit/verify"),
  auditExport,
  addAuditSink: (kind: string, endpoint: string) => request<{ id: string; kind: string; endpoint: string }>("/audit/sinks", { method: "POST", body: body({ kind, endpoint }) }),
  auditSinks: () => request<Array<{ id: string; kind: string; endpoint: string }>>("/audit/sinks"),
  removeAuditSink: (id: string) => request<void>(`/audit/sinks/${encodeURIComponent(id)}`, { method: "DELETE" }),

  // ── estavelles ─────────────────────────────────────────────────────────────
  estavellePublication: () => request<EstavellePublication>("/estavelle-services/publication"),
  previewEstavellePublication: () => request<EstavelleService[]>("/estavelle-services/publication/preview", { method: "POST" }),
  setEstavellePublication: (mode: EstavellePublication["mode"]) => request<EstavellePublication>("/estavelle-services/publication", { method: "PUT", body: body({ mode, acknowledge_connectivity_change: true }) }),
  setEstavelleServiceModes: (id: string, ponorEnabled: boolean) => request<EstavelleService>(`/estavelle-services/${encodeURIComponent(id)}/modes`, { method: "PUT", body: body({ ponor_enabled: ponorEnabled, acknowledge_connectivity_change: true }) }),
  estavelleServices: () => request<Array<EstavelleServiceView & ManagedEstavelleService>>("/estavelle-services"),
  addEstavelleService: (service: ManagedEstavelleService) => request<EstavelleService>("/estavelle-services", { method: "POST", body: body(service) }),
  estavelleAdmissionTargets: () => request<Array<{ relay_id: string; refreshed_at: string }>>("/estavelle-services/admission-targets"),
  setEstavelleAccess: (service: ManagedEstavelleService) => request<ManagedEstavelleService>(`/estavelle-services/${encodeURIComponent(service.id)}/access`, { method: "PUT", body: body({ ...service, acknowledge_access_change: true }) }),
  removeEstavelleService: (id: string) => request<void>(`/estavelle-services/${encodeURIComponent(id)}`, { method: "DELETE" }),
  estavelles: () => request<Estavelle[]>("/estavelles"),
  addEstavelle: (entry: { address: string; tls_server_name: string; identity_key: string; region: string; location?: EstavelleLocation }) => request<Estavelle>("/estavelles", { method: "POST", body: body(entry) }),
  removeEstavelle: (id: string) => request<void>(`/estavelles/${encodeURIComponent(id)}`, { method: "DELETE" }),

  // ── estavelle allocation (ADR-0063, #455) ───────────────────────────────────
  estavelleAllocations: () => request<EstavelleAllocation[]>("/estavelle-allocations"),
  allocateEstavelle: (draft: EstavelleAllocationDraft) => request<EstavelleAllocation>("/estavelle-allocations", { method: "POST", body: body(draft) }),
  deprovisionEstavelleAllocation: (id: string, revision: number) => request<EstavelleAllocation>(`/estavelle-allocations/${encodeURIComponent(id)}/deprovision`, { method: "POST", body: body({ revision, acknowledge_deprovision: true }) }),
  deleteEstavelleAllocation: (id: string, revision: number) => request<void>(`/estavelle-allocations/${encodeURIComponent(id)}?revision=${revision}`, { method: "DELETE" }),

  // ── component rollout (ADR-0066, #484) ──────────────────────────────────────
  // Control only computes/tracks/verifies-by-attestation here; it never calls
  // Nomad, a registry, or cosign itself. The operator still runs the
  // documented deploy/nomad/prod/README.md steps by hand and tells control
  // which step they completed.
  rollouts: () => request<RolloutPlan[]>("/rollouts"),
  rollout: (id: string) => request<RolloutPlan>(`/rollouts/${encodeURIComponent(id)}`),
  createRollout: (draft: RolloutPlanDraft) => request<RolloutPlan>("/rollouts", { method: "POST", body: body(draft) }),
  startRollout: (id: string, revision: number, acknowledge: boolean, overrideIncompatibility: boolean, maintenanceWindowNote?: string) =>
    request<RolloutPlan>(`/rollouts/${encodeURIComponent(id)}/start`, { method: "POST", body: body({ revision, acknowledge, override_incompatibility: overrideIncompatibility, maintenance_window_note: maintenanceWindowNote }) }),
  markRolloutComponentApplied: (id: string, name: string, revision: number) =>
    request<RolloutPlan>(`/rollouts/${encodeURIComponent(id)}/components/${encodeURIComponent(name)}/mark-applied`, { method: "POST", body: body({ revision }) }),
  markRolloutComponentFailed: (id: string, name: string, revision: number, reason: string) =>
    request<RolloutPlan>(`/rollouts/${encodeURIComponent(id)}/components/${encodeURIComponent(name)}/mark-failed`, { method: "POST", body: body({ revision, reason }) }),
  rollBackRollout: (id: string, revision: number, reason?: string) =>
    request<RolloutPlan>(`/rollouts/${encodeURIComponent(id)}/rollback`, { method: "POST", body: body({ revision, acknowledge_rollback: true, reason }) }),
  deleteRollout: (id: string, revision: number) => request<void>(`/rollouts/${encodeURIComponent(id)}?revision=${revision}`, { method: "DELETE" }),

  // ── NOC view (#241 Phase 1a, ADR-0046/ADR-0047, extended to ADR-0046 §1's
  // full component list) ──────────────────────────────────────────────────
  // nocComponents is audit-logged server-side on every request, since it's a
  // GET the console's generic mutation-audit middleware never sees.
  nocComponents: () => request<NocComponent[]>("/noc/components"),
  nocEstavelle: (id: string) => request<Estavelle>(`/noc/estavelles/${encodeURIComponent(id)}`),

  // ── NOC map: admin-authorized "possible locations" registry ────────────────
  // Additive, not a foreign key -- see locationreg's own doc comment. These
  // are the hollow/empty markers the map draws whether or not anything is
  // deployed there yet.
  locations: () => request<NocLocation[]>("/locations"),
  addLocation: (entry: LocationCreate) => request<NocLocation>("/locations", { method: "POST", body: body(entry) }),
  removeLocation: (id: string) => request<void>(`/locations/${encodeURIComponent(id)}`, { method: "DELETE" }),

  // ── NOC map: a route gateway group's declared location ─────────────────────
  // What places an exit-node/subnet-router marker -- a route only ever names
  // peer_groups, never a single machine, so the location is declared on the
  // group, not the route (see package grouplocation's own doc comment).
  groupLocations: () => request<GroupLocation[]>("/group-locations"),
  setGroupLocation: (groupId: string, entry: { lat: number; lon: number; label?: string }) => request<GroupLocation>(`/group-locations/${encodeURIComponent(groupId)}`, { method: "PUT", body: body(entry) }),
  removeGroupLocation: (groupId: string) => request<void>(`/group-locations/${encodeURIComponent(groupId)}`, { method: "DELETE" }),

  // ── NOC map: the control plane's own declared location ─────────────────────
  controlPlaneLocation: () => request<EstavelleLocation | undefined>("/control-plane/location"),
  setControlPlaneLocation: (entry: { lat: number; lon: number; label?: string }) => request<EstavelleLocation>("/control-plane/location", { method: "PUT", body: body(entry) }),

  // ── NOC map: Bedrock's own declared location ────────────────────────────────
  setBedrockLocation: (entry: { lat: number; lon: number; label?: string }) => request<EstavelleLocation>("/bedrock/location", { method: "PUT", body: body(entry) }),

  // ── scaler advisor (ADR-0045 §7 Phase 1) ───────────────────────────────────
  // Audit-logged server-side on every request, same as nocComponents/
  // demandRegions/demandAnchors above, since it's a GET the console's
  // generic mutation-audit middleware never sees.
  scalerRecommendations: () => request<ScalerRecommendations>("/scaler/recommendations"),
  allowedRegions: () => request<AllowedRegion[]>("/regions"),
  addAllowedRegion: (entry: AllowedRegion) => request<AllowedRegion>("/regions", { method: "POST", body: body(entry) }),
  removeAllowedRegion: (provider: string, region: string) => request<void>(`/regions/${encodeURIComponent(provider)}/${encodeURIComponent(region)}`, { method: "DELETE" }),

  // ── users ──────────────────────────────────────────────────────────────────
  users: () => management<AccountUser[]>("/users"),
  currentUser: () => management<AccountUser>("/users/current"),
  updateUser: (id: string, changes: { role: string; is_blocked: boolean; auto_groups: string[] }) => management<AccountUser>(`/users/${encodeURIComponent(id)}`, { method: "PUT", body: body(changes) }),
  deprovisionUser: (id: string) => management<void>(`/users/${encodeURIComponent(id)}`, { method: "DELETE" }),

  // ── identity providers ────────────────────────────────────────────────────
  // Only meaningful when the account's embedded_idp_enabled is true (see
  // identity-providers.tsx) -- create/update/delete 500 on the server, and
  // list silently returns [], when this deployment instead uses a single
  // external identity provider configured at startup.
  identityProviders: () => management<IdentityProvider[]>("/identity-providers"),
  createIdentityProvider: (draft: IdentityProviderDraft) => management<IdentityProvider>("/identity-providers", { method: "POST", body: body(draft) }),
  updateIdentityProvider: (id: string, draft: IdentityProviderDraft) => management<IdentityProvider>(`/identity-providers/${encodeURIComponent(id)}`, { method: "PUT", body: body(draft) }),
  deleteIdentityProvider: (id: string) => management<void>(`/identity-providers/${encodeURIComponent(id)}`, { method: "DELETE" }),

  // ── organization ───────────────────────────────────────────────────────────
  // The fork's endpoint is plural (`getAllAccounts`) but scopes to the
  // caller's own account and always returns exactly one — see accounts_handler.go.
  // Whichever account is currently in effect, home or a switched-into one —
  // withAccountOverride carries it here the same as everywhere else.
  account: () => management<Account[]>("/accounts").then((accounts) => accounts[0]),

  // ── tenancy (ADR-0037) ─────────────────────────────────────────────────────
  // The caller's own operator-granted accounts — never affected by
  // withAccountOverride, since /me/tenancy-accounts answers from the JWT
  // identity, not from whichever account a request happens to be scoped to.
  accessibleAccounts: () => request<{ account_id: string }[]>("/me/tenancy-accounts"),

  // ── groups ─────────────────────────────────────────────────────────────────
  groups: () => management<Group[]>("/groups"),
  createGroup: (name: string) => management<Group>("/groups", { method: "POST", body: body({ name, peers: [] }) }),
  group: (id: string) => management<Group>(`/groups/${encodeURIComponent(id)}`),
  groupPeers: () => management<Array<{ id: string; name: string }>>("/peers"),
  groupForEdit: async (id: string): Promise<GroupSnapshot> => {
    let revision: string | null = null;
    const group = await http<Group>(`/api${withAccountOverride(`/groups/${encodeURIComponent(id)}`)}`, undefined, response => { revision = response.headers.get("ETag"); });
    if (!revision) throw new Error("This server does not support safe group edits. Upgrade the control server before changing membership or names.");
    return { group, revision };
  },
  renameGroup: (snapshot: GroupSnapshot, name: string) => management<Group>(`/groups/${encodeURIComponent(snapshot.group.id)}`, { method: "PUT", headers: { "If-Match": snapshot.revision }, body: body({ name, peers: snapshot.group.peers?.map(peer => peer.id) ?? [], resources: snapshot.group.resources ?? [] }) }),
  setGroupMembers: (snapshot: GroupSnapshot, peers: string[]) => management<Group>(`/groups/${encodeURIComponent(snapshot.group.id)}`, { method: "PUT", headers: { "If-Match": snapshot.revision }, body: body({ name: snapshot.group.name, peers, resources: snapshot.group.resources ?? [] }) }),
  deleteGroup: (id: string) => management<void>(`/groups/${encodeURIComponent(id)}`, { method: "DELETE" }),

  // ── DNS ────────────────────────────────────────────────────────────────────
  dnsSettings: () => management<DnsSettings>("/dns/settings"),
  saveDnsSettings: (disabled_management_groups: string[]) => management<DnsSettings>("/dns/settings", { method: "PUT", body: body({ disabled_management_groups }) }),
  nameservers: () => management<NameserverGroup[]>("/dns/nameservers"),
  createNameserverGroup: (draft: NameserverGroupDraft) => management<NameserverGroup>("/dns/nameservers", { method: "POST", body: body(draft) }),
  updateNameserverGroup: (id: string, draft: NameserverGroupDraft) => management<NameserverGroup>(`/dns/nameservers/${encodeURIComponent(id)}`, { method: "PUT", body: body(draft) }),
  deleteNameserverGroup: (id: string) => management<void>(`/dns/nameservers/${encodeURIComponent(id)}`, { method: "DELETE" }),

  // ── network routes ─────────────────────────────────────────────────────────
  avens: async () => {
    const inventory = await request<AvenInventory>("/avens");
    if (inventory.schema_version !== 1) throw new Error("Unsupported Aven inventory schema; upgrade the console before using this view.");
    return inventory;
  },
  routes: () => management<NetworkRoute[]>("/routes"),
  createRoute: (draft: NetworkRouteDraft) => management<NetworkRoute>("/routes", { method: "POST", body: body(draft) }),
  updateRoute: (id: string, draft: NetworkRouteDraft) => management<NetworkRoute>(`/routes/${encodeURIComponent(id)}`, { method: "PUT", body: body(draft) }),
  deleteRoute: (id: string) => management<void>(`/routes/${encodeURIComponent(id)}`, { method: "DELETE" }),

  // ── personal access tokens ─────────────────────────────────────────────────
  tokens: (userId: string) => management<Token[]>(`/users/${encodeURIComponent(userId)}/tokens`),
  createToken: (userId: string, name: string, expires_in: number) => management<{ plain_token: string; personal_access_token: Token }>(`/users/${encodeURIComponent(userId)}/tokens`, { method: "POST", body: body({ name, expires_in }) }),
  deleteToken: (userId: string, id: string) => management<void>(`/users/${encodeURIComponent(userId)}/tokens/${encodeURIComponent(id)}`, { method: "DELETE" }),

  // ── first-run setup wizard ───────────────────────────────────────────────────
  firstRunState: () => request<FirstRunState>("/firstrun"),
  completeFirstRun: () => request<FirstRunState>("/firstrun/complete", { method: "POST" }),

  // ── guidance-text ("tutorial mode") setting ─────────────────────────────────
  tutorialMode: () => request<TutorialMode>("/tutorial-mode"),
  setTutorialMode: (enabled: boolean) => request<TutorialMode>("/tutorial-mode", { method: "PUT", body: body({ enabled }) }),

  // ── infrastructure connections (ADR-0045 §6 addenda) ────────────────────────
  // Secrets are never returned by the server -- see infraconnections.Response.
  infrastructureConnections: () => request<InfrastructureConnection[]>("/infrastructure-connections"),
  createInfrastructureConnection: (entry: InfrastructureConnectionCreate) => request<InfrastructureConnection>("/infrastructure-connections", { method: "POST", body: body(entry) }),
  deleteInfrastructureConnection: (id: string) => request<void>(`/infrastructure-connections/${encodeURIComponent(id)}`, { method: "DELETE" }),
  infrastructureConnectionResources: (id: string) => request<DiscoveredResource[]>(`/infrastructure-connections/${encodeURIComponent(id)}/resources`),
  // ADR-0045's 2026-11-04 addendum: the AWS launch shape (AMI/instance
  // type/subnet/security groups) a relay allocation (ADR-0063) actuates
  // against, set once here rather than on the allocation request itself.
  updateInfrastructureConnectionLaunchDefaults: (id: string, defaults: InfrastructureConnectionLaunchDefaults) =>
    request<InfrastructureConnection>(`/infrastructure-connections/${encodeURIComponent(id)}/launch-defaults`, { method: "PUT", body: body(defaults) }),
  // ADR-0067: the Nomad analog -- a pre-registered parameterized job ID
  // and datacenter, same full-replace semantics.
  updateInfrastructureConnectionNomadLaunchDefaults: (id: string, defaults: InfrastructureConnectionNomadLaunchDefaults) =>
    request<InfrastructureConnection>(`/infrastructure-connections/${encodeURIComponent(id)}/nomad-launch-defaults`, { method: "PUT", body: body(defaults) }),
  // ADR-0067: the Kubernetes analog -- image/cpu/memory/service account,
  // same full-replace semantics. Unlike Nomad, there is no pre-registered
  // job: this connection's own driver builds the Pod itself.
  updateInfrastructureConnectionKubernetesLaunchDefaults: (id: string, defaults: InfrastructureConnectionKubernetesLaunchDefaults) =>
    request<InfrastructureConnection>(`/infrastructure-connections/${encodeURIComponent(id)}/kubernetes-launch-defaults`, { method: "PUT", body: body(defaults) }),
  // ADR-0045 §6's second addendum: the one mutating call this API makes --
  // opts an AWS Local Zone's group into use. A one-way door on AWS's side
  // (no opt-out API), so the caller must have already confirmed this with
  // the operator naming this specific zone; this call does not ask again.
  // Still wired only to the legacy /cloud-accounts route server-side (see
  // infraconnections.Store.EnableLocalZone's doc comment) -- connection IDs
  // are shared between both surfaces, so this works against an id/resource
  // obtained from the infrastructureConnections* calls above.
  enableInfrastructureConnectionRegion: (id: string, code: string, parentRegion: string) =>
    request<DiscoveredResource>(`/cloud-accounts/${encodeURIComponent(id)}/regions/${encodeURIComponent(code)}/enable`, { method: "POST", body: body({ parent_region: parentRegion }) }),
};
