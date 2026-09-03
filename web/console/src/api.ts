// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import type { AuditPage, BedrockStatus, NodePage, PolicyPreview, PolicyValidation, PolicyVersion, PolicyVersionPage, PostureAggregate, Relay, SessionPage, TurnServer } from "@karst-net/api-client";
import { accessToken, loadConfig, login, renewOnce } from "./auth";

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
// Every request carries the in-memory access token from src/auth.ts (empty in
// the `just api-mock` dev flow, where OIDC is unconfigured and the mock
// ignores Authorization entirely). A 401 gets one silent-renew attempt — the
// token expired mid-session, not that the user was never authenticated, since
// bootstrap() already turned that case into the login screen — before it
// surfaces as a real error; a second 401 forces a fresh login redirect rather
// than leaving the view stuck retrying against a session that is really gone.
async function authHeaders(init?: RequestInit): Promise<HeadersInit> {
  const token = accessToken();
  return { "content-type": "application/json", ...(token ? { authorization: `Bearer ${token}` } : {}), ...init?.headers };
}

async function http<T>(url: string, init?: RequestInit, retried = false): Promise<T> {
  const response = await fetch(url, { ...init, headers: await authHeaders(init) });
  if (response.status === 401 && !retried) {
    const config = await loadConfig();
    if (config.oidcAuthority && (await renewOnce(config))) return http(url, init, true);
    if (config.oidcAuthority) login(config);
  }
  if (!response.ok) {
    const error = await response.json().catch(() => ({ message: response.statusText })) as Record<string, unknown>;
    throw new ApiError(typeof error.message === "string" ? error.message : "The server rejected this request.", response.status, error);
  }
  return response.status === 204 ? undefined as T : response.json() as Promise<T>;
}

const request = <T>(path: string, init?: RequestInit) => http<T>(`${base}${path}`, init);
const management = <T>(path: string, init?: RequestInit) => http<T>(`/api${path}`, init);
const body = (value: unknown) => JSON.stringify(value);

function auditExport(format: "json"): Promise<AuditPage["items"]>;
function auditExport(format: "csv"): Promise<string>;
async function auditExport(format: "json" | "csv"): Promise<AuditPage["items"] | string> {
  const path = `/audit/export?format=${format}`;
  if (format === "json") return request<AuditPage["items"]>(path);
  const response = await fetch(`${base}${path}`, { headers: { ...(await authHeaders()), accept: "text/csv" } });
  if (!response.ok) {
    const error = await response.json().catch(() => ({ message: response.statusText })) as Record<string, unknown>;
    throw new ApiError(typeof error.message === "string" ? error.message : "The server rejected this request.", response.status, error);
  }
  return response.text();
}

// ── the fork's resources ─────────────────────────────────────────────────────
// These live on the management API rather than /karst/v1. Karst owns nodes,
// policy, relays, Bedrock, posture and audit; users, groups, keys, routes and
// nameservers are the fork's and are reused as they are (ADR-0009).

export type SetupKeyType = "one-off" | "reusable";
export type SetupKey = {
  id: string;
  name: string;
  key: string;
  type: SetupKeyType;
  expires: string;
  revoked: boolean;
  /** "valid" | "overused" | "expired" | "revoked" — the server's own word for it. */
  state?: string;
  usage_limit?: number;
  used_times?: number;
  auto_groups?: string[];
  ephemeral?: boolean;
  last_used?: string | null;
};
export type SetupKeyDraft = { name: string; type: SetupKeyType; expires_in: number; usage_limit: number; auto_groups: string[]; ephemeral: boolean };

export type AccountUser = { id: string; name: string; email: string; role: string; status: string; is_current?: boolean; is_blocked: boolean; auto_groups?: string[]; issued?: string; last_login?: string | null };
export type UserDraft = { name: string; email: string; role: string; auto_groups: string[]; is_service_user: boolean };

export type Group = { id: string; name: string; peers_count: number; resources_count: number; issued?: string };

export type Nameserver = { ip: string; ns_type: "udp"; port: number };
export type NameserverGroup = { id: string; name: string; description: string; nameservers: Nameserver[]; enabled: boolean; groups: string[]; primary: boolean; domains: string[]; search_domains_enabled: boolean };
export type NameserverGroupDraft = Omit<NameserverGroup, "id">;

export type NetworkRoute = { id: string; network_id: string; description: string; enabled: boolean; network: string; peer_groups: string[]; groups: string[]; access_control_groups: string[]; metric: number; masquerade: boolean; keep_route: boolean; skip_auto_apply: boolean };
export type NetworkRouteDraft = Omit<NetworkRoute, "id">;

export type Token = { id: string; name: string; expiration_date: string; created_at: string; last_used?: string | null; plain_token?: string };

export type DnsSettings = { disabled_management_groups: string[] };

export type BedrockLogEntry = { sequence: number; op: string; tier: string; subject: string; signed_at: string; signers: string[] };
/** An offline signing bundle is intentionally opaque to the console: it is
 * created and signed by the Bedrock CLI, not interpreted or signed here. */
export type BedrockRequest = { id: string; created_at: string; payload_hash: string };
export type BedrockBundle = { format: "bedrock-signed-bundle-v1"; payload: string };
export type BedrockBootstrapBundle = { format: "bedrock-log-v1"; payload: string };

export const api = {
  // ── machines ───────────────────────────────────────────────────────────────
  nodes: () => request<NodePage>("/nodes?limit=100"),
  node: (handle: string) => request<NodePage["items"][number]>(`/nodes/${encodeURIComponent(handle)}`),
  nodePaths: (handle: string) => request<{ observed_at: string; paths: Array<{ peer_handle: string; kind: string; endpoint: string | null; relay_id: string | null; since: string | null; observed_at: string }> }>(`/nodes/${encodeURIComponent(handle)}/paths`),
  // Only the name. The contract rejects a PATCH carrying tags, expiry or
  // enabled with "only name is currently mutable for a Karst node", so the
  // console offers exactly what the server accepts rather than a form that
  // fails on save.
  renameNode: (handle: string, name: string) => request<NodePage["items"][number]>(`/nodes/${encodeURIComponent(handle)}`, { method: "PATCH", body: body({ name }) }),
  deprovision: (handle: string) => request<void>(`/nodes/${encodeURIComponent(handle)}`, { method: "DELETE" }),

  // ── access policy ──────────────────────────────────────────────────────────
  policy: () => request<PolicyVersion>("/policy"),
  policyVersions: () => request<PolicyVersionPage>("/policy/versions?limit=100"),
  policyVersion: (version: number) => request<PolicyVersion>(`/policy/versions/${version}`),
  validate: (document: string) => request<PolicyValidation>("/policy/validate", { method: "POST", body: body({ document }) }),
  preview: (document: string) => request<PolicyPreview>("/policy/preview", { method: "POST", body: body({ document }) }),
  testPolicy: (document: string) => request<{ passed: boolean; results: Array<{ name: string; passed: boolean; message: string }> }>("/policy/test", { method: "POST", body: body({ document }) }),
  savePolicy: (document: string, version: number) => request<PolicyVersion>("/policy", { method: "PUT", headers: { "if-match": String(version) }, body: body({ document }) }),
  rollbackPolicy: (version: number, currentVersion: number) => request<PolicyVersion>(`/policy/rollback/${version}`, { method: "POST", headers: { "if-match": String(currentVersion) } }),

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

  // ── relays ─────────────────────────────────────────────────────────────────
  relays: () => request<Relay[]>("/relays"),
  addRelay: (entry: { address: string; tls_server_name: string; identity_key: string; region: string }) => request<Relay>("/relays", { method: "POST", body: body(entry) }),
  removeRelay: (id: string) => request<void>(`/relays/${encodeURIComponent(id)}`, { method: "DELETE" }),

  // ── turn servers ───────────────────────────────────────────────────────────
  turns: () => request<TurnServer[]>("/turns"),
  addTurn: (entry: { uri: string; region: string }) => request<TurnServer>("/turns", { method: "POST", body: body(entry) }),
  removeTurn: (id: string) => request<void>(`/turns/${encodeURIComponent(id)}`, { method: "DELETE" }),

  // ── auth keys ──────────────────────────────────────────────────────────────
  setupKeys: () => management<SetupKey[]>("/setup-keys"),
  createSetupKey: (draft: SetupKeyDraft) => management<SetupKey>("/setup-keys", { method: "POST", body: body(draft) }),
  // The fork's PUT is the revocation path: it takes revoked and auto_groups,
  // and nothing else about a key is mutable once it exists.
  revokeSetupKey: (key: SetupKey) => management<SetupKey>(`/setup-keys/${encodeURIComponent(key.id)}`, { method: "PUT", body: body({ revoked: true, auto_groups: key.auto_groups ?? [] }) }),
  deleteSetupKey: (id: string) => management<void>(`/setup-keys/${encodeURIComponent(id)}`, { method: "DELETE" }),

  // ── users ──────────────────────────────────────────────────────────────────
  users: () => management<AccountUser[]>("/users"),
  currentUser: () => management<AccountUser>("/users/current"),
  createUser: (draft: UserDraft) => management<AccountUser>("/users", { method: "POST", body: body({ name: draft.name, email: draft.email, role: draft.role, auto_groups: draft.auto_groups, is_service_user: draft.is_service_user }) }),
  updateUser: (id: string, changes: { role: string; is_blocked: boolean; auto_groups: string[] }) => management<AccountUser>(`/users/${encodeURIComponent(id)}`, { method: "PUT", body: body(changes) }),
  inviteUser: (id: string) => management<void>(`/users/${encodeURIComponent(id)}/invite`, { method: "POST" }),
  deprovisionUser: (id: string) => management<void>(`/users/${encodeURIComponent(id)}`, { method: "DELETE" }),

  // ── groups ─────────────────────────────────────────────────────────────────
  groups: () => management<Group[]>("/groups"),
  createGroup: (name: string) => management<Group>("/groups", { method: "POST", body: body({ name, peers: [] }) }),
  renameGroup: (id: string, name: string) => management<Group>(`/groups/${encodeURIComponent(id)}`, { method: "PUT", body: body({ name }) }),
  deleteGroup: (id: string) => management<void>(`/groups/${encodeURIComponent(id)}`, { method: "DELETE" }),

  // ── DNS ────────────────────────────────────────────────────────────────────
  dnsSettings: () => management<DnsSettings>("/dns/settings"),
  saveDnsSettings: (disabled_management_groups: string[]) => management<DnsSettings>("/dns/settings", { method: "PUT", body: body({ disabled_management_groups }) }),
  nameservers: () => management<NameserverGroup[]>("/dns/nameservers"),
  createNameserverGroup: (draft: NameserverGroupDraft) => management<NameserverGroup>("/dns/nameservers", { method: "POST", body: body(draft) }),
  updateNameserverGroup: (id: string, draft: NameserverGroupDraft) => management<NameserverGroup>(`/dns/nameservers/${encodeURIComponent(id)}`, { method: "PUT", body: body(draft) }),
  deleteNameserverGroup: (id: string) => management<void>(`/dns/nameservers/${encodeURIComponent(id)}`, { method: "DELETE" }),

  // ── network routes ─────────────────────────────────────────────────────────
  routes: () => management<NetworkRoute[]>("/routes"),
  createRoute: (draft: NetworkRouteDraft) => management<NetworkRoute>("/routes", { method: "POST", body: body(draft) }),
  updateRoute: (id: string, draft: NetworkRouteDraft) => management<NetworkRoute>(`/routes/${encodeURIComponent(id)}`, { method: "PUT", body: body(draft) }),
  deleteRoute: (id: string) => management<void>(`/routes/${encodeURIComponent(id)}`, { method: "DELETE" }),

  // ── personal access tokens ─────────────────────────────────────────────────
  tokens: (userId: string) => management<Token[]>(`/users/${encodeURIComponent(userId)}/tokens`),
  createToken: (userId: string, name: string, expires_in: number) => management<{ plain_token: string; personal_access_token: Token }>(`/users/${encodeURIComponent(userId)}/tokens`, { method: "POST", body: body({ name, expires_in }) }),
  deleteToken: (userId: string, id: string) => management<void>(`/users/${encodeURIComponent(userId)}/tokens/${encodeURIComponent(id)}`, { method: "DELETE" }),
};
