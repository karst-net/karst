// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import http from "node:http";
import { buildFixture } from "../fixtures/karst-api.mjs";

// Two APIs are mocked here, because the console talks to two: /api/karst/v1 is
// the Karst contract (nodes, policy, relays, Bedrock, posture, audit) and /api
// is the fork's management API (users, groups, setup keys, routes, resolvers,
// tokens). Keeping both in one process is what lets a view that spans them —
// "add machine", which mints a key and then lists nodes — be exercised at all.

const seedUsers = () => [
  { id: "user-it", name: "IT operator", email: "it@example.test", role: "admin", status: "active", is_current: true, is_blocked: false, auto_groups: [], last_login: "2026-08-22T08:15:00Z" },
  { id: "user-sre", name: "SRE operator", email: "sre@example.test", role: "admin", status: "active", is_current: false, is_blocked: false, auto_groups: ["group-sre"], last_login: "2026-08-21T17:40:00Z" },
];
const seedGroups = () => [
  { id: "group-all", name: "All", peers_count: 50, resources_count: 0, issued: "api" },
  { id: "group-sre", name: "sre", peers_count: 18, resources_count: 0, issued: "api" },
  { id: "group-engineering", name: "engineering", peers_count: 32, resources_count: 0, issued: "jwt" },
  // The fixture route (karst-api.mjs) names this as its gateway group; without
  // it here the routes view's selector could not offer, let alone redisplay,
  // the group that route already carries.
  { id: "group-gateways", name: "gateways", peers_count: 4, resources_count: 0, issued: "api" },
];
const seedTokens = () => ({ "user-it": [{ id: "token-fixture-1", name: "ci-deploy", expiration_date: "2026-11-20T12:00:00Z", created_at: "2026-08-01T12:00:00Z", last_used: "2026-08-22T06:00:00Z" }] });

let fixture = buildFixture();
let relayCaps = new Map();
let billingPayments = new Map();
let paymentNotices = new Map();
let setupKeys = [];
let invitations = [];
// ADR-0032. Seeded with one small tree so the Domains view and the setup
// invitation form's picker both have something to show without the "empty"
// fixture path.
const seedDomains = (empty = false) => [
  { id: "domain-root", label: "", path: "", is_root: true, dns_suffix: "karst" },
  ...(empty ? [] : [
    { id: "domain-acme", parent_id: "domain-root", label: "acme", path: "acme" },
    { id: "domain-engineering", parent_id: "domain-acme", label: "engineering", path: "engineering.acme" },
  ]),
];
let domains = seedDomains();
let domainBindings = [];
let users = seedUsers();
let groups = seedGroups();
let sinks = [];
const account = { id: "account-fixture", domain: "example.test", domain_category: "private", created_at: "2026-01-01T00:00:00Z", created_by: "user-it" };
// Mirrors server/management/internals/karst/policy/schema.go's shape closely
// enough to exercise the console's own autocomplete against — not the full
// document (descriptions, patterns), which nothing here reads.
const policySchema = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  type: "object",
  properties: {
    groups: { type: "object" },
    tagOwners: { type: "object" },
    acls: { type: "array", items: { type: "object", properties: { action: { const: "accept" }, src: { type: "array" }, dst: { type: "array" } } } },
    ssh: { type: "array", items: { type: "object", properties: { action: { const: "accept" }, src: { type: "array" }, dst: { type: "array" } } } },
  },
};
let routes = fixture.routes.map((route) => ({ ...route }));
let nameservers = fixture.nameservers.map((group) => ({ ...group }));
// NOC map: admin-authorized "possible locations" registry (additive, not a
// foreign key -- see locationreg's own doc comment) and the per-group/
// control-plane declared locations that place an exit-node/subnet-router or
// control-plane marker. Seeded so the NOC view has something of each new
// kind to show without the "empty" fixture path.
let locations = [
  { id: "location-fixture-syd", lat: -33.8688, lon: 151.2093, label: "Sydney", kind: "aws-local-zone" },
];
// Matches fixture.routes' own gateway group (group-gateways, seedGroups
// above) so the "route" marker kind has a route to actually be placed by.
let groupLocations = [
  { group_id: "group-gateways", lat: 50.1109, lon: 8.6821, label: "Frankfurt" },
];
let controlPlaneLocation = { lat: 37.7749, lon: -122.4194, label: "Control room" };
// ADR-0045 §4c's deployment-wide region allowlist (package regionallow).
// Seeded with one pair so the Scaler view's "Allowed regions" section has
// something to show without the "empty" fixture path.
let allowedRegions = [
  { provider: "aws", region: "us-east-1" },
];
// ADR-0008 §4's TURN registry. Seeded with one declared-location entry so
// the Turns view and the "turn" NOC-map marker kind both have something to
// show without the "empty" fixture path, matching every other resource here.
let turns = [
  { id: "turn-fixture-1", uri: "turn:turn.example.test:3478", region: "default", location: { lat: 48.8566, lon: 2.3522, label: "Paris" } },
];
// Console first-run onboarding gate (GET/POST /firstrun). Defaults to true
// so the existing e2e suite's direct navigation to any route keeps working
// unchanged -- flip this to false (and restart the mock) to exercise the
// actual wizard.
let firstRunCompleted = true;
// Per-page "what is this" guidance text (GET/PUT /tutorial-mode). Defaults
// to true, matching the real server's own default.
let tutorialModeEnabled = true;
// Admin-entered infrastructure connections (ADR-0045 §6 addenda). Secrets
// are accepted but never stored here beyond this request -- the mock has no
// encryption-at-rest story to fake, so it simply never echoes one back,
// matching the real server's own InfrastructureConnection/CloudAccount
// response shape. One shared backing array for both the deprecated
// /cloud-accounts routes and the generalized /infrastructure-connections
// ones, the same coupling the real server's one table has.
let infraConnections = [];
// Canned discovery results per connection type, standing in for a live
// describe-regions/list-namespaces call -- just enough for the Authorized
// Locations picker to have something to choose from. enabled mirrors the
// real server's DiscoveredRegion/DiscoveredResource field: true for a
// region and an already opted-in local zone. us-west-2-lax-1 starts false
// so a read_write AWS connection has something to exercise the enable
// endpoint below against; a read_only connection never sees it at all
// (filtered where the regions/resources routes are handled, matching
// infraconnections' ModeReadOnly discovery behavior). Kubernetes
// namespaces have no enabled/opt-in concept at all.
const discoveryFixtures = {
  aws: [
    { code: "us-east-1", name: "US East (N. Virginia)", kind: "region", lat: 38.9519, lon: -77.4480, enabled: true },
    { code: "eu-west-1", name: "Europe (Ireland)", kind: "region", lat: 53.3498, lon: -6.2603, enabled: true },
    { code: "us-east-1-bos-1", name: "Boston Local Zone", kind: "local_zone", lat: 42.3601, lon: -71.0589, enabled: true, parent_region: "us-east-1" },
    { code: "us-west-2-lax-1", name: "Los Angeles Local Zone", kind: "local_zone", lat: 34.0522, lon: -118.2437, enabled: false, parent_region: "us-west-2" },
  ],
  azure: [
    { code: "eastus", name: "East US (Virginia)", kind: "region", lat: 37.3719, lon: -79.8164, enabled: true },
    { code: "westeurope", name: "West Europe (Netherlands)", kind: "region", lat: 52.3667, lon: 4.9000, enabled: true },
  ],
  gcp: [
    { code: "us-central1", name: "Iowa", kind: "region", lat: 41.2619, lon: -95.8608, enabled: true },
    { code: "europe-west1", name: "Belgium", kind: "region", lat: 50.8503, lon: 4.3517, enabled: true },
  ],
  // Namespaces never carry coordinates -- the console falls back to the
  // connection's own declared lat/lon (see settings.tsx/locations.tsx).
  kubernetes: [
    { code: "default", kind: "namespace" },
    { code: "kube-system", kind: "namespace" },
  ],
};
let tokens = seedTokens();
let memberDevices = [{ handle: "member-laptop", name: "SRE laptop", platform: "Linux", last_seen_at: "2026-08-22T20:32:00Z" }];
const memberAccess = [{ destination: "db-prod:5432", rule: 4, group: "group:sre", changed_at: "2026-08-12T10:00:00Z", changed_by: "alice@example.test" }];
const memberSessions = [{ device: "SRE laptop", started_at: "2026-08-22T19:01:00Z", ended_at: null, ip: "100.64.0.2" }];
// Coverage is a property of the signed Bedrock log, not of node liveness, so
// the uncovered set here deliberately does NOT match what a client could derive
// from posture or `enabled`: node 1 is healthy, online, and uncovered; the
// stale nodes (17, 34) are covered. A console that guesses gets a 409 from the
// real server, and must get one here too.
const bedrock = { mode: "advisory", quorum: 2, roots: [], authorities: [], zone: "fixture.karst.test", head: "beef", head_seq: 12, disabled: false, covered_count: 48, uncovered_handles: ["node-0001-karst-fixture-handle", "node-0049-karst-fixture-handle"] };
const dnsSettings = { disabled_management_groups: [] };
const port = Number.parseInt(process.env.KARST_API_MOCK_PORT ?? "4010", 10);
const prefix = "/api/karst/v1";
// Shaped like scripts/release-manifest.sh output, and named the way the
// pipeline actually names things — `karst-client-linux_<version>_<arch>.deb`,
// not the `karst-linux-amd64.deb` this fixture used to invent. A fixture that
// describes artifacts nothing builds lets the download test pass for a page
// that would be empty in production, which is the fixture-only failure
// GitHub issue [#47](https://github.com/karst-net/karst/issues/47) and 43
// are about.
//
// No Windows row: the client is Phase 8, so a manifest offering one would be
// describing a file that does not exist.
const releaseAssets = [
  { platform: "macos", arch: "arm64", format: "pkg", name: "karst-client-macos-arm64.pkg", url: "/releases/karst-client-macos-arm64.pkg", sha256: "31a05d7fd3946767a06d2638a63d7f6df13ce8cb4a4e06631d0a0258de4f4f57" },
  { platform: "macos", arch: "amd64", format: "pkg", name: "karst-client-macos-x86_64.pkg", url: "/releases/karst-client-macos-x86_64.pkg", sha256: "7a2c4e1b9d8f3065412789abcde0123456789fedcba9876543210abcdef1234" },
  { platform: "linux", arch: "amd64", format: "deb", name: "karst-client-linux_0.1.0-1_amd64.deb", url: "/releases/karst-client-linux_0.1.0-1_amd64.deb", sha256: "c10b418474a5ba59159d55ef58d54a24d8b9f341f089f67f1fd9b20a398b12f7" },
  { platform: "linux", arch: "arm64", format: "deb", name: "karst-client-linux_0.1.0-1_arm64.deb", url: "/releases/karst-client-linux_0.1.0-1_arm64.deb", sha256: "9d5f2a1c3e4b6789012345678901234567890abcdef1234567890abcdef12345" },
  { platform: "linux", arch: "amd64", format: "rpm", name: "karst-client-linux-0.1.0-1.x86_64.rpm", url: "/releases/karst-client-linux-0.1.0-1.x86_64.rpm", sha256: "b783bb7b65d1b9c8a5b0f81fd22cfe481ba6807e2b01986f8cf07b61185d1139" },
  { platform: "linux", arch: "arm64", format: "rpm", name: "karst-client-linux-0.1.0-1.aarch64.rpm", url: "/releases/karst-client-linux-0.1.0-1.aarch64.rpm", sha256: "4f1e2d3c4b5a69788796a5b4c3d2e1f00112233445566778899aabbccddeeff0" },
];

function json(response, status, value) {
  response.writeHead(status, { "content-type": "application/json; charset=utf-8" });
  response.end(JSON.stringify(value));
}

function page(items, requestUrl) {
  const limit = Number.parseInt(requestUrl.searchParams.get("limit") ?? "50", 10);
  const cursor = Number.parseInt(requestUrl.searchParams.get("cursor") ?? "0", 10);
  const safeLimit = Number.isFinite(limit) ? Math.max(1, Math.min(limit, 200)) : 50;
  return { items: items.slice(cursor, cursor + safeLimit), next_cursor: cursor + safeLimit < items.length ? String(cursor + safeLimit) : null };
}

function error(response, status, code, message) {
  json(response, status, { code, message, request_id: "mock-request-0001" });
}

const noContent = (response) => response.writeHead(204).end();
const id = (prefixText) => `${prefixText}-${Math.random().toString(36).slice(2, 8)}`;
const inDays = (days) => new Date(Date.now() + days * 86_400_000).toISOString();

// `JSON.parse`'s thrown `SyntaxError` carries no `.position` property on any
// V8 this was checked against — that field does not exist, so reading it
// always produced `undefined` and every diagnostic silently reported line 1
// regardless of where the real error was. Two message shapes to parse
// instead: newer V8 already states "(line N column M)" directly; anything
// else falls back to "at position N" and counts newlines in `document` up
// to that offset, the same computation the removed code intended. A message
// with neither ("Unexpected token 'x', ... is not valid JSON", V8's shape
// for some early-tokenizing failures) reports line 1 honestly rather than
// guessing.
function policyValidation(document) {
  try { JSON.parse(document); return { valid: true, diagnostics: [] }; }
  catch (error) {
    const message = error.message;
    const lineColumn = /\(line (\d+) column (\d+)\)/.exec(message);
    if (lineColumn) {
      return { valid: false, diagnostics: [{ severity: "error", message, line: Number(lineColumn[1]), column: Number(lineColumn[2]) }] };
    }
    const positioned = /at position (\d+)/.exec(message);
    const before = document.slice(0, positioned ? Number(positioned[1]) : 0);
    return { valid: false, diagnostics: [{ severity: "error", message, line: before.split("\n").length, column: before.length - before.lastIndexOf("\n") }] };
  }
}

async function readBody(request) {
  const chunks = [];
  for await (const chunk of request) chunks.push(chunk);
  if (chunks.length === 0) return {};
  try { return JSON.parse(Buffer.concat(chunks).toString("utf8")); } catch { return {}; }
}

function sameStrings(a, b) {
  const left = [...a].sort();
  const right = [...b].sort();
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

/** Update-in-place for a collection keyed by id, or 404. Written once because
 *  five resources need exactly this and four of them would otherwise get a
 *  slightly different not-found. */
function replace(collection, itemId, patch, response) {
  const index = collection.findIndex((item) => item.id === itemId);
  if (index < 0) return error(response, 404, "not_found", "not found");
  collection[index] = { ...collection[index], ...patch, id: itemId };
  return json(response, 200, collection[index]);
}

function remove(collection, itemId, response) {
  const index = collection.findIndex((item) => item.id === itemId);
  if (index < 0) return error(response, 404, "not_found", "not found");
  collection.splice(index, 1);
  return noContent(response);
}

const server = http.createServer((request, response) => {
  const url = new URL(request.url, `http://${request.headers.host ?? "localhost"}`);
  const method = request.method ?? "GET";
  const path = url.pathname;

  if (path === "/releases/manifest.json" && method === "GET") return json(response, 200, { assets: releaseAssets });

  // ── fixture control, not modeled endpoints ────────────────────────────────
  // Lets a test move the uncovered set between a page load and a save, which is
  // the race PUT /bedrock/mode's 409 exists for.
  if (path === "/__mock__/bedrock/uncovered" && method === "PUT") {
    return readBody(request).then((body) => { bedrock.uncovered_handles = body.uncovered_handles ?? []; return json(response, 200, bedrock); });
  }
  // Keep cap fixtures scoped to billing tests. Resetting the shared console
  // fixture while other Playwright workers are using it must not erase a cap
  // mid-assertion or reset their unrelated resources.
  if (path === "/__mock__/billing/fixture" && method === "PUT") {
    relayCaps = new Map();
    billingPayments = new Map();
    paymentNotices = new Map();
    return noContent(response);
  }
  if (path === "/__mock__/billing/payment-state" && method === "PUT") {
    return readBody(request).then(({ period, state }) => {
      const [year, month] = period.split("-").map(Number);
      const payment = { period_start: new Date(Date.UTC(year, month - 1, 1)).toISOString(), period_end: new Date(Date.UTC(year, month, 1)).toISOString(), currency: "USD", device_minor: 2500, relay_minor: 500, total_minor: 3000, state, checkout_url: "https://sandbox-buy.paddle.com/checkout/mock", updated_at: new Date().toISOString() };
      billingPayments.set(period, payment);
      paymentNotices.set(period, { notices: state === "past_due" ? [{ period_start: payment.period_start, period_end: payment.period_end, created_at: payment.updated_at }] : [] });
      return json(response, 200, payment);
    });
  }
  if (path === "/__mock__/fixture" && method === "PUT") {
    return readBody(request).then((body) => {
      const empty = Boolean(body.empty);
      fixture = buildFixture({ empty });
      setupKeys = [];
      invitations = [];
      domains = seedDomains(empty);
      domainBindings = [];
      users = empty ? [] : seedUsers();
      groups = empty ? [] : seedGroups();
      sinks = [];
      routes = fixture.routes.map((route) => ({ ...route }));
      nameservers = fixture.nameservers.map((group) => ({ ...group }));
      tokens = empty ? {} : seedTokens();
      bedrock.mode = "advisory";
      return json(response, 200, fixture);
    });
  }

  // ── the fork's management API ─────────────────────────────────────────────
  if (path === "/api/setup-keys" && method === "GET") return json(response, 200, setupKeys);
  if (path === "/api/setup-keys" && method === "POST") {
    return readBody(request).then((draft) => {
      const key = {
        id: id("key"),
        name: draft.name ?? "First node",
        // Fixed on purpose: a test asserting the enrollment command has to be
        // able to assert the whole string, secret included.
        key: "setup-fixture-secret",
        type: draft.type ?? "one-off",
        expires: new Date(Date.now() + (draft.expires_in ?? 86_400) * 1000).toISOString(),
        revoked: false,
        state: "valid",
        usage_limit: draft.usage_limit ?? 1,
        used_times: 0,
        auto_groups: draft.auto_groups ?? [],
        ephemeral: Boolean(draft.ephemeral),
        last_used: null,
      };
      setupKeys.push(key);
      return json(response, 201, key);
    });
  }
  const keyMatch = path.match(/^\/api\/setup-keys\/([^/]+)$/);
  if (keyMatch && method === "PUT") return readBody(request).then((body) => replace(setupKeys, keyMatch[1], { revoked: Boolean(body.revoked), state: body.revoked ? "revoked" : "valid", auto_groups: body.auto_groups ?? [] }, response));
  if (keyMatch && method === "DELETE") return remove(setupKeys, keyMatch[1], response);

  if (path === "/api/users/current" && method === "GET") {
    const current = users.find((user) => user.is_current) ?? users[0];
    return current ? json(response, 200, current) : error(response, 404, "not_found", "no current user");
  }
  if (path === "/api/users" && method === "GET") return json(response, 200, users);
  if (path === "/api/users" && method === "POST") {
    return readBody(request).then((draft) => {
      if (!draft.email) return error(response, 422, "invalid_argument", "email is required");
      const user = { id: id("user"), name: draft.name ?? draft.email, email: draft.email, role: draft.role ?? "user", status: "invited", is_current: false, is_blocked: false, auto_groups: draft.auto_groups ?? [], last_login: null };
      users.push(user);
      return json(response, 201, user);
    });
  }
  const userMatch = path.match(/^\/api\/users\/([^/]+)$/);
  if (userMatch && method === "PUT") return readBody(request).then((body) => replace(users, userMatch[1], { role: body.role, is_blocked: Boolean(body.is_blocked), auto_groups: body.auto_groups ?? [] }, response));
  if (userMatch && method === "DELETE") return remove(users, userMatch[1], response);
  const inviteMatch = path.match(/^\/api\/users\/([^/]+)\/invite$/);
  if (inviteMatch && method === "POST") return users.some((user) => user.id === inviteMatch[1]) ? noContent(response) : error(response, 404, "not_found", "user not found");

  const tokenList = path.match(/^\/api\/users\/([^/]+)\/tokens$/);
  if (tokenList && method === "GET") return json(response, 200, tokens[tokenList[1]] ?? []);
  if (tokenList && method === "POST") {
    return readBody(request).then((draft) => {
      const token = { id: id("token"), name: draft.name ?? "token", expiration_date: inDays(draft.expires_in ?? 30), created_at: new Date().toISOString(), last_used: null };
      tokens[tokenList[1]] = [...(tokens[tokenList[1]] ?? []), token];
      // The secret exists exactly once, in this response. Mirroring that is the
      // point: a console that could re-read it later would be modeling a
      // server that stores it, and this one does not.
      return json(response, 201, { plain_token: "pat-fixture-secret", personal_access_token: token });
    });
  }
  const tokenMatch = path.match(/^\/api\/users\/([^/]+)\/tokens\/([^/]+)$/);
  if (tokenMatch && method === "DELETE") {
    const owned = tokens[tokenMatch[1]] ?? [];
    const index = owned.findIndex((token) => token.id === tokenMatch[2]);
    if (index < 0) return error(response, 404, "not_found", "token not found");
    owned.splice(index, 1);
    return noContent(response);
  }

  if (path === "/api/accounts" && method === "GET") return json(response, 200, [account]);

  if (path === "/api/groups" && method === "GET") return json(response, 200, groups);
  if (path === "/api/groups" && method === "POST") {
    return readBody(request).then((draft) => {
      if (!draft.name) return error(response, 422, "invalid_argument", "name is required");
      const group = { id: id("group"), name: draft.name, peers_count: 0, resources_count: 0, issued: "api" };
      groups.push(group);
      return json(response, 201, group);
    });
  }
  const groupMatch = path.match(/^\/api\/groups\/([^/]+)$/);
  if (groupMatch && method === "PUT") return readBody(request).then((body) => replace(groups, groupMatch[1], { name: body.name }, response));
  if (groupMatch && method === "DELETE") return remove(groups, groupMatch[1], response);

  if (path === "/api/dns/settings" && method === "GET") return json(response, 200, dnsSettings);
  if (path === "/api/dns/settings" && method === "PUT") {
    return readBody(request).then((body) => { dnsSettings.disabled_management_groups = body.disabled_management_groups ?? []; return json(response, 200, dnsSettings); });
  }
  if (path === "/api/dns/nameservers" && method === "GET") return json(response, 200, nameservers);
  if (path === "/api/dns/nameservers" && method === "POST") {
    return readBody(request).then((draft) => { const group = { ...draft, id: id("ns") }; nameservers.push(group); return json(response, 201, group); });
  }
  const nsMatch = path.match(/^\/api\/dns\/nameservers\/([^/]+)$/);
  if (nsMatch && method === "PUT") return readBody(request).then((body) => replace(nameservers, nsMatch[1], body, response));
  if (nsMatch && method === "DELETE") return remove(nameservers, nsMatch[1], response);

  if (path === "/api/routes" && method === "GET") return json(response, 200, routes);
  if (path === "/api/routes" && method === "POST") {
    return readBody(request).then((draft) => {
      if (!draft.network_id) return error(response, 422, "invalid_argument", "network_id is required");
      const route = { ...draft, id: id("route") };
      routes.push(route);
      return json(response, 201, route);
    });
  }
  const routeMatch = path.match(/^\/api\/routes\/([^/]+)$/);
  if (routeMatch && method === "PUT") return readBody(request).then((body) => replace(routes, routeMatch[1], body, response));
  if (routeMatch && method === "DELETE") return remove(routes, routeMatch[1], response);

  // ── the Karst contract ────────────────────────────────────────────────────
  if (!path.startsWith(prefix)) return error(response, 404, "not_found", "unknown mock path");
  const karst = path.slice(prefix.length) || "/";

  if (method === "GET" && karst === "/usage/devices") {
    const start = url.searchParams.get("start") ?? "";
    const end = url.searchParams.get("end") ?? "";
    return json(response, 200, { start, end, as_of: new Date().toISOString(), complete: false, device_microseconds: "86400000000", segments: [{ start, end, coverage: "incomplete", devices: null }] });
  }
  if (method === "GET" && karst === "/usage/relays") {
    const start = url.searchParams.get("start") ?? "";
    const end = url.searchParams.get("end") ?? "";
    return json(response, 200, { start, end, as_of: new Date().toISOString(), authorization_history_start: "2026-01-01T00:00:00Z", first_received_window_start: start, last_received_at: new Date().toISOString(), coverage: "authorized_producers", history_complete: true, complete: false, expected_windows: 60, missing_windows: 4, unexpected_windows: 0, reported_bytes: "15000000000", days: [], limitations: ["Some producer windows have not arrived."] });
  }
  if (method === "GET" && karst === "/usage/relay-alerts") {
    const period = url.searchParams.get("period") ?? new Date().toISOString().slice(0, 7);
    const [year, month] = period.split("-").map(Number);
    const start = new Date(Date.UTC(year, month - 1, 1)).toISOString();
    const end = new Date(Date.UTC(year, month, 1)).toISOString();
    return json(response, 200, { period_start: start, period_end: end, as_of: new Date().toISOString(), coverage_complete: false, coverage_warning: "Relay usage coverage is incomplete; threshold amounts are lower bounds.", alerts: [{ period_start: start, period_end: end, schedule_version: "pilot-v1", target: "included_allowance", threshold_percent: 75, reported_bytes: "15000000000", threshold_bytes: "11250000000", as_of: new Date().toISOString(), usage_complete: false }] });
  }
  if (karst === "/billing/payments" && method === "GET") {
    const period = url.searchParams.get("period") ?? new Date().toISOString().slice(0, 7);
    const [year, month] = period.split("-").map(Number);
    return json(response, 200, billingPayments.get(period) ?? { period_start: new Date(Date.UTC(year, month - 1, 1)).toISOString(), period_end: new Date(Date.UTC(year, month, 1)).toISOString(), currency: "USD", device_minor: 2500, relay_minor: 0, total_minor: 2500, state: "not_queued", updated_at: new Date().toISOString() });
  }
  if (karst === "/billing/payments" && method === "POST") {
    const period = url.searchParams.get("period") ?? new Date().toISOString().slice(0, 7);
    const [year, month] = period.split("-").map(Number);
    const payment = { period_start: new Date(Date.UTC(year, month - 1, 1)).toISOString(), period_end: new Date(Date.UTC(year, month, 1)).toISOString(), currency: "USD", device_minor: 2500, relay_minor: 500, total_minor: 3000, state: "checkout", checkout_url: "https://sandbox-buy.paddle.com/checkout/mock", updated_at: new Date().toISOString() };
    billingPayments.set(period, payment);
    return json(response, 202, payment);
  }
  if (karst === "/billing/payment-notices" && method === "GET") {
    const period = url.searchParams.get("period") ?? new Date().toISOString().slice(0, 7);
    return json(response, 200, paymentNotices.get(period) ?? { notices: [] });
  }
  if (karst === "/billing/relay-cap" && method === "GET") {
    const period = url.searchParams.get("period") ?? new Date().toISOString().slice(0, 7);
    const [year, month] = period.split("-").map(Number);
    return json(response, 200, relayCaps.get(period) ?? { enabled: false, period_start: new Date(Date.UTC(year, month - 1, 1)).toISOString(), period_end: new Date(Date.UTC(year, month, 1)).toISOString(), currency: "USD", acknowledged_interruption: false });
  }
  if (karst === "/billing/relay-cap" && method === "PUT") {
    return readBody(request).then((draft) => {
      if (!/^\d{4}-(0[1-9]|1[0-2])$/.test(draft.period) || !Number.isSafeInteger(draft.overage_limit_minor) || draft.overage_limit_minor < 0 || draft.acknowledge_interruption !== true) return error(response, 400, "invalid_argument", "invalid relay cap settings");
      const [year, month] = draft.period.split("-").map(Number);
      const cap = { enabled: true, period_start: new Date(Date.UTC(year, month - 1, 1)).toISOString(), period_end: new Date(Date.UTC(year, month, 1)).toISOString(), currency: "USD", overage_limit_minor: draft.overage_limit_minor, acknowledged_interruption: true, effective_at: new Date(Date.now() + 15_000).toISOString() };
      relayCaps.set(draft.period, cap);
      return json(response, 200, cap);
    });
  }

  // The portal namespace is deliberately separate from the administrative
  // router. Fixtures only expose the member's own devices; there is no user
  // identifier to forge in any of these paths.
  if (method === "GET" && karst === "/me/devices") return json(response, 200, memberDevices);
  if (method === "GET" && karst === "/invitations") return json(response, 200, invitations);
  if (method === "POST" && karst === "/invitations") return readBody(request).then(draft => {
    if (!draft.name?.trim() || !draft.groups?.length) return error(response, 400, "invalid_argument", "Device label and groups are required");
    if (draft.domain_id && !domains.some(d => d.id === draft.domain_id)) return error(response, 400, "invalid_argument", "unknown domain_id");
    const item = { id: id("invitation"), name: draft.name, groups: draft.groups, state: "pending", created_at: new Date().toISOString(), expires_at: new Date(Date.now() + 86400000).toISOString(), ...(draft.domain_id ? { domain_id: draft.domain_id } : {}) };
    invitations.push(item);
    return json(response, 200, { ...item, credential: "invitation-fixture-secret" });
  });
  const revokeInvitation = karst.match(/^\/invitations\/([^/]+)\/revoke$/);
  if (method === "POST" && revokeInvitation) return replace(invitations, revokeInvitation[1], { state: "revoked" }, response);

  // ── mesh domains (ADR-0032) ───────────────────────────────────────────────
  if (method === "GET" && karst === "/domains") {
    const suffix = domains.find(domain => domain.is_root)?.dns_suffix;
    return json(response, 200, domains.map(domain => ({ ...domain, ...(suffix ? { dns_name: [domain.path, suffix].filter(Boolean).join(".") } : {}) })));
  }
  if (method === "POST" && karst === "/domains") return readBody(request).then(draft => {
    const label = draft.label?.trim();
    if (!label) return error(response, 400, "invalid_argument", "label is required");
    const parentId = draft.parent_id || "domain-root";
    const parent = parentId ? domains.find(d => d.id === parentId) : undefined;
    if (parentId && !parent) return error(response, 400, "invalid_argument", "unknown parent_id");
    if (domains.some(d => (d.parent_id || "") === parentId && d.label === label)) return error(response, 409, "already_exists", `a domain named "${label}" already exists at this level`);
    const path = parent?.path ? `${label}.${parent.path}` : label;
    const item = { id: id("domain"), ...(parentId ? { parent_id: parentId } : {}), label, path };
    domains.push(item);
    return json(response, 200, item);
  });
  const domainMatch = karst.match(/^\/domains\/([^/]+)$/);
  if (domainMatch && method === "DELETE") {
    const domainId = domainMatch[1];
    if (domains.find(d => d.id === domainId)?.is_root) return error(response, 412, "precondition_failed", "the account root cannot be deleted");
    if (domains.some(d => d.parent_id === domainId)) return error(response, 412, "precondition_failed", "domain has subdomains; delete them first");
    return remove(domains, domainId, response);
  }
  const delegationsMatch = karst.match(/^\/domains\/([^/]+)\/delegations$/);
  if (delegationsMatch && method === "GET") return json(response, 200, domainBindings.filter(b => b.domain_id === delegationsMatch[1]));
  if (delegationsMatch && method === "POST") return readBody(request).then(draft => {
    const domain = domains.find(d => d.id === delegationsMatch[1]);
    if (!domain) return error(response, 404, "not_found", "domain not found");
    if (!draft.user_id) return error(response, 400, "invalid_argument", "user_id is required");
    const binding = { id: id("binding"), domain_id: domain.id, domain_path: domain.path, user_id: draft.user_id };
    domainBindings.push(binding);
    return json(response, 200, binding);
  });
  const revokeDelegation = karst.match(/^\/domains\/delegations\/([^/]+)$/);
  if (revokeDelegation && method === "DELETE") return remove(domainBindings, revokeDelegation[1], response);
  if (method === "GET" && karst === "/me/enrollment") return json(response, 200, { server_kem_pin: "ab".repeat(1184), server_verify_pin: "cd".repeat(2592), control_minimum_version: 1 });
  if (method === "POST" && karst === "/me/devices/enroll") return json(response, 201, { key: "member-one-time-key", expires_at: "2026-08-22T20:47:00Z" });
  if (method === "GET" && karst === "/me/access") return json(response, 200, memberAccess);
  if (method === "GET" && karst === "/me/sessions") return json(response, 200, memberSessions);
  const memberDevice = karst.match(/^\/me\/devices\/([^/]+)$/);
  if (memberDevice && method === "PATCH") return readBody(request).then((body) => { const device = memberDevices.find((item) => item.handle === memberDevice[1]); if (!device) return error(response, 404, "not_found", "device not found"); if (typeof body.name !== "string" || !body.name.trim()) return error(response, 400, "invalid_argument", "name is required"); device.name = body.name.trim(); return json(response, 200, device); });
  if (memberDevice && method === "DELETE") { const index = memberDevices.findIndex((item) => item.handle === memberDevice[1]); if (index < 0) return error(response, 404, "not_found", "device not found"); memberDevices.splice(index, 1); return noContent(response); }

  const nodeMatch = karst.match(/^\/nodes\/([^/]+)(?:\/(paths|posture))?$/);
  const relayMatch = karst.match(/^\/relays\/([^/]+)(?:\/health)?$/);

  if (method === "GET" && karst === "/nodes") return json(response, 200, page(fixture.nodes, url));
  if (nodeMatch) {
    const index = fixture.nodes.findIndex((item) => item.handle === nodeMatch[1]);
    if (index < 0) return error(response, 404, "not_found", "node not found");
    const node = fixture.nodes[index];
    if (method === "GET" && nodeMatch[2] === "paths") return json(response, 200, { observed_at: fixture.asOf, paths: [{ peer_handle: fixture.nodes[1].handle, kind: "relay", endpoint: null, relay_id: fixture.relays[0]?.id ?? null, since: null, observed_at: fixture.asOf, tx_bytes: 1_234_567, rx_bytes: 7_654_321 }] });
    if (method === "GET" && nodeMatch[2] === "posture") return json(response, 200, node.posture);
    if (method === "GET") return json(response, 200, node);
    // Name and domain_id (ADR-0032), nothing else, exactly as the contract's
    // updateNode enforces: a console that offered tags here would pass
    // against a lenient mock and fail against the server.
    if (method === "PATCH") return readBody(request).then((body) => {
      if (body.name === undefined && body.domain_id === undefined) return error(response, 422, "invalid_argument", "only name and domain_id are currently mutable for a Karst node");
      if (body.tags !== undefined || body.enabled !== undefined || body.expires_at !== undefined) return error(response, 422, "invalid_argument", "only name and domain_id are currently mutable for a Karst node");
      if (body.name !== undefined) {
        if (typeof body.name !== "string" || !body.name.trim()) return error(response, 400, "invalid_argument", "name is required");
        node.name = body.name.trim();
      }
      if (body.domain_id !== undefined) {
        if (!body.domain_id || !domains.some(d => d.id === body.domain_id)) return error(response, 400, "invalid_argument", "unknown domain_id");
        node.domain_id = body.domain_id;
      }
      const domain = node.domain_id && domains.find(d => d.id === node.domain_id);
      node.dns_label = domain?.path ? `${node.name}.${domain.path}` : node.name;
      return json(response, 200, node);
    });
    if (method === "DELETE") { fixture.nodes.splice(index, 1); return noContent(response); }
  }
  if (method === "GET" && karst === "/policy/schema") return json(response, 200, policySchema);
  if (method === "GET" && karst === "/policy") return json(response, 200, fixture.policy);
  if (method === "GET" && karst === "/policy/versions") return json(response, 200, page(fixture.policyVersions, url));
  if (method === "GET" && /^\/policy\/versions\/\d+$/.test(karst)) {
    const version = Number.parseInt(karst.split("/").at(-1), 10);
    const policy = fixture.policyVersions.find((item) => item.version === version);
    return policy ? json(response, 200, policy) : error(response, 404, "not_found", "policy version not found");
  }
  if (method === "POST" && karst === "/policy/validate") return readBody(request).then((body) => json(response, 200, policyValidation(body.document ?? "")));
  if (method === "POST" && karst === "/policy/preview") return json(response, 200, { added: [{ source: "group:sre", destination: "tag:prod", protocol: "tcp", ports: "22" }], removed: [{ source: "group:contractors", destination: "tag:prod", protocol: "tcp", ports: "22" }], ssh_added: [{ principal: "group:sre", target: "tag:prod" }], ssh_removed: [{ principal: "group:contractors", target: "tag:prod" }] });
  if ((method === "PUT" && karst === "/policy") || (method === "POST" && /^\/policy\/rollback\/\d+$/.test(karst))) return json(response, 200, fixture.policy);
  if (method === "POST" && karst === "/policy/test") return json(response, 200, { passed: false, results: [{ name: "SRE SSH access", passed: true, message: "allowed" }, { name: "contractor production SSH", passed: false, message: "expected deny, got allow" }] });

  if (method === "GET" && karst === "/relays") return json(response, 200, fixture.relays);
  if (method === "POST" && karst === "/relays") {
    return readBody(request).then((entry) => {
      if (!entry.address || !entry.identity_key) return error(response, 422, "invalid_argument", "address and identity_key are required");
      if (fixture.relays.some((relay) => relay.address === entry.address)) return error(response, 412, "already_exists", "relay already exists");
      const relay = { id: id("relay"), address: entry.address, identity_key: entry.identity_key, region: entry.region ?? "default", tls_server_name: entry.tls_server_name ?? "", location: entry.location ?? undefined, location_source: entry.location ? "declared" : undefined, health: { source: "roster_mtime", last_confirmed_at: null, sessions: null, bytes: null, admission_state: "unknown" } };
      fixture.relays.push(relay);
      return json(response, 201, relay);
    });
  }
  if (relayMatch && method === "GET" && karst.endsWith("/health")) return json(response, 200, fixture.relays.find((item) => item.id === relayMatch[1])?.health ?? fixture.relays[0].health);
  if (relayMatch && method === "DELETE") return remove(fixture.relays, relayMatch[1], response);

  // ADR-0008 §4's TURN registry. turncred.go's own validate() requires a
  // turn: or turns: URI and nothing else; mirrored here so a malformed URI
  // is rejected the same way the real server rejects it.
  if (method === "GET" && karst === "/turns") return json(response, 200, turns);
  if (method === "POST" && karst === "/turns") {
    return readBody(request).then((entry) => {
      if (!/^turns?:/.test(entry.uri ?? "")) return error(response, 422, "invalid_argument", "uri must start with turn: or turns:");
      if (turns.some((turn) => turn.uri === entry.uri)) return error(response, 412, "already_exists", "turn server already exists");
      const turn = { id: id("turn"), uri: entry.uri, region: entry.region ?? "default", location: entry.location ?? undefined };
      turns.push(turn);
      return json(response, 201, turn);
    });
  }
  const turnMatch = karst.match(/^\/turns\/([^/]+)$/);
  if (turnMatch && method === "DELETE") return remove(turns, turnMatch[1], response);

  // NOC view (#241 Phase 1a, extended to ADR-0046 §1's full component list)
  // -- one discriminated union assembled from relays, TURN servers, route
  // gateway groups with a declared location, and the account's
  // control-plane/Bedrock declared locations.
  if (method === "GET" && karst === "/noc/components") {
    const result = [];
    for (const relay of fixture.relays) {
      result.push({ kind: "relay", id: relay.id, label: relay.location?.label || relay.region, health: relay.health.admission_state, location: relay.location });
    }
    for (const turn of turns) {
      result.push({ kind: "turn", id: turn.id, label: turn.location?.label || turn.uri, location: turn.location });
    }
    for (const gl of groupLocations) {
      const servedBy = routes.filter((route) => route.enabled && route.peer_groups.includes(gl.group_id)).map((route) => route.network_id);
      if (servedBy.length === 0) continue;
      result.push({ kind: "route", id: gl.group_id, label: gl.label || servedBy.join(", "), location: { lat: gl.lat, lon: gl.lon, label: gl.label } });
    }
    result.push({ kind: "control_plane", id: "control-plane", label: controlPlaneLocation?.label || "Control plane", location: controlPlaneLocation ?? undefined });
    result.push({ kind: "bedrock", id: "bedrock", label: bedrock.location?.label || "Bedrock", location: bedrock.location });
    return json(response, 200, result);
  }
  const nocRelayMatch = karst.match(/^\/noc\/relays\/([^/]+)$/);
  if (nocRelayMatch && method === "GET") {
    const relay = fixture.relays.find((item) => item.id === nocRelayMatch[1]);
    if (!relay) return error(response, 404, "not_found", "relay not found");
    return json(response, 200, relay);
  }

  // NOC map: admin-authorized "possible locations" registry.
  if (method === "GET" && karst === "/locations") return json(response, 200, locations);
  if (method === "POST" && karst === "/locations") {
    return readBody(request).then((entry) => {
      if (typeof entry.lat !== "number" || typeof entry.lon !== "number") return error(response, 422, "invalid_argument", "lat and lon are required numbers");
      const location = { id: id("location"), lat: entry.lat, lon: entry.lon, label: entry.label ?? undefined, kind: entry.kind ?? undefined };
      locations.push(location);
      return json(response, 201, location);
    });
  }
  const locationMatch = karst.match(/^\/locations\/([^/]+)$/);
  if (locationMatch && method === "DELETE") return remove(locations, locationMatch[1], response);

  // NOC map: a route gateway group's declared location.
  if (method === "GET" && karst === "/group-locations") return json(response, 200, groupLocations);
  const groupLocationMatch = karst.match(/^\/group-locations\/([^/]+)$/);
  if (groupLocationMatch && method === "PUT") {
    return readBody(request).then((entry) => {
      if (typeof entry.lat !== "number" || typeof entry.lon !== "number") return error(response, 422, "invalid_argument", "lat and lon are required numbers");
      const groupId = groupLocationMatch[1];
      const declared = { group_id: groupId, lat: entry.lat, lon: entry.lon, label: entry.label ?? undefined };
      groupLocations = [...groupLocations.filter((gl) => gl.group_id !== groupId), declared];
      return json(response, 200, declared);
    });
  }
  if (groupLocationMatch && method === "DELETE") {
    const before = groupLocations.length;
    groupLocations = groupLocations.filter((gl) => gl.group_id !== groupLocationMatch[1]);
    if (groupLocations.length === before) return error(response, 404, "not_found", "group location not found");
    return noContent(response);
  }

  // NOC map: the control plane's own declared location.
  if (method === "GET" && karst === "/control-plane/location") return controlPlaneLocation ? json(response, 200, controlPlaneLocation) : noContent(response);
  if (method === "PUT" && karst === "/control-plane/location") {
    return readBody(request).then((entry) => {
      if (typeof entry.lat !== "number" || typeof entry.lon !== "number") return error(response, 422, "invalid_argument", "lat and lon are required numbers");
      controlPlaneLocation = { lat: entry.lat, lon: entry.lon, label: entry.label ?? undefined };
      return json(response, 200, controlPlaneLocation);
    });
  }

  // NOC map: Bedrock's own declared location.
  if (method === "PUT" && karst === "/bedrock/location") {
    return readBody(request).then((entry) => {
      if (typeof entry.lat !== "number" || typeof entry.lon !== "number") return error(response, 422, "invalid_argument", "lat and lon are required numbers");
      bedrock.location = { lat: entry.lat, lon: entry.lon, label: entry.label ?? undefined };
      return json(response, 200, bedrock.location);
    });
  }

  // Scaler Advisor view (ADR-0045 §7 Phase 1 PR 5) -- karst-control's own
  // proxy of karst-scaler advise's loopback /recommendations endpoint. No
  // live karst-scaler process exists in this dev flow, so this is a fixed
  // snapshot, not a tick replay.
  if (method === "GET" && karst === "/scaler/recommendations") {
    return json(response, 200, {
      tick_unix: 1700000000,
      recommendation: {
        pools: [
          { pool_id: "aws-use1", desired_nodes: 5, cost_delta: 340.5, binding_constraint: "headroom" },
          { pool_id: "onprem-dc1", desired_nodes: 3, cost_delta: 0, binding_constraint: "none" },
        ],
        total_cost_delta: -12.3,
        baseline_cost: 982.1,
      },
      configured_nodes: { "aws-use1": 2, "onprem-dc1": 3 },
    });
  }

  // ADR-0045 §4c's deployment-wide region allowlist (package regionallow).
  if (method === "GET" && karst === "/regions") return json(response, 200, allowedRegions);
  if (method === "POST" && karst === "/regions") {
    return readBody(request).then((entry) => {
      if (!entry.provider || !entry.region) return error(response, 422, "invalid_argument", "provider and region are required");
      if (allowedRegions.some((r) => r.provider === entry.provider && r.region === entry.region)) return error(response, 412, "already_exists", "region already allowed");
      const allowed = { provider: entry.provider, region: entry.region };
      allowedRegions.push(allowed);
      return json(response, 201, allowed);
    });
  }
  const regionMatch = karst.match(/^\/regions\/([^/]+)\/([^/]+)$/);
  if (regionMatch && method === "DELETE") {
    const before = allowedRegions.length;
    allowedRegions = allowedRegions.filter((r) => !(r.provider === regionMatch[1] && r.region === regionMatch[2]));
    if (allowedRegions.length === before) return error(response, 404, "not_found", "region not allowed");
    return noContent(response);
  }

  // Console first-run onboarding gate.
  // A test can override this per-request with an x-mock-firstrun-completed
  // header (set via page.setExtraHTTPHeaders) rather than mutating the
  // shared firstRunCompleted flag -- this one setting gates the entire
  // app's render tree, so a global mutation would race every other test
  // running against this same long-lived mock process in another worker.
  if (method === "GET" && karst === "/firstrun") {
    const override = request.headers["x-mock-firstrun-completed"];
    const completed = override !== undefined ? override === "true" : firstRunCompleted;
    return json(response, 200, { completed });
  }
  if (method === "POST" && karst === "/firstrun/complete") {
    firstRunCompleted = true;
    return json(response, 200, { completed: true, completed_at: new Date().toISOString() });
  }

  // Per-page guidance-text setting.
  if (method === "GET" && karst === "/tutorial-mode") return json(response, 200, { enabled: tutorialModeEnabled });
  if (method === "PUT" && karst === "/tutorial-mode") {
    return readBody(request).then((entry) => {
      tutorialModeEnabled = Boolean(entry.enabled);
      return json(response, 200, { enabled: tutorialModeEnabled });
    });
  }

  // Deprecated, preserved /cloud-accounts surface (ADR-0045 §6 addendum):
  // still only ever sees aws/azure/gcp, filtering out any kubernetes-typed
  // connection -- same compatibility posture as the real server's handlers.
  if (method === "GET" && karst === "/cloud-accounts") {
    return json(response, 200, infraConnections.filter((item) => item.type !== "kubernetes").map(({ secret, type, ...rest }) => ({ ...rest, provider: type })));
  }
  if (method === "POST" && karst === "/cloud-accounts") {
    return readBody(request).then((entry) => {
      if (!["aws", "azure", "gcp"].includes(entry.provider)) return error(response, 422, "invalid_argument", "provider must be aws, azure, or gcp");
      if (!["read_only", "read_write"].includes(entry.mode)) return error(response, 422, "invalid_argument", "mode must be read_only or read_write");
      if (!entry.secret) return error(response, 422, "invalid_argument", "secret is required");
      const connection = { id: id("infra-connection"), type: entry.provider, mode: entry.mode, label: entry.label ?? undefined, created_at: new Date().toISOString(), secret: entry.secret };
      infraConnections.push(connection);
      const { secret, type, ...rest } = connection;
      return json(response, 201, { ...rest, provider: type });
    });
  }
  const cloudAccountMatch = karst.match(/^\/cloud-accounts\/([^/]+)$/);
  if (cloudAccountMatch && method === "DELETE") return remove(infraConnections, cloudAccountMatch[1], response);
  const cloudAccountRegionsMatch = karst.match(/^\/cloud-accounts\/([^/]+)\/regions$/);
  if (cloudAccountRegionsMatch && method === "GET") {
    const connection = infraConnections.find((item) => item.id === cloudAccountRegionsMatch[1] && item.type !== "kubernetes");
    if (!connection) return error(response, 404, "not_found", "cloud account not found");
    const regions = (discoveryFixtures[connection.type] ?? []).filter((r) => r.enabled || connection.mode === "read_write");
    return json(response, 200, regions);
  }
  // ADR-0045 §6's second addendum: opts an AWS local zone into use.
  const cloudAccountEnableMatch = karst.match(/^\/cloud-accounts\/([^/]+)\/regions\/([^/]+)\/enable$/);
  if (cloudAccountEnableMatch && method === "POST") {
    const connection = infraConnections.find((item) => item.id === cloudAccountEnableMatch[1]);
    if (!connection) return error(response, 404, "not_found", "cloud account not found");
    if (connection.mode !== "read_write") return error(response, 422, "invalid_argument", "enabling a local zone requires a read-write credential");
    if (connection.type !== "aws") return error(response, 422, "invalid_argument", "enabling a local zone is only supported for aws");
    const region = (discoveryFixtures.aws ?? []).find((item) => item.code === cloudAccountEnableMatch[2]);
    if (!region) return error(response, 404, "not_found", "region not found");
    region.enabled = true;
    return json(response, 200, region);
  }

  // Generalized /infrastructure-connections surface (AWS/Azure/GCP/
  // Kubernetes) backing the console's Infrastructure Connections Settings
  // section and the Authorized Locations picker.
  if (method === "GET" && karst === "/infrastructure-connections") {
    return json(response, 200, infraConnections.map(({ secret, ...rest }) => rest));
  }
  if (method === "POST" && karst === "/infrastructure-connections") {
    return readBody(request).then((entry) => {
      if (!["aws", "azure", "gcp", "kubernetes"].includes(entry.type)) return error(response, 422, "invalid_argument", "type must be aws, azure, gcp, or kubernetes");
      if (!["read_only", "read_write"].includes(entry.mode)) return error(response, 422, "invalid_argument", "mode must be read_only or read_write");
      if (!entry.secret) return error(response, 422, "invalid_argument", "secret is required");
      if (entry.type === "kubernetes" && !entry.secret.kubeconfig) return error(response, 422, "invalid_argument", "secret.kubeconfig is required");
      const connection = {
        id: id("infra-connection"), type: entry.type, mode: entry.mode, label: entry.label ?? undefined, created_at: new Date().toISOString(),
        secret: entry.secret, lat: entry.lat, lon: entry.lon, location_label: entry.location_label,
      };
      infraConnections.push(connection);
      const { secret, ...rest } = connection;
      return json(response, 201, rest);
    });
  }
  const infraConnectionMatch = karst.match(/^\/infrastructure-connections\/([^/]+)$/);
  if (infraConnectionMatch && method === "DELETE") return remove(infraConnections, infraConnectionMatch[1], response);
  const infraConnectionResourcesMatch = karst.match(/^\/infrastructure-connections\/([^/]+)\/resources$/);
  if (infraConnectionResourcesMatch && method === "GET") {
    const connection = infraConnections.find((item) => item.id === infraConnectionResourcesMatch[1]);
    if (!connection) return error(response, 404, "not_found", "infrastructure connection not found");
    const resources = (discoveryFixtures[connection.type] ?? []).filter((r) => r.enabled || r.kind !== "local_zone" || connection.mode === "read_write");
    return json(response, 200, resources);
  }

  if (method === "GET" && karst === "/bedrock") return json(response, 200, bedrock);
  if (method === "GET" && karst === "/bedrock/log") return json(response, 200, page(fixture.bedrockLog, url));
  if (method === "GET" && karst === "/bedrock/log/verify") return error(response, 501, "not_implemented", "Bedrock log verification is not implemented");
  if (method === "GET" && karst === "/bedrock/requests") return json(response, 200, fixture.bedrockRequests);
  if (method === "POST" && karst === "/bedrock/requests/export") return json(response, 200, { format: "bedrock-signed-bundle-v1", payload: btoa(JSON.stringify({ bundle: "bedrock-bundle-v1", kind: "request" })) });
  if (method === "POST" && karst === "/bedrock/audit-anchor/export") return json(response, 200, { format: "bedrock-signed-bundle-v1", payload: btoa(JSON.stringify({ bundle: "bedrock-bundle-v1", kind: "request" })) });
  if (method === "POST" && karst === "/bedrock/responses/import") return error(response, 501, "not_implemented", "Bedrock response import is not implemented");
  if (method === "PUT" && karst === "/bedrock/mode") {
    // Mirrors bedrock.Store.SetMode: the acknowledgment is required **only**
    // for enforcing, because only enforcing can cut anyone off. Demanding it
    // for advisory and off — as this mock used to — made the safe direction
    // harder than the dangerous one and modeled a server that does not exist.
    return readBody(request).then((body) => {
      const mode = typeof body.mode === "string" ? body.mode : "enforcing";
      if (!["off", "advisory", "enforcing"].includes(mode)) return error(response, 400, "invalid_argument", `invalid mode ${mode}`);
      if (mode === "enforcing") {
        const acknowledged = Array.isArray(body.acknowledged_cut_off_handles) ? body.acknowledged_cut_off_handles : [];
        if (!sameStrings(acknowledged, bedrock.uncovered_handles)) {
          return json(response, 409, { code: "acknowledgment_mismatch", message: `bedrock: acknowledgment list does not match uncovered nodes: required [${bedrock.uncovered_handles.join(" ")}]`, required_cut_off_handles: bedrock.uncovered_handles });
        }
      }
      bedrock.mode = mode;
      return json(response, 200, bedrock);
    });
  }
  if (method === "GET" && karst === "/posture") return json(response, 200, { as_of: fixture.asOf, window_start: "2026-08-22T20:27:00Z", observed_sessions: 252, eligible_sessions: 247, pq_covered_sessions: 241, lattice_only_sessions: 6, stale_nodes: 3, suites: { "ML-KEM-768 + X25519": 241, "ML-KEM-768 + X25519 (no PSK)": 6 } });
  if (method === "GET" && karst === "/posture/sessions") return json(response, 200, page(fixture.nodes.map((node) => ({ node_handle: node.handle, peer_handle: fixture.nodes[0].handle, ...node.posture })), url));
  if (method === "GET" && karst === "/audit") {
    const entries = fixture.audit.filter((entry) => (!url.searchParams.get("actor") || entry.actor === url.searchParams.get("actor")) && (!url.searchParams.get("action") || entry.action === url.searchParams.get("action")));
    return json(response, 200, { ...page(entries, url), anchor: { last_anchored_sequence: null, last_anchored_at: null, entries_since_anchor: 42, contradicts_anchor: false } });
  }
  if (method === "GET" && karst === "/audit/export") {
    const format = url.searchParams.get("format");
    if (format === "json") return json(response, 200, fixture.audit);
    if (format === "csv") {
      response.writeHead(200, { "content-type": "text/csv; charset=utf-8" });
      return response.end(["sequence,created_at,actor,action,target,detail,previous_hash,hash", ...fixture.audit.map((entry) => [entry.sequence, entry.created_at, entry.actor, entry.action, entry.target, entry.detail ?? "", entry.previous_hash, entry.hash].join(","))].join("\n"));
    }
    return error(response, 400, "invalid_argument", "format must be json or csv");
  }
  if (method === "GET" && karst === "/audit/head") return json(response, 200, { sequence: 42, hash: "audit-hash-42" });
  if (method === "GET" && karst === "/audit/verify") return json(response, 200, { valid: false, first_bad_sequence: 42, head: { sequence: 42, hash: "audit-hash-42" } });
  if (method === "GET" && karst === "/audit/sinks") return json(response, 200, sinks);
  if (method === "POST" && karst === "/audit/sinks") {
    return readBody(request).then((body) => {
      const sink = { id: id("sink"), kind: body.kind ?? "webhook", endpoint: body.endpoint ?? "" };
      sinks.push(sink);
      return json(response, 201, sink);
    });
  }
  const sinkMatch = karst.match(/^\/audit\/sinks\/([^/]+)$/);
  if (sinkMatch && method === "DELETE") {
    // Idempotent, mirroring audit.RemoveSink: removing an id that is not
    // there is success, not a 404.
    sinks = sinks.filter((sink) => sink.id !== sinkMatch[1]);
    return noContent(response);
  }
  return error(response, 404, "not_found", "mock route has not been configured");
});

server.listen(port, "127.0.0.1", () => console.log(`Karst API mock listening at http://127.0.0.1:${port}${prefix}`));
