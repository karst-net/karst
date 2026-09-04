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
let setupKeys = [];
let users = seedUsers();
let groups = seedGroups();
let routes = fixture.routes.map((route) => ({ ...route }));
let nameservers = fixture.nameservers.map((group) => ({ ...group }));
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
// pipeline actually names things — `karst-client_<version>_<arch>.deb`, not the
// `karst-linux-amd64.deb` this fixture used to invent. A fixture that describes
// artifacts nothing builds lets the download test pass for a page that would be
// empty in production, which is the fixture-only failure GitHub issue [#47](https://github.com/karst-net/karst/issues/47) and 43
// are about.
//
// No Windows row: the client is Phase 8, so a manifest offering one would be
// describing a file that does not exist.
const releaseAssets = [
  { platform: "macos", arch: "universal", format: "pkg", name: "karst-macos-universal.pkg", url: "/releases/karst-macos-universal.pkg", sha256: "31a05d7fd3946767a06d2638a63d7f6df13ce8cb4a4e06631d0a0258de4f4f57" },
  { platform: "linux", arch: "amd64", format: "deb", name: "karst-client_0.1.0-1_amd64.deb", url: "/releases/karst-client_0.1.0-1_amd64.deb", sha256: "c10b418474a5ba59159d55ef58d54a24d8b9f341f089f67f1fd9b20a398b12f7" },
  { platform: "linux", arch: "arm64", format: "deb", name: "karst-client_0.1.0-1_arm64.deb", url: "/releases/karst-client_0.1.0-1_arm64.deb", sha256: "9d5f2a1c3e4b6789012345678901234567890abcdef1234567890abcdef12345" },
  { platform: "linux", arch: "amd64", format: "rpm", name: "karst-client-0.1.0-1.x86_64.rpm", url: "/releases/karst-client-0.1.0-1.x86_64.rpm", sha256: "b783bb7b65d1b9c8a5b0f81fd22cfe481ba6807e2b01986f8cf07b61185d1139" },
  { platform: "linux", arch: "arm64", format: "rpm", name: "karst-client-0.1.0-1.aarch64.rpm", url: "/releases/karst-client-0.1.0-1.aarch64.rpm", sha256: "4f1e2d3c4b5a69788796a5b4c3d2e1f00112233445566778899aabbccddeeff0" },
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
  if (path === "/__mock__/fixture" && method === "PUT") {
    return readBody(request).then((body) => {
      const empty = Boolean(body.empty);
      fixture = buildFixture({ empty });
      setupKeys = [];
      users = empty ? [] : seedUsers();
      groups = empty ? [] : seedGroups();
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

  // The portal namespace is deliberately separate from the administrative
  // router. Fixtures only expose the member's own devices; there is no user
  // identifier to forge in any of these paths.
  if (method === "GET" && karst === "/me/devices") return json(response, 200, memberDevices);
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
    if (method === "GET" && nodeMatch[2] === "paths") return json(response, 200, { observed_at: fixture.asOf, paths: [{ peer_handle: fixture.nodes[1].handle, kind: "relay", endpoint: null, relay_id: fixture.relays[0]?.id ?? null, since: null, observed_at: fixture.asOf }] });
    if (method === "GET" && nodeMatch[2] === "posture") return json(response, 200, node.posture);
    if (method === "GET") return json(response, 200, node);
    // Name and nothing else, exactly as the contract's updateNode enforces: a
    // console that offered tags here would pass against a lenient mock and fail
    // against the server.
    if (method === "PATCH") return readBody(request).then((body) => {
      if (typeof body.name !== "string" || !body.name.trim()) return error(response, 400, "invalid_argument", "name is required");
      if (body.tags !== undefined || body.enabled !== undefined || body.expires_at !== undefined) return error(response, 422, "invalid_argument", "only name is currently mutable for a Karst node");
      node.name = body.name.trim();
      return json(response, 200, node);
    });
    if (method === "DELETE") { fixture.nodes.splice(index, 1); return noContent(response); }
  }
  if (method === "GET" && karst === "/policy") return json(response, 200, fixture.policy);
  if (method === "GET" && karst === "/policy/versions") return json(response, 200, page(fixture.policyVersions, url));
  if (method === "GET" && /^\/policy\/versions\/\d+$/.test(karst)) {
    const version = Number.parseInt(karst.split("/").at(-1), 10);
    const policy = fixture.policyVersions.find((item) => item.version === version);
    return policy ? json(response, 200, policy) : error(response, 404, "not_found", "policy version not found");
  }
  if (method === "POST" && karst === "/policy/validate") return readBody(request).then((body) => json(response, 200, policyValidation(body.document ?? "")));
  if (method === "POST" && karst === "/policy/preview") return json(response, 200, { added: [{ source: "group:sre", destination: "tag:prod", protocol: "tcp", ports: "22" }], removed: [{ source: "group:contractors", destination: "tag:prod", protocol: "tcp", ports: "22" }] });
  if ((method === "PUT" && karst === "/policy") || (method === "POST" && /^\/policy\/rollback\/\d+$/.test(karst))) return json(response, 200, fixture.policy);
  if (method === "POST" && karst === "/policy/test") return json(response, 200, { passed: false, results: [{ name: "SRE SSH access", passed: true, message: "allowed" }, { name: "contractor production SSH", passed: false, message: "expected deny, got allow" }] });

  if (method === "GET" && karst === "/relays") return json(response, 200, fixture.relays);
  if (method === "POST" && karst === "/relays") {
    return readBody(request).then((entry) => {
      if (!entry.address || !entry.identity_key) return error(response, 422, "invalid_argument", "address and identity_key are required");
      if (fixture.relays.some((relay) => relay.address === entry.address)) return error(response, 412, "already_exists", "relay already exists");
      const relay = { id: id("relay"), address: entry.address, identity_key: entry.identity_key, region: entry.region ?? "default", tls_server_name: entry.tls_server_name ?? "", health: { source: "roster_mtime", last_confirmed_at: null, sessions: null, bytes: null, admission_state: "unknown" } };
      fixture.relays.push(relay);
      return json(response, 201, relay);
    });
  }
  if (relayMatch && method === "GET" && karst.endsWith("/health")) return json(response, 200, fixture.relays.find((item) => item.id === relayMatch[1])?.health ?? fixture.relays[0].health);
  if (relayMatch && method === "DELETE") return remove(fixture.relays, relayMatch[1], response);

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
  if (method === "POST" && karst === "/audit/sinks") return readBody(request).then((body) => json(response, 201, { id: id("sink"), kind: body.kind ?? "webhook", endpoint: body.endpoint ?? "" }));
  return error(response, 404, "not_found", "mock route has not been configured");
});

server.listen(port, "127.0.0.1", () => console.log(`Karst API mock listening at http://127.0.0.1:${port}${prefix}`));
