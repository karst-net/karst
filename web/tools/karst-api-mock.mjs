// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import http from "node:http";
import { buildFixture } from "../fixtures/karst-api.mjs";

const fixture = buildFixture();
const port = Number.parseInt(process.env.KARST_API_MOCK_PORT ?? "4010", 10);
const prefix = "/api/karst/v1";

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

function policyValidation() {
  return { valid: true, diagnostics: [] };
}

const server = http.createServer((request, response) => {
  const url = new URL(request.url, `http://${request.headers.host ?? "localhost"}`);
  if (!url.pathname.startsWith(prefix)) return error(response, 404, "not_found", "unknown mock path");
  const path = url.pathname.slice(prefix.length) || "/";
  const method = request.method ?? "GET";
  const nodeMatch = path.match(/^\/nodes\/([^/]+)(?:\/(paths|posture))?$/);
  const relayMatch = path.match(/^\/relays\/([^/]+)(?:\/health)?$/);

  if (method === "GET" && path === "/nodes") return json(response, 200, page(fixture.nodes, url));
  if (nodeMatch) {
    const node = fixture.nodes.find((item) => item.handle === nodeMatch[1]);
    if (!node) return error(response, 404, "not_found", "node not found");
    if (method === "GET" && nodeMatch[2] === "paths") return json(response, 200, { observed_at: fixture.asOf, paths: [{ peer_handle: fixture.nodes[1].handle, kind: "relay", endpoint: null, relay_id: fixture.relays[0].id, since: null, observed_at: fixture.asOf }] });
    if (method === "GET" && nodeMatch[2] === "posture") return json(response, 200, node.posture);
    if (method === "GET" || method === "PATCH") return json(response, 200, node);
    if (method === "DELETE") return response.writeHead(204).end();
  }
  if (method === "GET" && path === "/policy") return json(response, 200, fixture.policy);
  if (method === "GET" && path === "/policy/versions") return json(response, 200, { items: [fixture.policy], next_cursor: null });
  if (method === "GET" && /^\/policy\/versions\/\d+$/.test(path)) return json(response, 200, fixture.policy);
  if (method === "POST" && path === "/policy/validate") return json(response, 200, policyValidation());
  if (method === "POST" && path === "/policy/preview") return json(response, 200, { added: [{ source: "group:sre", destination: "tag:prod", protocol: "tcp", ports: "22" }], removed: [{ source: "group:contractors", destination: "tag:prod", protocol: "tcp", ports: "22" }] });
  if ((method === "PUT" && path === "/policy") || (method === "POST" && /^\/policy\/rollback\/\d+$/.test(path))) return json(response, 200, fixture.policy);
  if (method === "POST" && path === "/policy/test") return json(response, 200, { passed: false, results: [{ name: "SRE SSH access", passed: true, message: "allowed" }, { name: "contractor production SSH", passed: false, message: "expected deny, got allow" }] });
  if (method === "GET" && path === "/relays") return json(response, 200, fixture.relays);
  if (method === "POST" && path === "/relays") return json(response, 201, fixture.relays[0]);
  if (relayMatch && method === "GET" && path.endsWith("/health")) return json(response, 200, fixture.relays.find((item) => item.id === relayMatch[1])?.health ?? fixture.relays[0].health);
  if (relayMatch && method === "DELETE") return response.writeHead(204).end();
  if (method === "GET" && path === "/bedrock") return json(response, 200, { mode: "advisory", quorum: 2, roots: [], authorities: [] });
  if (method === "GET" && path === "/bedrock/log") return json(response, 200, { items: [], next_cursor: null });
  if (method === "GET" && path === "/bedrock/log/verify") return error(response, 501, "not_implemented", "Bedrock log verification is not implemented");
  if (method === "GET" && path === "/bedrock/requests") return json(response, 200, []);
  if (method === "POST" && path === "/bedrock/requests/export") return error(response, 501, "not_implemented", "Bedrock request export is not implemented");
  if (method === "POST" && path === "/bedrock/responses/import") return error(response, 501, "not_implemented", "Bedrock response import is not implemented");
  if (method === "PUT" && path === "/bedrock/mode") return error(response, 409, "acknowledgement_mismatch", "acknowledged handles are out of date");
  if (method === "GET" && path === "/posture") return json(response, 200, { as_of: fixture.asOf, window_start: "2026-08-22T20:27:00Z", observed_sessions: 252, eligible_sessions: 247, pq_covered_sessions: 241, lattice_only_sessions: 6, stale_nodes: 3, suites: { "ML-KEM-768 + X25519": 241, "ML-KEM-768 + X25519 (no PSK)": 6 } });
  if (method === "GET" && path === "/posture/sessions") return json(response, 200, page(fixture.nodes.map((node) => ({ node_handle: node.handle, peer_handle: fixture.nodes[0].handle, ...node.posture })), url));
  if (method === "GET" && path === "/audit") {
    const entries = fixture.audit.filter((entry) => (!url.searchParams.has("actor") || entry.actor === url.searchParams.get("actor")) && (!url.searchParams.has("action") || entry.action === url.searchParams.get("action")));
    return json(response, 200, { ...page(entries, url), anchor: { last_anchored_sequence: null, last_anchored_at: null, entries_since_anchor: 42 } });
  }
  if (method === "GET" && path === "/audit/export") return json(response, 200, fixture.audit);
  if (method === "GET" && path === "/audit/head") return json(response, 200, { sequence: 42, hash: "audit-hash-42" });
  if (method === "GET" && path === "/audit/verify") return json(response, 200, { valid: false, first_bad_sequence: 42, head: { sequence: 42, hash: "audit-hash-42" } });
  if (method === "POST" && path === "/audit/sinks") return json(response, 201, { id: "sink-fixture-1", kind: "webhook", endpoint: "https://audit.example.test/ingest" });
  return error(response, 404, "not_found", "mock route has not been configured");
});

server.listen(port, "127.0.0.1", () => console.log(`Karst API mock listening at http://127.0.0.1:${port}${prefix}`));
