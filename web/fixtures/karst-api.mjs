// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// Interesting, deterministic fixture data for the contract mock. Do not turn
// these into empty arrays: the console must exercise pagination, stale reports,
// relay paths, lattice-only sessions, and an audit-chain failure before it sees
// a production account.
export function buildFixture({ empty = false } = {}) {
  const asOf = "2026-08-22T20:32:00Z";
  const nodes = Array.from({ length: empty ? 0 : 50 }, (_, index) => {
    const n = index + 1;
    const status = n % 17 === 0 ? "stale" : n % 11 === 0 ? "lattice_only" : "pq";
    return {
      handle: `node-${String(n).padStart(4, "0")}-karst-fixture-handle`,
      name: n === 1 ? "sre-laptop" : n === 2 ? "prod-db-01" : `fixture-node-${n}`,
      user_id: n % 3 === 0 ? "user-sre" : "user-it",
      tags: n % 2 === 0 ? ["prod"] : ["engineering"],
      enabled: n !== 49,
      expires_at: n === 50 ? "2026-09-01T00:00:00Z" : null,
      created_at: "2026-06-01T12:00:00Z",
      last_seen_at: status === "stale" ? "2026-08-22T17:01:00Z" : asOf,
      posture: {
        status,
        suite: status === "stale" ? null : "ML-KEM-768 + X25519",
        psk_epoch: status === "stale" ? null : 173,
        lattice_only: status === "lattice_only",
        observed_at: status === "stale" ? "2026-08-22T17:01:00Z" : asOf,
      },
    };
  });

  return {
    asOf,
    nodes,
    relays: empty ? [] : [
      {
        id: "relay-fixture-denver",
        address: "relay-den.example.test:443",
        identity_key: "fixture-public-key-denver",
        region: "us-central",
        tls_server_name: "relay-den.example.test",
        health: { source: "roster_mtime", last_confirmed_at: asOf, sessions: null, bytes: null, admission_state: "confirmed" },
      },
      {
        id: "relay-fixture-frankfurt",
        address: "relay-fra.example.test:443",
        identity_key: "fixture-public-key-frankfurt",
        region: "eu-central",
        tls_server_name: "relay-fra.example.test",
        health: { source: "roster_mtime", last_confirmed_at: "2026-08-22T20:30:00Z", sessions: null, bytes: null, admission_state: "stale" },
      },
    ],
    policy: {
      version: 7,
      document: '{\n  "acls": [{"action": "accept", "src": ["*"], "dst": ["tag:prod:22"]}]\n}',
      author: "user-owner",
      created_at: "2026-08-22T19:04:00Z",
    },
    policyVersions: [
      { version: 7, document: '{\n  "acls": [{"action": "accept", "src": ["*"], "dst": ["tag:prod:22"]}]\n}', author: "user-owner", created_at: "2026-08-22T19:04:00Z" },
      { version: 6, document: '{\n  "acls": [{"src": ["group:engineering"], "dst": ["tag:staging:22"]}]\n}', author: "user-sre", created_at: "2026-08-21T16:20:00Z" },
    ],
    audit: empty ? [] : [
      { sequence: 41, created_at: "2026-08-22T19:04:00Z", actor: "user-owner", action: "policy.write", target: "policy", detail: "version 7", previous_hash: "audit-hash-40", hash: "audit-hash-41" },
      { sequence: 42, created_at: "2026-08-22T20:01:00Z", actor: "user-sre", action: "node.disable", target: "node-0049-karst-fixture-handle", detail: "offboarding", previous_hash: "audit-hash-41", hash: "audit-hash-42" },
    ],
    // A log with a genesis and one node signature, and a request that is one
    // signature short of its quorum: the console must render "1 of 2" as
    // unsatisfied rather than rounding it up to signed.
    bedrockLog: empty ? [] : [
      { sequence: 1, op: "genesis", tier: "root", subject: "fixture.karst.test", signed_at: "2026-06-01T12:00:00Z", signers: ["root-a", "root-b"] },
      { sequence: 12, op: "node.sign", tier: "authority", subject: "node-0002-karst-fixture-handle", signed_at: "2026-08-20T09:12:00Z", signers: ["authority-eu"] },
    ],
    bedrockRequests: empty ? [] : [
      { id: "request-fixture-1", op: "node.sign", subject: "node-0001-karst-fixture-handle", created_at: "2026-08-22T18:40:00Z", quorum: 2, signatures: 1 },
    ],
    routes: empty ? [] : [
      { id: "route-fixture-aws", network_id: "aws-prod", description: "Production VPC", enabled: true, network: "10.10.0.0/16", peer_groups: ["group-gateways"], groups: ["group-engineering"], metric: 100, masquerade: true, keep_route: false },
    ],
    nameservers: empty ? [] : [
      { id: "ns-fixture-corp", name: "corp-internal", description: "Internal zones", nameservers: [{ ip: "10.10.0.53", ns_type: "udp", port: 53 }], enabled: true, groups: ["group-engineering"], primary: false, domains: ["corp.example.test"], search_domains_enabled: true },
    ],
  };
}
