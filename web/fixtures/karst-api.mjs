// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// Interesting, deterministic fixture data for the contract mock. Do not turn
// these into empty arrays: the console must exercise pagination, stale reports,
// relay paths, lattice-only sessions, and an audit-chain failure before it sees
// a production account.
export function buildFixture() {
  const asOf = "2026-08-22T20:32:00Z";
  const nodes = Array.from({ length: 50 }, (_, index) => {
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
    relays: [
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
      document: '{\n  // production access\n  "acls": [{"src": ["group:sre"], "dst": ["tag:prod:22"]}]\n}',
      author: "user-owner",
      created_at: "2026-08-22T19:04:00Z",
    },
    audit: [
      { sequence: 41, created_at: "2026-08-22T19:04:00Z", actor: "user-owner", action: "policy.write", target: "policy", detail: "version 7", previous_hash: "audit-hash-40", hash: "audit-hash-41" },
      { sequence: 42, created_at: "2026-08-22T20:01:00Z", actor: "user-sre", action: "node.disable", target: "node-0049-karst-fixture-handle", detail: "offboarding", previous_hash: "audit-hash-41", hash: "audit-hash-42" },
    ],
  };
}
