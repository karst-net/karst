<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Migrating from WireGuard or Tailscale

Karst has **no WireGuard interoperability bridge**. Its 2,378-byte PHREATIC
handshake cannot use WireGuard framing, so migration is a clean cutover, not a
period in which one peer speaks both protocols. You may run old and new
networks side by side for validation, but traffic does not cross between them.

Start with [Getting started](GETTING-STARTED.md), and use the
[operations manual](OPERATIONS.md) for production rollout and rollback.

## 1. Conceptual mapping

| Existing concept | Karst equivalent | Important difference |
|---|---|---|
| WireGuard peer public key and `AllowedIPs` | Bedrock-authorized node identity plus a server-compiled ACL | Identity authorization, address assignment, and traffic authorization are separate. ACLs are default deny and enforced at both endpoints. |
| WireGuard endpoint and keepalive | AVEN-discovered direct path | Candidates change dynamically; a static endpoint is not the identity. |
| WireGuard preshared key | Server-derived per-pair, per-epoch PSK | Operators do not copy pairwise PSKs between nodes. |
| Tailscale coordination server | Self-hosted `karst-control` | The server distributes policy and secrets but does not hold node decryption keys; Bedrock constrains node admission. |
| Tailscale ACL/tag owner | Karst `groups`, `tagOwners`, and `acls` | The policy shape is intentionally familiar, but only `accept` exists and unknown fields fail validation. |
| DERP | Ponor relay | Ponor carries PHREATIC ciphertext and uses a signed roster; it is not DERP-compatible. TURN is an additional fallback. |
| Tailnet lock | Bedrock | Bedrock uses a hash-chained, quorum-signed authorization log and offline roots. |
| Subnet router / exit node | Advertised Karst route / consented exit route | Route use remains ACL-gated and default-route use requires client consent. |

## 2. Inventory before changing traffic

Export every WireGuard `wg0.conf` or Tailscale ACL, node/user list, tags,
subnet routes, DNS settings, exit-node use, and relay/firewall exceptions.
Record the applications and destination ports actually required; do not
translate broad `AllowedIPs = 0.0.0.0/0` into an allow-all ACL by reflex.

Choose stable Karst groups and tags, identify Bedrock root custodians, and
deploy the control and relay services. Enroll a non-production canary for each
OS and location. Confirm direct and relayed paths, DNS, policy enforcement,
revocation, metrics, backup/restore, and your load-balanced control entry point
before scheduling cutover.

## 3. Worked WireGuard-to-Karst policy example

Suppose `wg0.conf` grants Alice's laptop access to a server's overlay address
on all ports and Bob's laptop access to the same peer on SSH only:

```ini
[Peer] # alice-laptop
PublicKey = ALICE_WIREGUARD_PUBLIC_KEY
AllowedIPs = 10.20.0.10/32

[Peer] # bob-laptop
PublicKey = BOB_WIREGUARD_PUBLIC_KEY
AllowedIPs = 10.20.0.10/32
```

WireGuard `AllowedIPs` combines routing and peer-key selection; it does not by
itself express the per-user port distinction. In Karst, tag the server
`tag:production` and use this policy:

```json migration-policy
{
  "groups": {
    "group:admins": ["alice@example.com"],
    "group:operators": ["bob@example.com"]
  },
  "tagOwners": {
    "tag:production": ["group:admins"]
  },
  "acls": [
    { "action": "accept", "src": ["group:admins"], "dst": ["tag:production:*"] },
    { "action": "accept", "src": ["group:operators"], "dst": ["tag:production:22"] }
  ]
}
```

This exact fenced document is parsed by the server policy package's
`TestMigrationGuidePolicyIsValid` test. Against a running authenticated server,
paste it into Console → Access policy and run Validate and Preview before Save,
or POST it as the `document` field to `/api/karst/v1/policy/validate`. Confirm
Alice reaches intended ports, Bob reaches TCP/22 only, and an unrelated canary
reaches neither. The ACL grants connectivity; address routing still comes from
the node netmap.

## 4. Clean-cutover procedure

1. Lower DNS TTLs and freeze policy changes in the old system. Take a final
   inventory and define measurable acceptance and rollback checks.
2. Install Karst alongside the old client without routing production traffic
   through it. Avoid overlapping interface routes; use canary destinations.
3. Enroll every node, attach users/tags, import and validate least-privilege
   ACLs, and verify Bedrock coverage before enabling network lock.
4. Test each required flow, relay fallback, DNS, subnet routes, exit-route
   consent, revocation, observability, backup/restore, and control failover.
5. During the change window, stop the old VPN, remove its routes and DNS
   integration, start Karst, and verify `karst status` plus the acceptance
   matrix. There is no mixed-protocol fallback path.
6. If checks fail, stop Karst, run `karst dns revert` if needed, restore the
   old client's routes/DNS, and investigate off the production path.
7. After the observation window, revoke old WireGuard keys or Tailscale nodes,
   remove obsolete firewall/relay rules, raise DNS TTLs, and retain the
   migration record for audit.

## 5. Tailscale-specific notes

Translate identities and groups before ACL rules, and tags before tagged
destinations. Recreate routes and exit-node consent explicitly; do not assume
that a syntactically similar ACL implies equivalent routing. Replace DERP
assumptions with a Ponor roster and, where needed, TURN. Rehearse device and
user deprovisioning through the IdP/SCIM path because that is the operational
equivalent of removing a Tailscale node or user, not merely deleting an ACL
line.
