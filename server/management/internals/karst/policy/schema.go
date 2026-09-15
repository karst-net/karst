// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package policy

// JSONSchema describes [Document] as JSON Schema (2020-12), for an editor's
// autocomplete and inline lint (issue #128). Hand-written rather than
// reflected from Document's struct tags: the two constraints that matter most
// for autocomplete — a "groups" key must start with "group:", an acl's action
// is only ever "accept" — are validation rules in [Document.Validate], not
// something Go's own struct tags carry. TestJSONSchemaMatchesDocument keeps
// this from drifting silently if Document gains a field this does not.
//
// This is deliberately not the full ruleset [Document.Validate] enforces —
// "an acl's src group must be defined in groups", for one, is a
// cross-reference no generic JSON Schema validator expresses — so an editor
// using this for live linting still needs a round trip to /policy/validate
// before saving. What it does buy an editor: key and value completion, and
// catching a whole category of typo (a stray property, a wrong type, an
// action that isn't "accept") without a network round trip.
const JSONSchema = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "Karst access policy",
  "description": "PLAN.md §4.3. Tailscale-compatible in shape: groups name sets of users, tagOwners say who may apply a tag, acls and ssh grant traffic. A rule with no match denies.",
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "groups": {
      "type": "object",
      "description": "Maps \"group:name\" to a list of user identifiers.",
      "propertyNames": { "pattern": "^group:" },
      "additionalProperties": { "type": "array", "items": { "type": "string" } }
    },
    "tagOwners": {
      "type": "object",
      "description": "Maps \"tag:name\" to the groups or users allowed to apply it. Governs who may assign a tag, not who a tagged node can reach.",
      "propertyNames": { "pattern": "^tag:" },
      "additionalProperties": { "type": "array", "items": { "type": "string" } }
    },
    "acls": {
      "type": "array",
      "description": "Accept rules, evaluated as a union. There is no deny form.",
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["action", "src", "dst"],
        "properties": {
          "action": { "const": "accept", "description": "The only action that exists." },
          "src": { "type": "array", "items": { "type": "string" }, "minItems": 1, "description": "Selectors: \"*\", \"tag:name\", \"group:name\", or a user identifier." },
          "dst": { "type": "array", "items": { "type": "string" }, "minItems": 1, "description": "Each a \"selector:ports\" pair, e.g. \"tag:prod:443\" or \"*:22,80,1000-2000\". A selector may also be an explicit CIDR (always with a \"/\", e.g. \"10.50.0.0/24:80,443\" or \"fd00:50::/32:*\" — a bare address is not recognized) to grant a routed subnet directly, matched by the packet's real destination address rather than by node identity." }
        }
      }
    },
    "ssh": {
      "type": "array",
      "description": "Independent SSH admission gate (plans/phase-6/07-acl-gated-ssh.md §3.1). A connection must be permitted by both acls and ssh to reach port 22; absent means SSH is governed by acls alone.",
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["action", "src", "dst"],
        "properties": {
          "action": { "const": "accept", "description": "The only action that exists." },
          "src": { "type": "array", "items": { "type": "string" }, "minItems": 1, "description": "Selectors: \"*\", \"tag:name\", \"group:name\", or a user identifier." },
          "dst": { "type": "array", "items": { "type": "string" }, "minItems": 1, "description": "A selector with no port suffix — SSH gating is always port 22." }
        }
      }
    }
  }
}
`
