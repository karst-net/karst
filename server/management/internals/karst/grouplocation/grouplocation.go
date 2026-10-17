// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// Package grouplocation declares where a group's machines are, for exactly
// one purpose: placing an exit-node/subnet-router marker on the NOC map
// (ADR-0046 §1) at the location of the gateway group a route's peer_groups
// names.
//
// A route (server/route/route.go, the fork's own Route type) only ever
// names peer_groups — group IDs, never a single machine — so "the gateway
// machine's location" concretely means a location declared on the group,
// not on the fork's own Group entity (types.Group) itself.
//
// This is a Karst-owned side table, the same shape of addition relayreg and
// turncred already are beside the inherited fork, rather than a field added
// to types.Group: that type is upstream-owned scaffolding reused across
// ACL/DNS/policy with its own REST surface and OpenAPI schema, and groups.tsx
// already treats cross-references into Karst-owned concerns as a
// best-effort match by ID/name rather than a foreign key (see its own
// selectorFor comment) — this follows the same convention. A group that is
// renamed or deleted on the fork side simply leaves its location entry
// unreferenced; nothing here enforces referential integrity against it.
package grouplocation

import (
	"errors"

	"github.com/netbirdio/netbird/management/internals/karst/geo"
)

// Entry is one group's declared location as an operator writes it.
type Entry struct {
	GroupID string  `json:"group_id"`
	Lat     float64 `json:"lat"`
	Lon     float64 `json:"lon"`
	Label   string  `json:"label,omitempty"`
}

var errEmptyGroupID = errors.New("group_id is empty")

func Compile(entry Entry) (Entry, error) {
	if entry.GroupID == "" {
		return Entry{}, errEmptyGroupID
	}
	if err := geo.ValidLocation(entry.Lat, entry.Lon); err != nil {
		return Entry{}, err
	}
	return entry, nil
}
