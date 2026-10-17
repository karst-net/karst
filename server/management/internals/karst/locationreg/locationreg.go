// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// Package locationreg is the admin-authorized "possible locations" registry
// the NOC map draws as hollow markers (ADR-0046 §1 extension): a site an
// operator has declared this deployment may place infrastructure at,
// independent of whether anything is actually deployed there yet.
//
// This is deliberately additive, not a foreign key. relayreg/turncred/the
// group-location and Bedrock/control-plane locations below are unaffected by
// what is or is not in this registry — a relay may still declare a location
// that is not an authorized one. Coupling the two would force every existing
// declared-location caller through a new constraint nobody asked for; see
// the NOC map plan's own "scope boundary" note. This registry exists only to
// answer, visually, "where are we authorized to be."
package locationreg

import "github.com/netbirdio/netbird/management/internals/karst/geo"

// Entry is one authorized location as an operator writes it.
type Entry struct {
	Lat   float64 `json:"lat"`
	Lon   float64 `json:"lon"`
	Label string  `json:"label,omitempty"`
	// Kind is a free-text tag ("datacenter", "aws-region", "aws-local-zone",
	// ...) for grouping/display only. Not validated against a fixed list —
	// this codebase has no native AWS-local-zone (or any other cloud
	// topology) registry to validate it against, and inventing one is out
	// of scope here.
	Kind string `json:"kind,omitempty"`
}

// Compile validates one entry. Named to match relayreg.Compile/turncred's
// own validate() — every registry in this package family runs API input
// through the same validate-then-store shape.
func Compile(entry Entry) (Entry, error) {
	if err := geo.ValidLocation(entry.Lat, entry.Lon); err != nil {
		return Entry{}, err
	}
	return entry, nil
}
