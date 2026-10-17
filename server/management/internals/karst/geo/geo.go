// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// Package geo holds the one validation rule every operator-declared NOC-map
// position shares (ADR-0046 §1): a latitude/longitude pair, bounds-checked
// the same way regardless of which component it is attached to.
//
// relayreg.Location/relayreg.ValidLocation predate this package and are now
// aliases of the types here -- see relayreg.go -- so a relay's own wire
// shape (JSON, proto) is unchanged by this extraction.
package geo

import "fmt"

// Location is a point an operator declares for a component, never derived
// from an address, region code, or any other field -- matching relayreg's
// existing no-inference rule (ADR-0046 §1, ADR-0048).
type Location struct {
	Lat   float64 `json:"lat"`
	Lon   float64 `json:"lon"`
	Label string  `json:"label,omitempty"`
}

// ValidLocation bounds-checks a latitude/longitude pair. Shared by every
// package that accepts a declared location, so a typo is rejected with the
// same named-field message regardless of which component it was declared on.
func ValidLocation(lat, lon float64) error {
	if lat < -90 || lat > 90 {
		return fmt.Errorf("location.lat is %v, want -90..90", lat)
	}
	if lon < -180 || lon > 180 {
		return fmt.Errorf("location.lon is %v, want -180..180", lon)
	}
	return nil
}
