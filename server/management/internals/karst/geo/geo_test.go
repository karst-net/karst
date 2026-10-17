// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package geo

import "testing"

func TestValidLocation(t *testing.T) {
	cases := []struct {
		name    string
		lat     float64
		lon     float64
		wantErr bool
	}{
		{"zero", 0, 0, false},
		{"corners", 90, 180, false},
		{"negative corners", -90, -180, false},
		{"lat too high", 90.1, 0, true},
		{"lat too low", -90.1, 0, true},
		{"lon too high", 0, 180.1, true},
		{"lon too low", 0, -180.1, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := ValidLocation(c.lat, c.lon)
			if (err != nil) != c.wantErr {
				t.Fatalf("ValidLocation(%v, %v) = %v, wantErr %v", c.lat, c.lon, err, c.wantErr)
			}
		})
	}
}
