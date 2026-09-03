// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package routes

import "testing"

func TestDefaultRoutesRequireClientConsentByDefault(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		network  *string
		explicit *bool
		want     bool
	}{
		{name: "IPv4 exit", network: stringPtr("0.0.0.0/0"), want: true},
		{name: "IPv6 exit", network: stringPtr("::/0"), want: true},
		{name: "subnet", network: stringPtr("10.0.0.0/8"), want: false},
		{name: "domain route", network: nil, want: false},
		{name: "explicit legacy false", network: stringPtr("0.0.0.0/0"), explicit: boolPtr(false), want: false},
		{name: "explicit true", network: stringPtr("10.0.0.0/8"), explicit: boolPtr(true), want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := defaultSkipAutoApply(tc.network, tc.explicit); got != tc.want {
				t.Fatalf("defaultSkipAutoApply() = %v, want %v", got, tc.want)
			}
		})
	}
}

func stringPtr(value string) *string {
	return &value
}

func boolPtr(value bool) *bool {
	return &value
}
