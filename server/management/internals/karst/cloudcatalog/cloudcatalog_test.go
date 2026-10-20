// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package cloudcatalog

import "testing"

func TestLookupKnownEntry(t *testing.T) {
	got, ok := Lookup("aws", "us-east-1")
	if !ok {
		t.Fatal("want us-east-1 to be found")
	}
	if got.Kind != KindRegion || got.Lat == 0 || got.Lon == 0 {
		t.Fatalf("got %+v, want a region with nonzero coordinates", got)
	}
}

func TestLookupUnknownEntry(t *testing.T) {
	if _, ok := Lookup("aws", "not-a-real-region"); ok {
		t.Fatal("want an unknown code to report not found")
	}
	if _, ok := Lookup("not-a-real-provider", "us-east-1"); ok {
		t.Fatal("want an unknown provider to report not found")
	}
}

func TestAllCoversEveryProvider(t *testing.T) {
	for _, provider := range []string{"aws", "azure", "gcp"} {
		entries := All(provider)
		if len(entries) == 0 {
			t.Fatalf("want at least one catalog entry for %s", provider)
		}
		for _, e := range entries {
			if e.Provider != provider {
				t.Fatalf("entry %+v has provider mismatch, want %s", e, provider)
			}
			if e.Lat < -90 || e.Lat > 90 || e.Lon < -180 || e.Lon > 180 {
				t.Fatalf("entry %+v has out-of-range coordinates", e)
			}
			if e.Kind != KindRegion && e.ParentRegion == "" {
				t.Fatalf("entry %+v is not a region but has no ParentRegion", e)
			}
		}
	}
}

func TestNoDuplicateCodesWithinAProvider(t *testing.T) {
	for _, provider := range []string{"aws", "azure", "gcp"} {
		seen := map[string]bool{}
		for _, e := range All(provider) {
			if seen[e.Code] {
				t.Fatalf("duplicate code %s in %s catalog", e.Code, provider)
			}
			seen[e.Code] = true
		}
	}
}
