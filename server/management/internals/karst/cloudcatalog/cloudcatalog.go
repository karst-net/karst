// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// Package cloudcatalog is a static, hand-maintained table of approximate
// coordinates for AWS/Azure/GCP regions and zones. None of the three
// providers' own "list regions" APIs return a latitude/longitude -- that is
// the gap this package fills, joined against whatever
// infraconnections.Discover returns live from the provider. There are no
// entries for KindNamespace: a Kubernetes namespace has no catalog-knowable
// coordinates, so infraconnections.Discover never calls this package's
// Lookup for one -- the console falls back to the connection's own
// operator-declared location instead.
//
// Coordinates are approximate (the metro area the region/zone is marketed
// as being in, not a facility address) and this table is not claimed to be
// exhaustive -- a provider that adds a region this table doesn't yet know
// about still shows up from Discover, just without a map pin, rather than
// being dropped. Extend the per-provider slice below when that happens.
package cloudcatalog

// Kind distinguishes a standard region from a zone with its own distinct
// physical location (AWS Local Zones, AWS Wavelength Zones) from a zone
// that is simply a fault-isolated slice of its parent region and shares its
// coordinates (Azure Availability Zones, GCP zones).
type Kind string

const (
	KindRegion    Kind = "region"
	KindLocalZone Kind = "local_zone"
	KindZone      Kind = "zone"
	// KindNamespace is a Kubernetes namespace -- see the package doc
	// comment for why it never has a catalog entry.
	KindNamespace Kind = "namespace"
)

// Region is one catalog entry: a region or zone code with its approximate
// coordinates. ParentRegion is set for a Kind other than KindRegion.
type Region struct {
	Provider     string  `json:"provider"`
	Code         string  `json:"code"`
	Name         string  `json:"name"`
	Lat          float64 `json:"lat"`
	Lon          float64 `json:"lon"`
	Kind         Kind    `json:"kind"`
	ParentRegion string  `json:"parent_region,omitempty"`
}

// Lookup returns the catalog entry for a (provider, code) pair, if known.
func Lookup(provider, code string) (Region, bool) {
	for _, r := range byProvider(provider) {
		if r.Code == code {
			return r, true
		}
	}
	return Region{}, false
}

// All returns every catalog entry for a provider, or nil for an unknown one.
func All(provider string) []Region {
	return byProvider(provider)
}

func byProvider(provider string) []Region {
	switch provider {
	case "aws":
		return aws
	case "azure":
		return azure
	case "gcp":
		return gcp
	default:
		return nil
	}
}
