// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package cloudaccounts

import (
	"context"
	"fmt"

	"github.com/netbirdio/netbird/management/internals/karst/cloudcatalog"
)

// DiscoveredRegion is one region/zone the provider reports for the
// credential's account, joined against cloudcatalog where possible. Lat/Lon
// are nil when the catalog has no entry for Code yet -- the console still
// lists it, just without a map pin (see cloudcatalog's own doc comment).
//
// Enabled is true for a standard region and for an already opted-in Local
// Zone -- the only two cases a read_only credential ever reports (ADR-0045
// §6's first addendum). A read_write credential's Discover additionally
// reports a Local Zone's group that exists but is not yet opted in, with
// Enabled false, so the console can offer EnableLocalZone for it (ADR-0045
// §6's second addendum) rather than silently omitting it the way read_only
// always has.
type DiscoveredRegion struct {
	Code string            `json:"code"`
	Name string            `json:"name,omitempty"`
	Kind cloudcatalog.Kind `json:"kind"`
	Lat  *float64          `json:"lat,omitempty"`
	Lon  *float64          `json:"lon,omitempty"`
	// ParentRegion is set for a Kind other than KindRegion -- the region
	// EnableLocalZone must open its AWS client against, since AWS has no
	// single global endpoint for opting a zone group in.
	ParentRegion string `json:"parent_region,omitempty"`
	Enabled      bool   `json:"enabled"`
}

func enrich(provider Provider, code, fallbackName string, kind cloudcatalog.Kind, enabled bool) DiscoveredRegion {
	if entry, ok := cloudcatalog.Lookup(string(provider), code); ok {
		lat, lon := entry.Lat, entry.Lon
		name := entry.Name
		if name == "" {
			name = fallbackName
		}
		return DiscoveredRegion{Code: code, Name: name, Kind: entry.Kind, Lat: &lat, Lon: &lon, ParentRegion: entry.ParentRegion, Enabled: enabled}
	}
	return DiscoveredRegion{Code: code, Name: fallbackName, Kind: kind, Enabled: enabled}
}

// validateSecretShape is dispatched from CreateRequest.validate so a
// malformed credential is rejected before it is ever encrypted and stored.
func validateSecretShape(provider Provider, raw []byte) error {
	switch provider {
	case ProviderAWS:
		return validateAWSSecret(raw)
	case ProviderAzure:
		return validateAzureSecret(raw)
	case ProviderGCP:
		return validateGCPSecret(raw)
	default:
		return fmt.Errorf("unknown provider %q", provider)
	}
}

// Discover calls out to the credential's cloud provider and lists the
// regions (and, for AWS, local zones) enabled on that account, enriched
// with cloudcatalog coordinates where available. Both Mode values may
// discover; only a ModeReadWrite AWS credential also sees a Local Zone
// group that exists but is not yet opted in (Enabled false) -- see
// discoverAWSLocalZones.
func (s *Store) Discover(ctx context.Context, id string) ([]DiscoveredRegion, error) {
	account, err := s.get(ctx, id)
	if err != nil {
		return nil, err
	}
	switch account.Provider {
	case ProviderAWS:
		return discoverAWS(ctx, account.Secret, account.Mode)
	case ProviderAzure:
		return discoverAzure(ctx, account.Secret)
	case ProviderGCP:
		return discoverGCP(ctx, account.Secret)
	default:
		return nil, fmt.Errorf("cloud accounts: unknown provider %q", account.Provider)
	}
}

// EnableLocalZone opts an AWS Local Zone's group into use (ADR-0045 §6's
// second addendum) -- the one real, mutating cloud-provider call this
// package makes, deliberately scoped to exactly this and gated to
// ModeReadWrite. AWS opt-in is a one-way door: there is no API to opt back
// out (AWS's own ModifyAvailabilityZoneGroupInput doc says to contact
// Support), so callers must have already confirmed this with the operator
// before reaching here -- this method does not ask again.
func (s *Store) EnableLocalZone(ctx context.Context, id, groupCode, parentRegion string) (DiscoveredRegion, error) {
	account, err := s.get(ctx, id)
	if err != nil {
		return DiscoveredRegion{}, err
	}
	if account.Mode != ModeReadWrite {
		return DiscoveredRegion{}, fmt.Errorf("cloud accounts: enabling a local zone requires a read-write credential")
	}
	if account.Provider != ProviderAWS {
		return DiscoveredRegion{}, fmt.Errorf("cloud accounts: enabling a local zone is only supported for provider %q", ProviderAWS)
	}
	if err := enableAWSLocalZone(ctx, account.Secret, parentRegion, groupCode); err != nil {
		return DiscoveredRegion{}, err
	}
	return enrich(ProviderAWS, groupCode, groupCode, cloudcatalog.KindLocalZone, true), nil
}
