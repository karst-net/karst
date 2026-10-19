// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package cloudaccounts

import (
	"context"
	"fmt"

	"github.com/netbirdio/netbird/management/internals/karst/cloudcatalog"
)

// DiscoveredRegion is one region/zone the provider reports as enabled for
// the credential's account, joined against cloudcatalog where possible.
// Lat/Lon are nil when the catalog has no entry for Code yet -- the console
// still lists it, just without a map pin (see cloudcatalog's own doc
// comment).
type DiscoveredRegion struct {
	Code string          `json:"code"`
	Name string          `json:"name,omitempty"`
	Kind cloudcatalog.Kind `json:"kind"`
	Lat  *float64        `json:"lat,omitempty"`
	Lon  *float64        `json:"lon,omitempty"`
}

func enrich(provider Provider, code, fallbackName string, kind cloudcatalog.Kind) DiscoveredRegion {
	if entry, ok := cloudcatalog.Lookup(string(provider), code); ok {
		lat, lon := entry.Lat, entry.Lon
		name := entry.Name
		if name == "" {
			name = fallbackName
		}
		return DiscoveredRegion{Code: code, Name: name, Kind: entry.Kind, Lat: &lat, Lon: &lon}
	}
	return DiscoveredRegion{Code: code, Name: fallbackName, Kind: kind}
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
// regions (and, for AWS, opted-in local zones) enabled on that account,
// enriched with cloudcatalog coordinates where available. Both Mode values
// may discover -- see the package doc comment on why ModeReadWrite is not
// treated specially here.
func (s *Store) Discover(ctx context.Context, id string) ([]DiscoveredRegion, error) {
	account, err := s.get(ctx, id)
	if err != nil {
		return nil, err
	}
	switch account.Provider {
	case ProviderAWS:
		return discoverAWS(ctx, account.Secret)
	case ProviderAzure:
		return discoverAzure(ctx, account.Secret)
	case ProviderGCP:
		return discoverGCP(ctx, account.Secret)
	default:
		return nil, fmt.Errorf("cloud accounts: unknown provider %q", account.Provider)
	}
}
