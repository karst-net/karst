// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package infraconnections

import (
	"context"
	"fmt"

	"github.com/netbirdio/netbird/management/internals/karst/cloudcatalog"
)

// DiscoveredRegion is the frozen, legacy-only shape /cloud-accounts/{id}/
// regions has always returned -- never add a value to its Kind that an old
// typed client wouldn't expect (e.g. "namespace"). DiscoveredResource below
// is the generalized, evolving shape; the two are kept as distinct Go/
// OpenAPI types on purpose, not aliases, so freezing one never constrains
// the other.
type DiscoveredRegion struct {
	Code string            `json:"code"`
	Name string            `json:"name,omitempty"`
	Kind cloudcatalog.Kind `json:"kind"`
	Lat  *float64          `json:"lat,omitempty"`
	Lon  *float64          `json:"lon,omitempty"`
}

// DiscoveredResource is the generalized /infrastructure-connections/{id}/
// resources shape -- a region/local zone/zone for a cloud connection, or a
// namespace for a Kubernetes one. Namespace entries never carry
// coordinates (no cloudcatalog entry exists for them); the console falls
// back to the connection's own declared Lat/Lon/LocationLabel instead.
type DiscoveredResource struct {
	Code string            `json:"code"`
	Name string            `json:"name,omitempty"`
	Kind cloudcatalog.Kind `json:"kind"`
	Lat  *float64          `json:"lat,omitempty"`
	Lon  *float64          `json:"lon,omitempty"`
}

func enrich(typ Type, code, fallbackName string, kind cloudcatalog.Kind) DiscoveredRegion {
	if entry, ok := cloudcatalog.Lookup(string(typ), code); ok {
		lat, lon := entry.Lat, entry.Lon
		name := entry.Name
		if name == "" {
			name = fallbackName
		}
		return DiscoveredRegion{Code: code, Name: name, Kind: entry.Kind, Lat: &lat, Lon: &lon}
	}
	return DiscoveredRegion{Code: code, Name: fallbackName, Kind: kind}
}

func toResources(regions []DiscoveredRegion) []DiscoveredResource {
	out := make([]DiscoveredResource, len(regions))
	for i, r := range regions {
		out[i] = DiscoveredResource(r)
	}
	return out
}

// validateSecretShape is dispatched from CreateRequest.validate so a
// malformed credential is rejected before it is ever encrypted and stored.
func validateSecretShape(typ Type, raw []byte) error {
	switch typ {
	case TypeAWS:
		return validateAWSSecret(raw)
	case TypeAzure:
		return validateAzureSecret(raw)
	case TypeGCP:
		return validateGCPSecret(raw)
	case TypeKubernetes:
		return validateKubernetesSecret(raw)
	default:
		return fmt.Errorf("unknown type %q", typ)
	}
}

func discoverCloudRegions(ctx context.Context, typ Type, rawSecret string) ([]DiscoveredRegion, error) {
	switch typ {
	case TypeAWS:
		return discoverAWS(ctx, rawSecret)
	case TypeAzure:
		return discoverAzure(ctx, rawSecret)
	case TypeGCP:
		return discoverGCP(ctx, rawSecret)
	default:
		return nil, fmt.Errorf("cloud accounts: unknown provider %q", typ)
	}
}

// DiscoverLegacy only ever reaches aws/azure/gcp -- it returns ErrNotFound
// for a kubernetes-typed row (which can only exist if it was created
// through /infrastructure-connections) so the legacy wire shape never has
// to represent a namespace. Both Mode values may discover -- see the
// package doc comment on why ModeReadWrite is not treated specially here.
func (s *Store) DiscoverLegacy(ctx context.Context, id string) ([]DiscoveredRegion, error) {
	account, err := s.get(ctx, id)
	if err != nil {
		return nil, err
	}
	if !account.Type.isLegacy() {
		return nil, ErrNotFound
	}
	out, discoverErr := discoverCloudRegions(ctx, account.Type, account.Secret)
	s.recordDiscoveryResult(ctx, id, discoverErr)
	return out, discoverErr
}

// Discover calls out to the connection's own type and lists the resources
// it reports -- regions/local zones/zones for AWS/Azure/GCP, namespaces for
// Kubernetes -- enriched with coordinates where a static catalog or the
// provider's own API supplies them. Kubernetes namespace entries never
// carry coordinates; see DiscoveredResource's own doc comment.
func (s *Store) Discover(ctx context.Context, id string) ([]DiscoveredResource, error) {
	account, err := s.get(ctx, id)
	if err != nil {
		return nil, err
	}
	var out []DiscoveredResource
	var discoverErr error
	switch account.Type {
	case TypeAWS, TypeAzure, TypeGCP:
		var regions []DiscoveredRegion
		regions, discoverErr = discoverCloudRegions(ctx, account.Type, account.Secret)
		out = toResources(regions)
	case TypeKubernetes:
		out, discoverErr = discoverKubernetes(ctx, account.Secret)
	default:
		discoverErr = fmt.Errorf("infra connections: unknown type %q", account.Type)
	}
	s.recordDiscoveryResult(ctx, id, discoverErr)
	return out, discoverErr
}
