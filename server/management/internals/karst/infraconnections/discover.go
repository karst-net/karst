// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package infraconnections

import (
	"context"
	"fmt"

	"github.com/netbirdio/netbird/management/internals/karst/cloudcatalog"
)

// DiscoveredRegion is the deprecated, legacy-only shape
// /cloud-accounts/{id}/regions has always returned -- never add a value to
// its Kind that an old typed client wouldn't expect (e.g. "namespace").
// DiscoveredResource below is the generalized, evolving shape; the two are
// kept as distinct Go/OpenAPI types on purpose, not aliases, so adding a
// Kubernetes-only kind to one never constrains the other.
//
// Enabled is true for a standard region and for an already opted-in Local
// Zone -- the only two cases a read_only credential ever reports (ADR-0045
// §6's first addendum). A read_write AWS credential's Discover additionally
// reports a Local Zone group that exists but is not yet opted in, with
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

// DiscoveredResource is the generalized /infrastructure-connections/{id}/
// resources shape -- a region/local zone/zone for a cloud connection, a
// namespace for a Kubernetes one, a datacenter for a Nomad one, or a
// cluster member for a clustered LXD one. Namespace/datacenter/cluster-
// member entries never carry coordinates (no cloudcatalog entry exists for
// them) or a meaningful Enabled/ParentRegion (none of Kubernetes, Nomad, or
// LXD has an opt-in-zone concept); the console falls back to the
// connection's own declared Lat/Lon/LocationLabel instead.
type DiscoveredResource struct {
	Code         string            `json:"code"`
	Name         string            `json:"name,omitempty"`
	Kind         cloudcatalog.Kind `json:"kind"`
	Lat          *float64          `json:"lat,omitempty"`
	Lon          *float64          `json:"lon,omitempty"`
	ParentRegion string            `json:"parent_region,omitempty"`
	Enabled      bool              `json:"enabled,omitempty"`
}

func enrich(typ Type, code, fallbackName string, kind cloudcatalog.Kind, enabled bool) DiscoveredRegion {
	if entry, ok := cloudcatalog.Lookup(string(typ), code); ok {
		lat, lon := entry.Lat, entry.Lon
		name := entry.Name
		if name == "" {
			name = fallbackName
		}
		return DiscoveredRegion{Code: code, Name: name, Kind: entry.Kind, Lat: &lat, Lon: &lon, ParentRegion: entry.ParentRegion, Enabled: enabled}
	}
	return DiscoveredRegion{Code: code, Name: fallbackName, Kind: kind, Enabled: enabled}
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
	case TypeNomad:
		return validateNomadSecret(raw)
	case TypeLXD:
		return validateLXDSecret(raw)
	default:
		return fmt.Errorf("unknown type %q", typ)
	}
}

// discoverCloudRegions dispatches to the three cloud providers' region
// discovery. mode is only consulted by AWS (see discoverAWSLocalZones);
// Azure/GCP's "list regions" APIs have no opt-in-zone concept to gate on.
func discoverCloudRegions(ctx context.Context, typ Type, rawSecret string, mode Mode) ([]DiscoveredRegion, error) {
	switch typ {
	case TypeAWS:
		return discoverAWS(ctx, rawSecret, mode)
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
// to represent a namespace. Both Mode values may discover; only a
// ModeReadWrite AWS credential also sees a Local Zone group that exists but
// is not yet opted in (Enabled false) -- see discoverAWSLocalZones.
func (s *Store) DiscoverLegacy(ctx context.Context, id string) ([]DiscoveredRegion, error) {
	account, err := s.get(ctx, id)
	if err != nil {
		return nil, err
	}
	if !account.Type.IsLegacy() {
		return nil, ErrNotFound
	}
	out, discoverErr := discoverCloudRegions(ctx, account.Type, account.Secret, account.Mode)
	s.recordDiscoveryResult(ctx, id, discoverErr)
	return out, discoverErr
}

// Discover calls out to the connection's own type and lists the resources
// it reports -- regions/local zones/zones for AWS/Azure/GCP, namespaces for
// Kubernetes, datacenters for Nomad, cluster members for a clustered LXD
// server -- enriched with coordinates where a static catalog or the
// provider's own API supplies them. The non-cloud types' entries never
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
		regions, discoverErr = discoverCloudRegions(ctx, account.Type, account.Secret, account.Mode)
		out = toResources(regions)
	case TypeKubernetes:
		out, discoverErr = discoverKubernetes(ctx, account.Secret)
	case TypeNomad:
		out, discoverErr = discoverNomad(ctx, account.Secret)
	case TypeLXD:
		out, discoverErr = discoverLXD(ctx, account.Secret)
	default:
		discoverErr = fmt.Errorf("infra connections: unknown type %q", account.Type)
	}
	s.recordDiscoveryResult(ctx, id, discoverErr)
	return out, discoverErr
}

// EnableLocalZone opts an AWS Local Zone's group into use (ADR-0045 §6's
// second addendum) -- the one real, mutating cloud-provider call this
// package makes, deliberately scoped to exactly this and gated to
// ModeReadWrite. AWS opt-in is a one-way door: there is no API to opt back
// out (AWS's own ModifyAvailabilityZoneGroupInput doc says to contact
// Support), so callers must have already confirmed this with the operator
// before reaching here -- this method does not ask again.
//
// This is wired only to the legacy /cloud-accounts route today (the one
// AWS-specific action in an otherwise type-generic model); a generalized
// /infrastructure-connections equivalent is a reasonable follow-up, not
// built here to keep this rename's scope bounded.
func (s *Store) EnableLocalZone(ctx context.Context, id, groupCode, parentRegion string) (DiscoveredRegion, error) {
	account, err := s.get(ctx, id)
	if err != nil {
		return DiscoveredRegion{}, err
	}
	if account.Mode != ModeReadWrite {
		return DiscoveredRegion{}, fmt.Errorf("cloud accounts: enabling a local zone requires a read-write credential")
	}
	if account.Type != TypeAWS {
		return DiscoveredRegion{}, fmt.Errorf("cloud accounts: enabling a local zone is only supported for provider %q", TypeAWS)
	}
	if err := enableAWSLocalZone(ctx, account.Secret, parentRegion, groupCode); err != nil {
		return DiscoveredRegion{}, err
	}
	return enrich(TypeAWS, groupCode, groupCode, cloudcatalog.KindLocalZone, true), nil
}
