// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package cloudaccounts

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	compute "cloud.google.com/go/compute/apiv1"
	"cloud.google.com/go/compute/apiv1/computepb"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"

	"github.com/netbirdio/netbird/management/internals/karst/cloudcatalog"
)

// gcpSecret is the admin-entered credential shape for Provider "gcp" -- a
// service account key, in the exact JSON form the GCP console issues it in
// (so the admin can paste the downloaded key file's contents verbatim).
type gcpSecret struct {
	ProjectID         string          `json:"project_id"`
	ServiceAccountKey json.RawMessage `json:"service_account_key"`
}

func validateGCPSecret(raw []byte) error {
	var s gcpSecret
	if err := json.Unmarshal(raw, &s); err != nil {
		return fmt.Errorf("gcp secret: %w", err)
	}
	if s.ProjectID == "" || len(s.ServiceAccountKey) == 0 {
		return fmt.Errorf("gcp secret: project_id and service_account_key are both required")
	}
	return nil
}

func discoverGCP(ctx context.Context, rawSecret string) ([]DiscoveredRegion, error) {
	var s gcpSecret
	if err := json.Unmarshal([]byte(rawSecret), &s); err != nil {
		return nil, fmt.Errorf("gcp secret: %w", err)
	}
	client, err := compute.NewRegionsRESTClient(ctx, option.WithAuthCredentialsJSON(option.ServiceAccount, s.ServiceAccountKey))
	if err != nil {
		return nil, fmt.Errorf("gcp: build client: %w", err)
	}
	defer client.Close()

	var out []DiscoveredRegion
	it := client.List(ctx, &computepb.ListRegionsRequest{Project: s.ProjectID})
	for {
		region, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("gcp: list regions: %w", err)
		}
		if region.GetName() == "" {
			continue
		}
		out = append(out, enrich(ProviderGCP, region.GetName(), region.GetName(), cloudcatalog.KindRegion, true))
	}
	return out, nil
}
