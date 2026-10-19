// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package cloudaccounts

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions"

	"github.com/netbirdio/netbird/management/internals/karst/cloudcatalog"
)

// azureSecret is the admin-entered credential shape for Provider "azure" --
// an app registration (service principal) scoped to one subscription.
type azureSecret struct {
	TenantID       string `json:"tenant_id"`
	ClientID       string `json:"client_id"`
	ClientSecret   string `json:"client_secret"`
	SubscriptionID string `json:"subscription_id"`
}

func validateAzureSecret(raw []byte) error {
	var s azureSecret
	if err := json.Unmarshal(raw, &s); err != nil {
		return fmt.Errorf("azure secret: %w", err)
	}
	if s.TenantID == "" || s.ClientID == "" || s.ClientSecret == "" || s.SubscriptionID == "" {
		return fmt.Errorf("azure secret: tenant_id, client_id, client_secret, and subscription_id are all required")
	}
	return nil
}

func discoverAzure(ctx context.Context, rawSecret string) ([]DiscoveredRegion, error) {
	var s azureSecret
	if err := json.Unmarshal([]byte(rawSecret), &s); err != nil {
		return nil, fmt.Errorf("azure secret: %w", err)
	}
	cred, err := azidentity.NewClientSecretCredential(s.TenantID, s.ClientID, s.ClientSecret, nil)
	if err != nil {
		return nil, fmt.Errorf("azure: build credential: %w", err)
	}
	client, err := armsubscriptions.NewClient(cred, nil)
	if err != nil {
		return nil, fmt.Errorf("azure: build client: %w", err)
	}

	var out []DiscoveredRegion
	pager := client.NewListLocationsPager(s.SubscriptionID, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("azure: list locations: %w", err)
		}
		for _, loc := range page.Value {
			if loc == nil || loc.Name == nil {
				continue
			}
			out = append(out, azureRegion(*loc))
		}
	}
	return out, nil
}

// azureRegion prefers Azure's own reported lat/long (LocationMetadata) over
// the static catalog -- Azure's API actually returns coordinates, unlike
// AWS/GCP's "list regions" calls, so it is the more current source here.
func azureRegion(loc armsubscriptions.Location) DiscoveredRegion {
	code := *loc.Name
	name := code
	if loc.DisplayName != nil {
		name = *loc.DisplayName
	}
	if loc.Metadata != nil && loc.Metadata.Latitude != nil && loc.Metadata.Longitude != nil {
		if lat, err := strconv.ParseFloat(*loc.Metadata.Latitude, 64); err == nil {
			if lon, err := strconv.ParseFloat(*loc.Metadata.Longitude, 64); err == nil {
				return DiscoveredRegion{Code: code, Name: name, Kind: cloudcatalog.KindRegion, Lat: &lat, Lon: &lon}
			}
		}
	}
	return enrich(ProviderAzure, code, name, cloudcatalog.KindRegion)
}
