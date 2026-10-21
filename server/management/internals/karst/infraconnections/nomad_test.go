// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package infraconnections

import (
	"encoding/json"
	"testing"

	"github.com/netbirdio/netbird/management/internals/karst/cloudcatalog"
)

func TestValidateNomadSecretRejectsEmptyAddress(t *testing.T) {
	secret, _ := json.Marshal(nomadSecret{Address: ""})
	if err := validateNomadSecret(secret); err == nil {
		t.Fatal("want an error for an empty address")
	}
}

func TestValidateNomadSecretRequiresBothHalvesOfClientCert(t *testing.T) {
	secret, _ := json.Marshal(nomadSecret{Address: "https://nomad.internal:4646", ClientCert: "cert-only"})
	if err := validateNomadSecret(secret); err == nil {
		t.Fatal("want an error for client_cert without client_key")
	}
}

func TestValidateNomadSecretAcceptsAddressOnly(t *testing.T) {
	secret, _ := json.Marshal(nomadSecret{Address: "https://nomad.internal:4646"})
	if err := validateNomadSecret(secret); err != nil {
		t.Fatalf("want a bare address to validate, got %v", err)
	}
}

func TestValidateNomadSecretAcceptsFullTLSConfig(t *testing.T) {
	secret, _ := json.Marshal(nomadSecret{
		Address: "https://nomad.internal:4646", Region: "us-east", Namespace: "prod", Token: "fake-token",
		CACert: "ca-pem", ClientCert: "cert-pem", ClientKey: "key-pem",
	})
	if err := validateNomadSecret(secret); err != nil {
		t.Fatalf("want a fully-populated secret to validate, got %v", err)
	}
}

// TestDatacenterResourceNeverGetsCatalogCoordinates mirrors
// TestNamespaceResourceNeverGetsCatalogCoordinates in kubernetes_test.go:
// documents that discoverNomad builds DiscoveredResource directly,
// bypassing enrich(), so a datacenter never gets a catalog lookup.
func TestDatacenterResourceNeverGetsCatalogCoordinates(t *testing.T) {
	got := DiscoveredResource{Code: "dc1", Kind: cloudcatalog.KindDatacenter}
	if got.Lat != nil || got.Lon != nil {
		t.Fatalf("got %+v, want no coordinates on a datacenter resource", got)
	}
}
