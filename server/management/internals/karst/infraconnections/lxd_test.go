// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package infraconnections

import (
	"encoding/json"
	"testing"

	"github.com/netbirdio/netbird/management/internals/karst/cloudcatalog"
)

func TestValidateLXDSecretRejectsEmptyAddress(t *testing.T) {
	secret, _ := json.Marshal(lxdSecret{Address: ""})
	if err := validateLXDSecret(secret); err == nil {
		t.Fatal("want an error for an empty address")
	}
}

func TestValidateLXDSecretRequiresBothHalvesOfClientCert(t *testing.T) {
	secret, _ := json.Marshal(lxdSecret{Address: "https://lxd.internal:8443", ClientCert: "cert-only"})
	if err := validateLXDSecret(secret); err == nil {
		t.Fatal("want an error for client_cert without client_key")
	}
}

func TestValidateLXDSecretAcceptsAddressOnly(t *testing.T) {
	secret, _ := json.Marshal(lxdSecret{Address: "https://lxd.internal:8443"})
	if err := validateLXDSecret(secret); err != nil {
		t.Fatalf("want a bare address to validate, got %v", err)
	}
}

func TestValidateLXDSecretAcceptsFullTLSConfig(t *testing.T) {
	secret, _ := json.Marshal(lxdSecret{
		Address: "https://lxd.internal:8443", Project: "default",
		ServerCert: "server-cert-pem", ClientCert: "cert-pem", ClientKey: "key-pem",
	})
	if err := validateLXDSecret(secret); err != nil {
		t.Fatalf("want a fully-populated secret to validate, got %v", err)
	}
}

// TestClusterMemberResourceNeverGetsCatalogCoordinates mirrors
// TestDatacenterResourceNeverGetsCatalogCoordinates in nomad_test.go:
// documents that discoverLXD builds DiscoveredResource directly, bypassing
// enrich(), so a cluster member never gets a catalog lookup.
func TestClusterMemberResourceNeverGetsCatalogCoordinates(t *testing.T) {
	got := DiscoveredResource{Code: "node1", Kind: cloudcatalog.KindClusterMember}
	if got.Lat != nil || got.Lon != nil {
		t.Fatalf("got %+v, want no coordinates on a cluster member resource", got)
	}
}
