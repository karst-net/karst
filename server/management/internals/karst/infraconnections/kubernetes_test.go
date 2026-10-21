// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package infraconnections

import (
	"encoding/json"
	"testing"

	"github.com/netbirdio/netbird/management/internals/karst/cloudcatalog"
)

func TestValidateKubernetesSecretRejectsEmptyKubeconfig(t *testing.T) {
	secret, _ := json.Marshal(kubernetesSecret{Kubeconfig: ""})
	if err := validateKubernetesSecret(secret); err == nil {
		t.Fatal("want an error for an empty kubeconfig")
	}
}

func TestValidateKubernetesSecretRejectsMalformedYAML(t *testing.T) {
	secret, _ := json.Marshal(kubernetesSecret{Kubeconfig: "not: [valid: yaml"})
	if err := validateKubernetesSecret(secret); err == nil {
		t.Fatal("want an error for malformed kubeconfig YAML")
	}
}

func TestValidateKubernetesSecretRejectsNoCurrentContext(t *testing.T) {
	secret, _ := json.Marshal(kubernetesSecret{Kubeconfig: `
apiVersion: v1
kind: Config
clusters: []
users: []
contexts: []
`})
	if err := validateKubernetesSecret(secret); err == nil {
		t.Fatal("want an error for a kubeconfig with no current-context")
	}
}

func TestValidateKubernetesSecretAcceptsWellFormedKubeconfig(t *testing.T) {
	secret, _ := json.Marshal(kubernetesSecret{Kubeconfig: validTestKubeconfig})
	if err := validateKubernetesSecret(secret); err != nil {
		t.Fatalf("want a well-formed kubeconfig to validate, got %v", err)
	}
}

// TestNamespaceResourceNeverGetsCatalogCoordinates documents the rule a
// reviewer could otherwise assume enrich() should be extended to cover:
// namespaces are not geographic and are never looked up in cloudcatalog.
// discoverKubernetes builds DiscoveredResource directly, bypassing enrich().
func TestNamespaceResourceNeverGetsCatalogCoordinates(t *testing.T) {
	got := DiscoveredResource{Code: "default", Kind: cloudcatalog.KindNamespace}
	if got.Lat != nil || got.Lon != nil {
		t.Fatalf("got %+v, want no coordinates on a namespace resource", got)
	}
}
