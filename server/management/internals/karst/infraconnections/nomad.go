// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package infraconnections

import (
	"context"
	"encoding/json"
	"fmt"

	nomadapi "github.com/hashicorp/nomad/api"

	"github.com/netbirdio/netbird/management/internals/karst/cloudcatalog"
)

// nomadSecret is the admin-entered credential shape for Type "nomad" -- a
// Nomad API environment's address plus optional scope/auth, matching the
// fields Nomad's own client Config/TLSConfig already model rather than a
// pasted blob (Nomad has no single "config file" the way a kubeconfig is).
// Region scopes which Nomad region this connection talks to -- a scheduler/
// control concept, not a geographic one (see cloudcatalog's doc comment);
// Namespace scopes queries to one Nomad namespace, if the token is scoped
// to one. CACert/ClientCert/ClientKey are PEM contents, pasted the same way
// Kubernetes's kubeconfig is, not file paths.
type nomadSecret struct {
	Address    string `json:"address"`
	Region     string `json:"region,omitempty"`
	Namespace  string `json:"namespace,omitempty"`
	Token      string `json:"token,omitempty"`
	CACert     string `json:"ca_cert,omitempty"`
	ClientCert string `json:"client_cert,omitempty"`
	ClientKey  string `json:"client_key,omitempty"`
}

func validateNomadSecret(raw []byte) error {
	var s nomadSecret
	if err := json.Unmarshal(raw, &s); err != nil {
		return fmt.Errorf("nomad secret: %w", err)
	}
	if s.Address == "" {
		return fmt.Errorf("nomad secret: address is required")
	}
	if (s.ClientCert == "") != (s.ClientKey == "") {
		return fmt.Errorf("nomad secret: client_cert and client_key must both be set or both omitted")
	}
	return nil
}

func nomadClient(rawSecret string) (*nomadapi.Client, nomadSecret, error) {
	var s nomadSecret
	if err := json.Unmarshal([]byte(rawSecret), &s); err != nil {
		return nil, s, fmt.Errorf("nomad secret: %w", err)
	}
	cfg := &nomadapi.Config{
		Address:   s.Address,
		Region:    s.Region,
		Namespace: s.Namespace,
		SecretID:  s.Token,
	}
	if s.CACert != "" || s.ClientCert != "" {
		cfg.TLSConfig = &nomadapi.TLSConfig{
			CACertPEM:     []byte(s.CACert),
			ClientCertPEM: []byte(s.ClientCert),
			ClientKeyPEM:  []byte(s.ClientKey),
		}
	}
	client, err := nomadapi.NewClient(cfg)
	if err != nil {
		return nil, s, fmt.Errorf("nomad: build client: %w", err)
	}
	return client, s, nil
}

// discoverNomad proves the connection is reachable (Status().Leader()) and
// lists the datacenters its nodes report -- the "permissions" surfaced to
// the operator as discovered resources, and the closest Nomad analog to a
// Kubernetes namespace or cloud region for Authorized Locations purposes.
// This is discovery-only: no job, allocation, or variable access, and no
// watch/blocking-query loop. Nomad has no "list datacenters" endpoint, so
// this is derived by deduping Nodes().List()'s own Datacenter field --
// Nomad regions (see nomadSecret.Region) are a separate, operator-
// configured scope, not something this call enumerates.
func discoverNomad(ctx context.Context, rawSecret string) ([]DiscoveredResource, error) {
	client, _, err := nomadClient(rawSecret)
	if err != nil {
		return nil, err
	}
	if _, err := client.Status().Leader(); err != nil {
		return nil, fmt.Errorf("nomad: leader (reachability check): %w", err)
	}
	nodes, _, err := client.Nodes().List((&nomadapi.QueryOptions{}).WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("nomad: list nodes: %w", err)
	}
	seen := map[string]bool{}
	out := make([]DiscoveredResource, 0, len(nodes))
	for _, node := range nodes {
		if node.Datacenter == "" || seen[node.Datacenter] {
			continue
		}
		seen[node.Datacenter] = true
		out = append(out, DiscoveredResource{Code: node.Datacenter, Kind: cloudcatalog.KindDatacenter})
	}
	return out, nil
}
