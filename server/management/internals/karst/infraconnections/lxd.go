// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package infraconnections

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/netbirdio/netbird/management/internals/karst/cloudcatalog"
)

// lxdSecret is the admin-entered credential shape for Type "lxd" -- an LXD
// server's API address plus its TLS client certificate, matching LXD's own
// trust model rather than a pasted blob (LXD has no single "config file"
// the way a kubeconfig is; its CLI's own per-remote config lives as several
// files on disk, not one portable document).
//
// ClientCert/ClientKey are PEM contents, pasted the same way Kubernetes's
// kubeconfig and Nomad's TLS fields are, not file paths -- LXD's HTTPS API
// authenticates the *client* by certificate (`lxc config trust add`),
// unlike Nomad's optional bearer token. ServerCert is deliberately not
// named CACert, unlike Nomad: an LXD server's default certificate is
// self-signed, with no real CA behind it, so what this field actually
// pins is the server's own certificate (accepted as its own trust root via
// Go's normal certificate-verification path), the same property LXD's own
// CLI gets from fingerprint-pinning on first connect. Project scopes
// queries to one LXD project, if the credential is not restricted to a
// single project already -- LXD's closest analog to a Kubernetes namespace
// or a Nomad namespace, though discoverLXD does not enumerate it (see that
// function's own doc comment for why cluster members, not projects, are
// this backend's discoverable resource).
type lxdSecret struct {
	Address    string `json:"address"`
	Project    string `json:"project,omitempty"`
	ServerCert string `json:"server_cert,omitempty"`
	ClientCert string `json:"client_cert,omitempty"`
	ClientKey  string `json:"client_key,omitempty"`
}

func validateLXDSecret(raw []byte) error {
	var s lxdSecret
	if err := json.Unmarshal(raw, &s); err != nil {
		return fmt.Errorf("lxd secret: %w", err)
	}
	if s.Address == "" {
		return fmt.Errorf("lxd secret: address is required")
	}
	if (s.ClientCert == "") != (s.ClientKey == "") {
		return fmt.Errorf("lxd secret: client_cert and client_key must both be set or both omitted")
	}
	return nil
}

// lxdHTTPClient builds an *http.Client trusting ServerCert (if set, in
// place of the system trust store -- see lxdSecret's own doc comment on why
// that is the right trust anchor for a self-signed LXD server) and
// presenting ClientCert/ClientKey for mutual TLS (if set -- most LXD
// servers require this for anything beyond the unauthenticated subset of
// GET /1.0).
func lxdHTTPClient(s lxdSecret) (*http.Client, error) {
	tlsCfg := &tls.Config{}
	if s.ServerCert != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(s.ServerCert)) {
			return nil, fmt.Errorf("lxd: server_cert is not a valid PEM certificate")
		}
		tlsCfg.RootCAs = pool
	}
	if s.ClientCert != "" {
		cert, err := tls.X509KeyPair([]byte(s.ClientCert), []byte(s.ClientKey))
		if err != nil {
			return nil, fmt.Errorf("lxd: client_cert/client_key: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: tlsCfg}}, nil
}

// lxdGet issues an authenticated GET against the LXD server and decodes its
// standard synchronous-response envelope's metadata field into out -- every
// LXD REST call below is a plain `{"type":"sync","metadata":...}` response,
// so this is the one request/decode path both callers in this file share.
func lxdGet(ctx context.Context, client *http.Client, url string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("lxd: build request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("lxd: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("lxd: read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("lxd: %s: unexpected status %d: %s", url, resp.StatusCode, string(body))
	}
	var envelope struct {
		Metadata json.RawMessage `json:"metadata"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return fmt.Errorf("lxd: %s: decode envelope: %w", url, err)
	}
	if err := json.Unmarshal(envelope.Metadata, out); err != nil {
		return fmt.Errorf("lxd: %s: decode metadata: %w", url, err)
	}
	return nil
}

// discoverLXD proves the connection is reachable (GET /1.0) and, only for a
// clustered server, lists its cluster members -- the closest LXD analog to
// a Nomad datacenter or Kubernetes namespace for Authorized Locations
// purposes: each member is a separate physical or virtual host, which a
// single standalone LXD server has none of to enumerate. A standalone
// server (the common case for a self-hoster) therefore returns an empty
// list rather than an error; the console falls back to the connection's own
// declared Lat/Lon/LocationLabel exactly as it already does for a
// Kubernetes/Nomad connection whose discovered resources carry no
// coordinates. This is discovery-only: no instance, volume, network, or
// image access, and no event/websocket stream.
func discoverLXD(ctx context.Context, rawSecret string) ([]DiscoveredResource, error) {
	var s lxdSecret
	if err := json.Unmarshal([]byte(rawSecret), &s); err != nil {
		return nil, fmt.Errorf("lxd secret: %w", err)
	}
	client, err := lxdHTTPClient(s)
	if err != nil {
		return nil, err
	}
	var server struct {
		Environment struct {
			ServerClustered bool `json:"server_clustered"`
		} `json:"environment"`
	}
	if err := lxdGet(ctx, client, s.Address+"/1.0", &server); err != nil {
		return nil, fmt.Errorf("lxd: server info (reachability check): %w", err)
	}
	if !server.Environment.ServerClustered {
		return []DiscoveredResource{}, nil
	}
	var members []struct {
		ServerName string `json:"server_name"`
	}
	if err := lxdGet(ctx, client, s.Address+"/1.0/cluster/members?recursion=1", &members); err != nil {
		return nil, fmt.Errorf("lxd: list cluster members: %w", err)
	}
	out := make([]DiscoveredResource, 0, len(members))
	for _, member := range members {
		if member.ServerName == "" {
			continue
		}
		out = append(out, DiscoveredResource{Code: member.ServerName, Kind: cloudcatalog.KindClusterMember})
	}
	return out, nil
}
