// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package api

import (
	"context"
	"testing"

	"github.com/netbirdio/netbird/management/internals/modules/meshdomain"
	"github.com/stretchr/testify/require"
)

type domainNamingSource struct {
	peerReader
	root *meshdomain.Domain
}

func (s domainNamingSource) GetAccountRootDomain(context.Context, string) (*meshdomain.Domain, error) {
	return s.root, nil
}

func TestDomainNamesUseOneRootRevisionDuringRename(t *testing.T) {
	oldRoot, err := meshdomain.NewRoot("account", "karst")
	require.NoError(t, err)
	current := *oldRoot
	current.DNSSuffix, current.NamingRevision = "corp.example", 9
	child := meshdomain.NewDomain("account", oldRoot.ID, "engineering", "")
	h := handler{peers: domainNamingSource{root: &current}}
	// Rename commits after the tree was listed but before names are projected.
	views, err := h.domainViews(context.Background(), "account", []*meshdomain.Domain{oldRoot, child})
	require.NoError(t, err)
	require.Equal(t, "corp.example", views[0].DNSSuffix)
	require.Equal(t, "corp.example", views[0].DNSName)
	require.Equal(t, uint64(9), views[0].NamingRevision)
	require.Equal(t, "engineering.corp.example", views[1].DNSName)
}
