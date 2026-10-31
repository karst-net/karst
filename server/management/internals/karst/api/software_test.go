// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package api

import (
	"testing"
	"time"

	"github.com/netbirdio/netbird/management/internals/karst/node"
	"github.com/netbirdio/netbird/management/server/peer"
	"github.com/stretchr/testify/require"
)

func TestSoftwareProjectionNeverUsesPeerActivityAsAnObservation(t *testing.T) {
	seen := time.Now().UTC()
	p := &peer.Peer{Status: &peer.PeerStatus{LastSeen: seen}}
	identity := &node.Identity{SoftwareVersion: "unobserved", CreatedAt: seen}
	require.Nil(t, toNodeResponse(p, identity, nodePosture{}).Software)

	observed := seen.Add(-time.Hour)
	identity.SoftwareObservedAt = &observed
	identity.SoftwareVersion = ""
	software := toNodeResponse(p, identity, nodePosture{}).Software
	require.NotNil(t, software)
	require.True(t, software.ObservedAt.Equal(observed))
	require.Nil(t, software.Version)
	require.Nil(t, software.Revision)
	require.Nil(t, software.ArtifactId)
}
