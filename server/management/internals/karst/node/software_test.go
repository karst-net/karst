// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package node_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/netbirdio/netbird/management/internals/karst/node"
	"github.com/stretchr/testify/require"
)

func TestSoftwareObservationReplacesBuildAndSurvivesRegistration(t *testing.T) {
	s := newStore(t)
	key := newIdentity(t)
	handle, err := s.Register(key.Public(), testKeys())
	require.NoError(t, err)
	ctx := context.Background()
	first := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	require.NoError(t, s.RecordSoftware(ctx, handle, node.SoftwareIdentity{Version: "v1", Revision: "commit-1", ArtifactID: "sha256:artifact-1"}, first))
	_, err = s.Register(key.Public(), testKeys())
	require.NoError(t, err)
	identity, err := s.Get(handle)
	require.NoError(t, err)
	require.Equal(t, "sha256:artifact-1", identity.SoftwareArtifactID)
	require.True(t, identity.SoftwareObservedAt.Equal(first))

	second := first.Add(time.Minute)
	require.NoError(t, s.RecordSoftware(ctx, handle, node.SoftwareIdentity{Version: "v2"}, second))
	identity, err = s.Get(handle)
	require.NoError(t, err)
	require.Equal(t, "v2", identity.SoftwareVersion)
	require.Empty(t, identity.SoftwareRevision)
	require.Empty(t, identity.SoftwareArtifactID)
	require.True(t, identity.SoftwareObservedAt.Equal(second))
	require.ErrorIs(t, s.RecordSoftware(ctx, "missing", node.SoftwareIdentity{Version: "v1"}, second), node.ErrUnknownNode)
}

func TestInvalidSoftwareDoesNotRefreshObservation(t *testing.T) {
	s := newStore(t)
	handle, err := s.Register(newIdentity(t).Public(), testKeys())
	require.NoError(t, err)
	now := time.Now().UTC()
	require.NoError(t, s.RecordSoftware(context.Background(), handle, node.SoftwareIdentity{Version: "v1"}, now))
	for _, report := range []node.SoftwareIdentity{
		{Version: strings.Repeat("a", 129)}, {Revision: strings.Repeat("b", 129)},
		{ArtifactID: strings.Repeat("c", 257)}, {Version: "line\nbreak"},
		{Revision: "\x00"}, {ArtifactID: string([]byte{0xff})},
	} {
		require.Error(t, s.RecordSoftware(context.Background(), handle, report, now.Add(time.Minute)))
	}
	require.Error(t, s.RecordSoftware(context.Background(), handle, node.SoftwareIdentity{}, time.Time{}))
	identity, err := s.Get(handle)
	require.NoError(t, err)
	require.Equal(t, "v1", identity.SoftwareVersion)
	require.True(t, identity.SoftwareObservedAt.Equal(now))
}
