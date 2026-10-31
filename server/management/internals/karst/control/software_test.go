// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package control_test

import (
	"context"
	"strings"
	"testing"

	"github.com/netbirdio/netbird/shared/management/proto"
	"github.com/stretchr/testify/require"
	pb "google.golang.org/protobuf/proto"
)

func TestSoftwareReportsAreBoundToAuthenticatedNodeAndDoNotChangeNetmaps(t *testing.T) {
	f := newNetmapFixture(t, 1)
	initial := requestNetmap(t, f, 0)
	call := func(software *proto.KarstSoftwareIdentity) *proto.KarstNetmapResponse {
		req, err := pb.Marshal(&proto.KarstNetmapRequest{KnownVersion: initial.Version, Software: software})
		require.NoError(t, err)
		// The supplied node-id argument cannot redirect the observation: the
		// authenticated identity is the only source of its owner.
		raw, err := f.handler.Handle(context.Background(), []byte(f.peerH[0]), f.self.Public(), req)
		require.NoError(t, err)
		resp := &proto.KarstNetmapResponse{}
		require.NoError(t, pb.Unmarshal(raw, resp))
		require.True(t, resp.Unchanged)
		require.Equal(t, initial.Version, resp.Version)
		return resp
	}
	call(&proto.KarstSoftwareIdentity{Version: "v1", Revision: "commit", ArtifactId: "sha256:artifact"})
	self, err := f.handler.Nodes.Get(f.selfH)
	require.NoError(t, err)
	require.Equal(t, "v1", self.SoftwareVersion)
	require.Equal(t, "commit", self.SoftwareRevision)
	require.Equal(t, "sha256:artifact", self.SoftwareArtifactID)
	require.NotNil(t, self.SoftwareObservedAt)
	other, err := f.handler.Nodes.Get(f.peerH[0])
	require.NoError(t, err)
	require.Nil(t, other.SoftwareObservedAt)

	// Legacy and malformed reports cannot make an old observation look fresh,
	// and malformed advisory software metadata cannot deny network access.
	call(nil)
	call(&proto.KarstSoftwareIdentity{Version: strings.Repeat("x", 129)})
	after, err := f.handler.Nodes.Get(f.selfH)
	require.NoError(t, err)
	require.Equal(t, self.SoftwareVersion, after.SoftwareVersion)
	require.True(t, self.SoftwareObservedAt.Equal(*after.SoftwareObservedAt))
}
