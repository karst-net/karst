// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package types

import (
	"context"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestGroupRevision(t *testing.T) {
	g := &Group{AccountID: "a", ID: "g", Name: "Engineering", Issued: GroupIssuedAPI, Peers: []string{"b", "a"}, Resources: []Resource{{ID: "b", Type: ResourceTypePeer}, {ID: "a", Type: ResourceTypeSubnet}}}
	version := GroupRevision(g)
	require.True(t, ValidGroupRevision(version))
	reordered := g.Copy()
	reordered.Peers = []string{"a", "b", "a"}
	reordered.Resources = []Resource{g.Resources[1], g.Resources[0], g.Resources[0]}
	require.Equal(t, version, GroupRevision(reordered))
	require.Equal(t, []string{"b", "a"}, g.Peers)
	for _, change := range []func(*Group){
		func(g *Group) { g.AccountID = "b" }, func(g *Group) { g.Name = "Renamed" }, func(g *Group) { g.Issued = GroupIssuedJWT }, func(g *Group) { g.Peers = []string{"a"} }, func(g *Group) { g.Resources = nil }, func(g *Group) { g.IntegrationReference.ID = 42 },
	} {
		copy := g.Copy()
		change(copy)
		require.NotEqual(t, version, GroupRevision(copy))
	}
	empty := &Group{}
	same := &Group{Peers: []string{}, Resources: []Resource{}}
	require.Equal(t, GroupRevision(empty), GroupRevision(same))
	require.Equal(t, version, ExpectedGroupRevision(WithGroupRevision(context.Background(), version)))
	for _, invalid := range []string{"", "*", "W/" + version, version + "," + version, "not-a-revision"} {
		require.False(t, ValidGroupRevision(invalid))
	}
}
