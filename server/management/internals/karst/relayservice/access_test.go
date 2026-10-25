// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package relayservice

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/netbirdio/netbird/management/internals/karst/policy"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/route"
	"github.com/stretchr/testify/require"
)

func accessFixture(t *testing.T) (*Store, Service) {
	s, _, svc := fixture(t)
	require.NoError(t, s.db.AutoMigrate(&types.Group{}, &types.GroupPeer{}, &types.User{}, &nbpeer.Peer{}, &route.Route{}, &policy.Version{}))
	require.NoError(t, s.db.Create(&types.Group{ID: "engineering", AccountID: "a", Name: "Engineering"}).Error)
	require.NoError(t, s.db.Create(&types.User{Id: "owner", AccountID: "a"}).Error)
	require.NoError(t, s.db.Create(&nbpeer.Peer{ID: "laptop", AccountID: "a", Key: "laptop-key", UserID: "owner", Name: "Laptop"}).Error)
	require.NoError(t, s.db.Create(&nbpeer.Peer{ID: "gateway", AccountID: "a", Key: "gateway-key", UserID: "owner", Name: "Gateway", Meta: nbpeer.PeerSystemMeta{GoOS: "linux"}}).Error)
	require.NoError(t, s.db.Create(&types.GroupPeer{AccountID: "a", GroupID: "engineering", PeerID: "laptop"}).Error)
	ctx := WithAccount(context.Background(), "a")
	_, err := s.SetPublication(ctx, "services")
	require.NoError(t, err)
	require.NoError(t, s.RefreshAdmissionLease(svc.PonorID))
	svc.AccessManaged = true
	svc.AllowedGroups = []string{"engineering"}
	return s, svc
}

func TestRelayGroupAdmissionAndRevocation(t *testing.T) {
	s, svc := accessFixture(t)
	ctx := WithAccount(context.Background(), "a")
	_, err := s.Create(ctx, svc)
	require.NoError(t, err)
	allowed, err := s.AllowedOnRelay(ctx, svc.PonorID, "a", "laptop-key")
	require.NoError(t, err)
	require.True(t, allowed)
	allowed, err = s.AllowedOnRelay(ctx, svc.PonorID, "a", "gateway-key")
	require.NoError(t, err)
	require.False(t, allowed)
	allowed, err = s.AllowedOnRelay(ctx, svc.PonorID, "other-account", "laptop-key")
	require.NoError(t, err)
	require.False(t, allowed)
	require.NoError(t, s.db.Model(&types.Group{}).Where("id = ?", "engineering").Update("name", "Renamed").Error)
	allowed, err = s.AllowedOnRelay(ctx, svc.PonorID, "a", "laptop-key")
	require.NoError(t, err)
	require.True(t, allowed)
	require.NoError(t, s.db.Model(&types.User{}).Where("id = ?", "owner").Update("blocked", true).Error)
	allowed, err = s.AllowedOnRelay(ctx, svc.PonorID, "a", "laptop-key")
	require.NoError(t, err)
	require.False(t, allowed)
	require.NoError(t, s.db.Model(&types.User{}).Where("id = ?", "owner").Update("blocked", false).Error)
	require.NoError(t, s.db.Where("group_id = ?", "engineering").Delete(&types.GroupPeer{}).Error)
	allowed, err = s.AllowedOnRelay(ctx, svc.PonorID, "a", "laptop-key")
	require.NoError(t, err)
	require.False(t, allowed)
	require.NoError(t, s.Delete(ctx, svc.ID))
	allowed, err = s.AllowedOnRelay(ctx, svc.PonorID, "a", "laptop-key")
	require.NoError(t, err)
	require.False(t, allowed)
	_, err = s.Create(ctx, Service{ID: "bypass", PonorID: svc.PonorID})
	require.ErrorIs(t, err, ErrInvalid)
}

func TestRelayExitConfigurationAtomicAndVersioned(t *testing.T) {
	s, svc := accessFixture(t)
	ctx := WithAccount(context.Background(), "a")
	svc.ExitIPv4 = true
	svc.ExitIPv6 = true
	svc.GatewayHandle = "gateway-key"
	created, err := s.Create(ctx, svc)
	require.NoError(t, err)
	var routes []route.Route
	require.NoError(t, s.db.Find(&routes).Error)
	require.Len(t, routes, 2)
	for _, r := range routes {
		require.True(t, r.SkipAutoApply)
		require.Equal(t, []string{"engineering"}, r.Groups)
		require.Equal(t, "gateway", r.Peer)
	}
	v, err := policy.TransactionStore(s.db).Current(policy.WithAccount(ctx, "a"))
	require.NoError(t, err)
	doc, err := policy.Parse([]byte(v.Document))
	require.NoError(t, err)
	require.Len(t, doc.Grants, 1)
	changed := *created
	changed.ExitIPv6 = false
	updated, err := s.UpdateAccess(ctx, created.ID, changed)
	require.NoError(t, err)
	require.Greater(t, updated.Revision, created.Revision)
	_, err = s.UpdateAccess(ctx, created.ID, changed)
	require.ErrorIs(t, err, ErrExists)
	require.NoError(t, s.Delete(ctx, svc.ID))
	routes = nil
	require.NoError(t, s.db.Find(&routes).Error)
	require.Empty(t, routes)
	v, err = policy.TransactionStore(s.db).Current(policy.WithAccount(ctx, "a"))
	require.NoError(t, err)
	doc, err = policy.Parse([]byte(v.Document))
	require.NoError(t, err)
	require.Empty(t, doc.Grants)
}

func TestFailedAllocationLeavesNoAccessOrRoutes(t *testing.T) {
	s, svc := accessFixture(t)
	ctx := WithAccount(context.Background(), "a")
	svc.ExitIPv4 = true
	svc.GatewayHandle = "foreign-key"
	_, err := s.Create(ctx, svc)
	require.Error(t, err)
	var count int64
	require.NoError(t, s.db.Model(&BackendAccess{}).Count(&count).Error)
	require.Zero(t, count)
	require.NoError(t, s.db.Model(&Service{}).Count(&count).Error)
	require.Zero(t, count)
	require.NoError(t, s.db.Model(&route.Route{}).Count(&count).Error)
	require.Zero(t, count)
}

func TestAutomaticWritePreservesEmptySSHGate(t *testing.T) {
	doc := policy.Document{Ssh: []policy.SshRule{}}
	data, err := json.Marshal(doc)
	require.NoError(t, err)
	restored, err := policy.Parse(data)
	require.NoError(t, err)
	require.NotNil(t, restored.Ssh)
	require.Empty(t, restored.Ssh)
}
