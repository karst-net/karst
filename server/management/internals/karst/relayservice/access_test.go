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
	require.Equal(t, "gateway-key", doc.Grants[0].Gateway)
	require.Empty(t, doc.Grants[0].TargetNodes)
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

func TestInstallationWriterRequiresManagedAccessForEveryTenant(t *testing.T) {
	s, svc := accessFixture(t)
	ctx := WithAccount(context.Background(), "a")
	// Legacy behavior is retained only for writers not using managed-only mode.
	legacy, err := s.AllowedOnRelay(ctx, svc.PonorID, "a", "laptop-key")
	require.NoError(t, err)
	require.True(t, legacy)
	allowed, err := s.AllowedOnManagedRelay(ctx, svc.PonorID, "a", "laptop-key")
	require.NoError(t, err)
	require.False(t, allowed)
	_, err = s.Create(ctx, svc)
	require.NoError(t, err)
	allowed, err = s.AllowedOnManagedRelay(ctx, svc.PonorID, "a", "laptop-key")
	require.NoError(t, err)
	require.True(t, allowed)
	allowed, err = s.AllowedOnManagedRelay(ctx, svc.PonorID, "other-account", "laptop-key")
	require.NoError(t, err)
	require.False(t, allowed)
	allowed, err = s.AllowedOnManagedRelay(ctx, svc.PonorID, "a", "gateway-key")
	require.NoError(t, err)
	require.False(t, allowed)
	require.NoError(t, s.Delete(ctx, svc.ID))
	allowed, err = s.AllowedOnManagedRelay(ctx, svc.PonorID, "a", "laptop-key")
	require.NoError(t, err)
	require.False(t, allowed)
}

func TestReapplyingLegacyExitAccessScopesOnlyItsGeneratedGrant(t *testing.T) {
	s, svc := accessFixture(t)
	ctx := WithAccount(context.Background(), "a")
	svc.ExitIPv4 = true
	svc.GatewayHandle = "gateway-key"
	created, err := s.Create(ctx, svc)
	require.NoError(t, err)
	doc, version, err := currentDocument(s.db, "a")
	require.NoError(t, err)
	// A pre-upgrade service has a broad machine target plus its network grant.
	doc.Grants[0].Gateway = ""
	doc.Grants[0].TargetNodes = []string{"gateway-key"}
	doc.Grants = append(doc.Grants, policy.Grant{ID: "independent", Name: "Machine web", SourceGroups: []string{"engineering"}, TargetNodes: []string{"gateway-key"}, Ports: "443"})
	doc.Ssh = []policy.SshRule{}
	require.NoError(t, writeDocument(s.db, "a", doc, version))
	legacy, err := policy.TransactionStore(s.db).Current(policy.WithAccount(ctx, "a"))
	require.NoError(t, err)
	_, err = s.UpdateAccess(ctx, svc.ID, *created)
	require.NoError(t, err)
	updated, _, err := currentDocument(s.db, "a")
	require.NoError(t, err)
	require.Len(t, updated.Grants, 2)
	require.NotNil(t, updated.Ssh)
	nodes := []policy.Node{{Handle: "laptop-key", GroupIDs: []string{"engineering"}}, {Handle: "gateway-key"}}
	filter, err := updated.Compile(nodes[1], nodes)
	require.NoError(t, err)
	require.True(t, filter.Permits("laptop-key", 443), "independent machine grant survives")
	require.False(t, filter.Permits("laptop-key", 22), "generated broad machine access was removed")
	gate, err := updated.CompileSSH(nodes[1], nodes)
	require.NoError(t, err)
	require.NotNil(t, gate)
	require.Empty(t, gate.Rules, "explicit empty SSH gate survives")
	var retained policy.Version
	require.NoError(t, s.db.Where("account_id = ? AND version = ?", "a", legacy.Version).First(&retained).Error)
	require.Equal(t, legacy.Document, retained.Document, "migration must preserve immutable policy history")
}
