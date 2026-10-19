// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package store

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/netbirdio/netbird/management/internals/modules/meshdomain"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/types"
)

func rootMigrationStore(t *testing.T, suffix string) *SqlStore {
	t.Helper()
	s, cleanup, err := NewTestStoreFromSQL(context.Background(), "", t.TempDir())
	require.NoError(t, err)
	t.Cleanup(cleanup)
	sqlStore := s.(*SqlStore)
	require.NoError(t, s.SaveAccount(context.Background(), &types.Account{Id: "legacy", Settings: &types.Settings{DNSDomain: suffix}, Network: &types.Network{Dns: suffix, Serial: 42}}))
	return sqlStore
}

func TestMeshRootMigrationPreservesNamesAndAuthority(t *testing.T) {
	ctx := context.Background()
	s := rootMigrationStore(t, "mesh.example")
	engineering := meshdomain.NewDomain("legacy", "", "engineering", "")
	child := meshdomain.NewDomain("legacy", engineering.ID, "build", engineering.Path)
	require.NoError(t, s.CreateDomain(ctx, engineering))
	require.NoError(t, s.CreateDomain(ctx, child))
	for _, peer := range []*nbpeer.Peer{
		{ID: "laptop", AccountID: "legacy", Key: "laptop-key", IP: netip.MustParseAddr("100.64.0.1"), DNSLabel: "laptop"},
		{ID: "builder", AccountID: "legacy", Key: "builder-key", IP: netip.MustParseAddr("100.64.0.2"), DomainID: child.ID, DNSLabel: "box.build.engineering"},
	} {
		require.NoError(t, s.AddPeerToAccount(ctx, peer))
	}
	rootKey, _ := types.GenerateSetupKey("root-key", types.SetupKeyReusable, time.Hour, nil, 0, false, false)
	rootKey.AccountID = "legacy"
	require.NoError(t, s.SaveSetupKey(ctx, rootKey))
	childKey, _ := types.GenerateSetupKey("child-key", types.SetupKeyOneOff, time.Hour, nil, 1, false, false)
	childKey.AccountID, childKey.DomainID, childKey.DomainPath = "legacy", child.ID, child.Path
	require.NoError(t, s.SaveSetupKey(ctx, childKey))
	binding := meshdomain.NewDomainRoleBinding("legacy", engineering.ID, engineering.Path, "admin")
	require.NoError(t, s.CreateDomainRoleBinding(ctx, binding))

	require.NoError(t, s.InitializeMeshDomains(ctx, "unused-default.example"))
	account, err := s.GetAccount(ctx, "legacy")
	require.NoError(t, err)
	rootID := account.RootDomainID
	require.NotEmpty(t, rootID)
	require.True(t, account.RootDomain.IsRoot())
	require.Empty(t, account.RootDomain.Path)
	require.Equal(t, "mesh.example", account.RootDomain.DNSSuffix)
	require.Equal(t, rootID, account.Peers["laptop"].DomainID)
	require.Equal(t, child.ID, account.Peers["builder"].DomainID)
	require.Equal(t, "laptop.mesh.example", account.Peers["laptop"].FQDN(account.RootDomain.DNSSuffix))
	require.Equal(t, "box.build.engineering.mesh.example", account.Peers["builder"].FQDN(account.RootDomain.DNSSuffix))
	keys, err := s.GetAccountSetupKeys(ctx, LockingStrengthNone, "legacy")
	require.NoError(t, err)
	byKey := map[string]*types.SetupKey{}
	for _, key := range keys {
		byKey[key.Id] = key
	}
	require.Equal(t, rootID, byKey[rootKey.Id].DomainID)
	require.Equal(t, child.ID, byKey[childKey.Id].DomainID)
	require.Equal(t, child.Path, byKey[childKey.Id].DomainPath)
	require.Equal(t, uint64(42), account.Network.Serial)
	migrated, err := s.GetDomainByID(ctx, LockingStrengthNone, "legacy", engineering.ID)
	require.NoError(t, err)
	require.Equal(t, rootID, migrated.ParentID)
	require.Equal(t, engineering.Path, migrated.Path)
	domains, err := s.GetAccountDomains(ctx, LockingStrengthNone, "legacy")
	require.NoError(t, err)
	bindings, err := s.GetUserDomainRoleBindings(ctx, "legacy", "admin")
	require.NoError(t, err)
	scope := meshdomain.NewAdminScope("legacy", "admin", domains, bindings)
	require.True(t, scope.Covers(child.ID))
	require.False(t, scope.Covers(rootID), "migration cannot widen a child grant to the root")
	require.NoError(t, s.InitializeMeshDomains(ctx, "different-inactive-default.example"))
	again, err := s.GetAccountRootDomain(ctx, LockingStrengthNone, "legacy")
	require.NoError(t, err)
	require.Equal(t, rootID, again.ID, "repeat initialization must not create a second root")
	// Replacing an account snapshot must not delete the separately stored tree.
	require.NoError(t, s.SaveAccount(ctx, account.Copy()))
	after, err := s.GetAccountDomains(ctx, LockingStrengthNone, "legacy")
	require.NoError(t, err)
	require.Len(t, after, len(domains))
}

func TestMeshRootMigrationRejectsAmbiguityWithoutPartialWrites(t *testing.T) {
	for _, mode := range []string{"conflicting-suffix", "missing-suffix", "invalid-suffix", "missing-parent", "missing-device-domain", "missing-key-domain", "missing-binding-domain", "invalid-path", "overlong-name"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			s := rootMigrationStore(t, "mesh.example")
			d := meshdomain.NewDomain("legacy", "", "engineering", "")
			peer := &nbpeer.Peer{ID: "device", AccountID: "legacy", Key: "device-key", DNSLabel: "laptop"}
			switch mode {
			case "conflicting-suffix":
				require.NoError(t, s.db.Model(&types.Account{}).Where("id = ?", "legacy").Update("network_dns", "other.example").Error)
			case "missing-suffix":
				require.NoError(t, s.db.Model(&types.Account{}).Where("id = ?", "legacy").Updates(map[string]any{"network_dns": "", "settings_dns_domain": ""}).Error)
			case "invalid-suffix":
				require.NoError(t, s.db.Model(&types.Account{}).Where("id = ?", "legacy").Update("settings_dns_domain", "invalid..example").Error)
			case "missing-parent":
				d.ParentID = "missing"
			case "invalid-path":
				d.Path = "wrong-parent-path"
			case "missing-device-domain":
				peer.DomainID = "missing"
			case "missing-key-domain":
				key, _ := types.GenerateSetupKey("bad-key", types.SetupKeyOneOff, time.Hour, nil, 1, false, false)
				key.AccountID, key.DomainID = "legacy", "missing"
				require.NoError(t, s.SaveSetupKey(ctx, key))
			case "missing-binding-domain":
				require.NoError(t, s.CreateDomainRoleBinding(ctx, meshdomain.NewDomainRoleBinding("legacy", "missing", "engineering", "admin")))
			case "overlong-name":
				peer.DNSLabel = strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 63)
			}
			require.NoError(t, s.CreateDomain(ctx, d))
			require.NoError(t, s.AddPeerToAccount(ctx, peer))
			err := s.InitializeMeshDomains(ctx, "")
			require.ErrorContains(t, err, "account legacy")
			require.ErrorContains(t, err, "reconcile")
			root, lookupErr := s.GetAccountRootDomain(ctx, LockingStrengthNone, "legacy")
			require.NoError(t, lookupErr)
			require.Nil(t, root)
			unchanged, lookupErr := s.GetDomainByID(ctx, LockingStrengthNone, "legacy", d.ID)
			require.NoError(t, lookupErr)
			require.Equal(t, d.ParentID, unchanged.ParentID)
			domains, lookupErr := s.GetAccountDomains(ctx, LockingStrengthNone, "legacy")
			require.NoError(t, lookupErr)
			require.Len(t, domains, 1, "the failed transaction must not leave a root row")
		})
	}
}

func TestMeshRootMigrationLegacyFallbackAndEmptyDefault(t *testing.T) {
	for _, fallback := range []string{"legacy.example", ""} {
		t.Run(fallback, func(t *testing.T) {
			s := rootMigrationStore(t, "")
			require.NoError(t, s.InitializeMeshDomains(context.Background(), fallback))
			root, err := s.GetAccountRootDomain(context.Background(), LockingStrengthNone, "legacy")
			require.NoError(t, err)
			expected := fallback
			if expected == "" {
				expected = "karst"
			}
			require.Equal(t, expected, root.DNSSuffix)
		})
	}
}

func TestMeshRootProvisioningIsAtomicAndUnique(t *testing.T) {
	ctx := context.Background()
	s := rootMigrationStore(t, "legacy.example")
	root, err := meshdomain.NewRoot("fresh", "karst")
	require.NoError(t, err)
	account := &types.Account{Id: "fresh", RootDomainID: root.ID, RootDomain: root, Settings: &types.Settings{DNSDomain: "wrong.example"}, Network: &types.Network{Dns: "karst"}}
	require.Error(t, s.SaveAccount(ctx, account), "invalid projections must roll back account and root together")
	domains, err := s.GetAccountDomains(ctx, LockingStrengthNone, account.Id)
	require.NoError(t, err)
	require.Empty(t, domains)
	_, err = s.GetAccount(ctx, account.Id)
	require.Error(t, err)
	account.Settings.DNSDomain = "karst"
	require.NoError(t, s.SaveAccount(ctx, account))
	second, err := meshdomain.NewRoot(account.Id, "another.example")
	require.NoError(t, err)
	require.Error(t, s.CreateDomain(ctx, second), "a database constraint must prevent multiple roots")
	loaded, err := s.GetAccount(ctx, account.Id)
	require.NoError(t, err)
	require.Equal(t, root.ID, loaded.RootDomainID)
	changed := loaded.Settings.Copy()
	changed.DNSDomain = "renamed.example"
	require.Error(t, s.SaveAccountSettings(ctx, account.Id, changed), "legacy settings writes cannot bypass rename safeguards")
	require.NoError(t, s.SaveAccount(ctx, loaded.Copy()))
}

func TestMeshRootConcurrentProvisioning(t *testing.T) {
	s := rootMigrationStore(t, "legacy.example")
	ctx := context.Background()
	start := make(chan struct{})
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		root, err := meshdomain.NewRoot("concurrent", "karst")
		require.NoError(t, err)
		account := &types.Account{Id: "concurrent", RootDomainID: root.ID, RootDomain: root, Settings: &types.Settings{DNSDomain: "karst"}, Network: &types.Network{Dns: "karst"}}
		go func() { <-start; results <- s.SaveAccount(ctx, account) }()
	}
	close(start)
	successes := 0
	for i := 0; i < 2; i++ {
		if <-results == nil {
			successes++
		}
	}
	require.Equal(t, 1, successes)
	root, err := s.GetAccountRootDomain(ctx, LockingStrengthNone, "concurrent")
	require.NoError(t, err)
	domains, err := s.GetAccountDomains(ctx, LockingStrengthNone, "concurrent")
	require.NoError(t, err)
	require.Len(t, domains, 1)
	require.Equal(t, root.ID, domains[0].ID)
	account, err := s.GetAccount(ctx, "concurrent")
	require.NoError(t, err)
	require.NoError(t, s.DeleteAccount(ctx, account))
	domains, err = s.GetAccountDomains(ctx, LockingStrengthNone, "concurrent")
	require.NoError(t, err)
	require.Empty(t, domains, "deleting an account must remove its root and tree")
}

func TestMeshRootMigrationRollsBackWriteFailureAndResumes(t *testing.T) {
	ctx := context.Background()
	s := rootMigrationStore(t, "mesh.example")
	peer := &nbpeer.Peer{ID: "device", AccountID: "legacy", Key: "device-key", DNSLabel: "laptop"}
	require.NoError(t, s.AddPeerToAccount(ctx, peer))
	// Fail the final account-reference write, after root creation and backfill.
	require.NoError(t, s.db.Callback().Update().Before("gorm:update").Register("test:fail_account_root", func(tx *gorm.DB) {
		if tx.Statement.Table == "accounts" {
			tx.AddError(errors.New("injected account write failure"))
		}
	}))
	err := s.InitializeMeshDomains(ctx, "")
	require.ErrorContains(t, err, "injected account write failure")
	require.NoError(t, s.db.Callback().Update().Remove("test:fail_account_root"))
	domains, err := s.GetAccountDomains(ctx, LockingStrengthNone, "legacy")
	require.NoError(t, err)
	require.Empty(t, domains)
	unchanged, err := s.GetPeerByID(ctx, LockingStrengthNone, "legacy", peer.ID)
	require.NoError(t, err)
	require.Empty(t, unchanged.DomainID, "backfill must roll back with its root")
	require.NoError(t, s.InitializeMeshDomains(ctx, ""))
	root, err := s.GetAccountRootDomain(ctx, LockingStrengthNone, "legacy")
	require.NoError(t, err)
	resumed, err := s.GetPeerByID(ctx, LockingStrengthNone, "legacy", peer.ID)
	require.NoError(t, err)
	require.Equal(t, root.ID, resumed.DomainID)
}
