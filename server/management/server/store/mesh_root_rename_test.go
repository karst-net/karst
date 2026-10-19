// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package store

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/internals/modules/meshdomain"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func allowRename(Store) error { return nil }

func TestMeshRootRenameCommitRollbackAndRestart(t *testing.T) {
	ctx := context.Background()
	s := rootMigrationStore(t, "karst")
	require.NoError(t, s.InitializeMeshDomains(ctx, ""))
	root, err := s.GetAccountRootDomain(ctx, LockingStrengthNone, "legacy")
	require.NoError(t, err)
	child := meshdomain.NewDomain("legacy", root.ID, "engineering", "")
	require.NoError(t, s.CreateDomain(ctx, child))
	peer := &nbpeer.Peer{ID: "builder", AccountID: "legacy", Key: "stable-key", DomainID: child.ID, DNSLabel: "box.engineering"}
	require.NoError(t, s.AddPeerToAccount(ctx, peer))
	binding := meshdomain.NewDomainRoleBinding("legacy", child.ID, child.Path, "admin")
	require.NoError(t, s.CreateDomainRoleBinding(ctx, binding))
	preview, err := s.RootRename(ctx, "legacy", "CORP.Example.", "", false, allowRename)
	require.NoError(t, err)
	require.Equal(t, "corp.example", preview.NewSuffix)
	require.Equal(t, 1, preview.DeviceCount)
	require.Equal(t, 2, preview.DomainCount)
	require.Equal(t, meshdomain.RenameExample{Before: "box.engineering.karst", After: "box.engineering.corp.example"}, preview.Examples[0])
	again, err := s.RootRename(ctx, "legacy", "corp.example", "", false, allowRename)
	require.NoError(t, err)
	require.Equal(t, preview.Revision, again.Revision)
	committed, err := s.RootRename(ctx, "legacy", "corp.example", preview.Revision, true, allowRename)
	require.NoError(t, err)
	require.True(t, committed.Committed)
	require.Equal(t, uint64(1), committed.NamingRevision)
	require.Equal(t, "unobserved", committed.Convergence)
	after, err := s.GetAccount(ctx, "legacy")
	require.NoError(t, err)
	require.Equal(t, root.ID, after.RootDomainID)
	require.Equal(t, "corp.example", after.RootDomain.DNSSuffix)
	require.Equal(t, "corp.example", after.Settings.DNSDomain)
	require.Equal(t, "corp.example", after.Network.Dns)
	require.Equal(t, uint64(43), after.Network.Serial)
	// Legacy settings writes cannot restore the pre-rename suffix.
	settings := *after.Settings
	settings.DNSDomain = "karst"
	require.Error(t, s.SaveAccountSettings(ctx, "legacy", &settings))
	settings.DNSDomain = ""
	require.NoError(t, s.SaveAccountSettings(ctx, "legacy", &settings))
	require.Equal(t, "corp.example", settings.DNSDomain)
	require.Equal(t, peer.Key, after.Peers[peer.ID].Key)
	require.Equal(t, peer.DomainID, after.Peers[peer.ID].DomainID)
	require.Equal(t, peer.DNSLabel, after.Peers[peer.ID].DNSLabel)
	delegations, err := s.GetUserDomainRoleBindings(ctx, "legacy", "admin")
	require.NoError(t, err)
	require.Equal(t, binding.ID, delegations[0].ID)
	require.NoError(t, s.InitializeMeshDomains(ctx, "ignored"), "restart must load the committed root")
	rollback, err := s.RootRename(ctx, "legacy", "karst", "", false, allowRename)
	require.NoError(t, err)
	_, err = s.RootRename(ctx, "legacy", "karst", preview.Revision, true, allowRename)
	require.Error(t, err, "an old preview cannot roll state back")
	rolledBack, err := s.RootRename(ctx, "legacy", "karst", rollback.Revision, true, allowRename)
	require.NoError(t, err)
	require.Equal(t, uint64(2), rolledBack.NamingRevision)
}

func TestMeshRootRenameRejectsStaleOrInvalidPreview(t *testing.T) {
	ctx := context.Background()
	for _, change := range []string{"enroll", "domain", "serial", "target", "permission"} {
		t.Run(change, func(t *testing.T) {
			s := rootMigrationStore(t, "karst")
			require.NoError(t, s.InitializeMeshDomains(ctx, ""))
			preview, err := s.RootRename(ctx, "legacy", "corp.example", "", false, allowRename)
			require.NoError(t, err)
			suffix := "corp.example"
			authorize := allowRename
			switch change {
			case "enroll":
				require.NoError(t, s.AddPeerToAccount(ctx, &nbpeer.Peer{ID: "new", AccountID: "legacy", DNSLabel: "new"}))
			case "domain":
				require.NoError(t, s.CreateDomain(ctx, meshdomain.NewDomain("legacy", preview.RootID, "new", "")))
			case "serial":
				require.NoError(t, s.IncrementNetworkSerial(ctx, "legacy"))
			case "target":
				suffix = "other.example"
			case "permission":
				authorize = func(Store) error { return errors.New("permission revoked") }
			}
			_, err = s.RootRename(ctx, "legacy", suffix, preview.Revision, true, authorize)
			require.Error(t, err)
			root, err := s.GetAccountRootDomain(ctx, LockingStrengthNone, "legacy")
			require.NoError(t, err)
			require.Equal(t, "karst", root.DNSSuffix)
			require.Zero(t, root.NamingRevision)
		})
	}
	s := rootMigrationStore(t, "karst")
	require.NoError(t, s.InitializeMeshDomains(ctx, ""))
	require.NoError(t, s.AddPeerToAccount(ctx, &nbpeer.Peer{ID: "long", AccountID: "legacy", DNSLabel: strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63)}))
	_, err := s.RootRename(ctx, "legacy", strings.Repeat("d", 63)+".example", "", false, allowRename)
	require.Error(t, err)
	_, err = s.RootRename(ctx, "legacy", "bad_suffix", "", false, allowRename)
	require.Error(t, err)
}

func TestMeshRootRenameTransactionFailureLeavesOldState(t *testing.T) {
	ctx := context.Background()
	s := rootMigrationStore(t, "karst")
	require.NoError(t, s.InitializeMeshDomains(ctx, ""))
	preview, err := s.RootRename(ctx, "legacy", "corp.example", "", false, allowRename)
	require.NoError(t, err)
	require.NoError(t, s.db.Callback().Update().Before("gorm:update").Register("fail-rename-account", func(tx *gorm.DB) {
		if tx.Statement.Table == "accounts" {
			tx.AddError(errors.New("injected write failure"))
		}
	}))
	_, err = s.RootRename(ctx, "legacy", "corp.example", preview.Revision, true, allowRename)
	require.Error(t, err)
	require.NoError(t, s.db.Callback().Update().Remove("fail-rename-account"))
	root, err := s.GetAccountRootDomain(ctx, LockingStrengthNone, "legacy")
	require.NoError(t, err)
	require.Equal(t, "karst", root.DNSSuffix)
	require.Zero(t, root.NamingRevision)
	account, err := s.GetAccount(ctx, "legacy")
	require.NoError(t, err)
	require.Equal(t, "karst", account.Settings.DNSDomain)
	require.Equal(t, uint64(42), account.Network.Serial)
	_, err = s.RootRename(ctx, "legacy", "corp.example", preview.Revision, true, allowRename)
	require.NoError(t, err, "retry must recover without partial rename state")
}

func TestMeshRootRenameConcurrentConfirmation(t *testing.T) {
	ctx := context.Background()
	s := rootMigrationStore(t, "karst")
	require.NoError(t, s.InitializeMeshDomains(ctx, ""))
	preview, err := s.RootRename(ctx, "legacy", "corp.example", "", false, allowRename)
	require.NoError(t, err)
	start := make(chan struct{})
	results := make(chan error, 2)
	for range 2 {
		go func() {
			<-start
			_, err := s.RootRename(ctx, "legacy", "corp.example", preview.Revision, true, allowRename)
			results <- err
		}()
	}
	close(start)
	successes := 0
	for range 2 {
		if <-results == nil {
			successes++
		}
	}
	require.Equal(t, 1, successes)
	root, err := s.GetAccountRootDomain(ctx, LockingStrengthNone, "legacy")
	require.NoError(t, err)
	require.Equal(t, uint64(1), root.NamingRevision)
	require.Equal(t, "corp.example", root.DNSSuffix)
}

func TestMeshRootRenameRejectsSplitDNSConflict(t *testing.T) {
	ctx := context.Background()
	s := rootMigrationStore(t, "karst")
	require.NoError(t, s.InitializeMeshDomains(ctx, ""))
	require.NoError(t, s.SaveNameServerGroup(ctx, &nbdns.NameServerGroup{ID: "split", AccountID: "legacy", Domains: []string{"example"}, Enabled: true, NameServers: []nbdns.NameServer{{IP: netip.MustParseAddr("100.64.0.53"), Port: 53}}}))
	_, err := s.RootRename(ctx, "legacy", "corp.example", "", false, allowRename)
	require.ErrorContains(t, err, "conflicts with split DNS")
	preview, err := s.RootRename(ctx, "legacy", "corp.internal", "", false, allowRename)
	require.NoError(t, err)
	// A conflict introduced after preview is revalidated before commit.
	require.NoError(t, s.SaveNameServerGroup(ctx, &nbdns.NameServerGroup{ID: "split", AccountID: "legacy", Domains: []string{"internal"}, Enabled: true, NameServers: []nbdns.NameServer{{IP: netip.MustParseAddr("100.64.0.53"), Port: 53}}}))
	_, err = s.RootRename(ctx, "legacy", "corp.internal", preview.Revision, true, allowRename)
	require.ErrorContains(t, err, "conflicts with split DNS")
}

func TestMeshRootRenamePlacementInvalidatesPreview(t *testing.T) {
	ctx := context.Background()
	s := rootMigrationStore(t, "karst")
	require.NoError(t, s.InitializeMeshDomains(ctx, ""))
	root, err := s.GetAccountRootDomain(ctx, LockingStrengthNone, "legacy")
	require.NoError(t, err)
	child := meshdomain.NewDomain("legacy", root.ID, "engineering", "")
	require.NoError(t, s.CreateDomain(ctx, child))
	peer := &nbpeer.Peer{ID: "moving", Key: "stable-key", AccountID: "legacy", DomainID: root.ID, DNSLabel: "laptop"}
	require.NoError(t, s.AddPeerToAccount(ctx, peer))
	preview, err := s.RootRename(ctx, "legacy", "corp.example", "", false, allowRename)
	require.NoError(t, err)
	peer.DomainID, peer.DNSLabel = child.ID, "laptop.engineering"
	require.NoError(t, s.SavePeer(ctx, "legacy", peer))
	_, err = s.RootRename(ctx, "legacy", "corp.example", preview.Revision, true, allowRename)
	require.Error(t, err, "a naming change must invalidate confirmation even without a serial increment")
}
