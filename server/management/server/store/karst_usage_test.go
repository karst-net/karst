// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package store

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/netbirdio/netbird/management/internals/karst/usage"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/types"
)

func usageStore(t *testing.T) (*SqlStore, *time.Time) {
	t.Helper()
	s, err := NewSqliteStore(context.Background(), t.TempDir(), nil, false)
	require.NoError(t, err)
	db, err := s.db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	require.NoError(t, s.InitializeDeviceUsage())
	at := time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC)
	s.deviceUsage.Now = func() time.Time { return at }
	require.NoError(t, s.SaveAccount(context.Background(), &types.Account{Id: "a", Network: types.NewNetwork()}))
	return s, &at
}

func usagePeer(n int) *nbpeer.Peer {
	return &nbpeer.Peer{ID: fmt.Sprintf("peer-%d", n), AccountID: "a", Key: fmt.Sprintf("key-%d", n),
		DNSLabel: fmt.Sprintf("peer-%d", n), IP: netip.AddrFrom4([4]byte{100, 64, 0, byte(n)}), Status: &nbpeer.PeerStatus{}}
}

func eventCount(t *testing.T, s *SqlStore) int64 {
	t.Helper()
	var count int64
	require.NoError(t, s.db.Table("karst_usage_device_events").Where("account_id = ?", "a").Count(&count).Error)
	return count
}

func TestDeviceUsageSemanticMembership(t *testing.T) {
	s, at := usageStore(t)
	ctx := context.Background()
	p1, p2 := usagePeer(1), usagePeer(2)
	require.NoError(t, s.AddPeerToAccount(ctx, p1))
	require.Zero(t, eventCount(t, s), "unconfigured accounts do not collect")
	*at = at.Add(time.Second)
	require.NoError(t, s.SetDeviceUsageCollection(ctx, "a", true))
	require.EqualValues(t, 1, eventCount(t, s), "activation observes the existing peer")
	*at = at.Add(time.Second)
	require.NoError(t, s.AddPeerToAccount(ctx, p2))
	require.EqualValues(t, 2, eventCount(t, s))

	// Status and key updates preserve the enrollment generation.
	p1.Status.Connected = false
	p1.Key = "rotated-key"
	require.NoError(t, s.SavePeer(ctx, "a", p1))
	require.EqualValues(t, 2, eventCount(t, s))
	account, err := s.GetAccount(ctx, "a")
	require.NoError(t, err)
	require.NoError(t, s.SaveAccount(ctx, account))
	require.EqualValues(t, 2, eventCount(t, s), "association replacement is not re-enrollment")

	*at = at.Add(time.Second)
	account, err = s.GetAccount(ctx, "a")
	require.NoError(t, err)
	p3 := usagePeer(3)
	account.Peers[p3.ID] = p3
	delete(account.Peers, p2.ID)
	require.NoError(t, s.SaveAccount(ctx, account))
	require.EqualValues(t, 4, eventCount(t, s), "one real removal and one real addition")

	*at = at.Add(time.Second)
	require.NoError(t, s.DeletePeer(ctx, "a", p3.ID))
	require.EqualValues(t, 5, eventCount(t, s))
	*at = at.Add(time.Second)
	account, err = s.GetAccount(ctx, "a")
	require.NoError(t, err)
	require.NoError(t, s.DeleteAccount(ctx, account))
	require.EqualValues(t, 6, eventCount(t, s), "account deletion closes the last device")
	coverage, err := usage.Coverage(ctx, s.db, "a")
	require.NoError(t, err)
	require.Len(t, coverage, 1)
	require.NotNil(t, coverage[0].EndUS)
	require.Equal(t, at.UnixMicro(), *coverage[0].EndUS)
	segments, err := usage.Timeline(ctx, s.db, "a", at.Add(-time.Second), at.Add(time.Second))
	require.NoError(t, err)
	require.Len(t, segments, 2)
	require.EqualValues(t, 1, segments[0].Devices)
	require.Zero(t, segments[1].Devices)
}

func TestDeviceUsageOuterTransactionRollback(t *testing.T) {
	s, at := usageStore(t)
	ctx := context.Background()
	require.NoError(t, s.SetDeviceUsageCollection(ctx, "a", true))
	p := usagePeer(1)
	failure := errors.New("abort business transaction")
	err := s.ExecuteInTransaction(ctx, func(tx Store) error {
		if err := tx.AddPeerToAccount(ctx, p); err != nil {
			return err
		}
		return failure
	})
	require.ErrorIs(t, err, failure)
	require.Zero(t, eventCount(t, s))
	_, err = s.GetPeerByID(ctx, LockingStrengthNone, "a", p.ID)
	require.Error(t, err)
	require.NoError(t, s.AddPeerToAccount(ctx, p))
	*at = at.Add(time.Second)
	err = s.ExecuteInTransaction(ctx, func(tx Store) error {
		if err := tx.DeletePeer(ctx, "a", p.ID); err != nil {
			return err
		}
		return failure
	})
	require.ErrorIs(t, err, failure)
	require.EqualValues(t, 1, eventCount(t, s))
	_, err = s.GetPeerByID(ctx, LockingStrengthNone, "a", p.ID)
	require.NoError(t, err)

	// A ledger write failure cannot leave a deleted peer with an open charge.
	require.NoError(t, s.db.Callback().Create().Before("gorm:create").Register("fail_usage", func(tx *gorm.DB) {
		if tx.Statement.Table == "karst_usage_device_events" {
			tx.AddError(failure)
		}
	}))
	err = s.DeletePeer(ctx, "a", p.ID)
	require.ErrorIs(t, err, failure)
	require.NoError(t, s.db.Callback().Create().Remove("fail_usage"))
	_, err = s.GetPeerByID(ctx, LockingStrengthNone, "a", p.ID)
	require.NoError(t, err)
	require.EqualValues(t, 1, eventCount(t, s))
}

func TestDeviceUsageReactivationAndReconciliation(t *testing.T) {
	s, at := usageStore(t)
	ctx := context.Background()
	p1, p2 := usagePeer(1), usagePeer(2)
	require.NoError(t, s.AddPeerToAccount(ctx, p1))
	require.NoError(t, s.SetDeviceUsageCollection(ctx, "a", true))
	*at = at.Add(time.Second)
	require.NoError(t, s.SetDeviceUsageCollection(ctx, "a", false))
	*at = at.Add(time.Second)
	require.NoError(t, s.DeletePeer(ctx, "a", p1.ID))
	require.NoError(t, s.AddPeerToAccount(ctx, p2))
	require.EqualValues(t, 1, eventCount(t, s))
	*at = at.Add(time.Second)
	require.NoError(t, s.SetDeviceUsageCollection(ctx, "a", true))
	require.EqualValues(t, 3, eventCount(t, s))
	coverage, err := usage.Coverage(ctx, s.db, "a")
	require.NoError(t, err)
	require.Len(t, coverage, 2)
	require.Less(t, *coverage[0].EndUS, coverage[1].StartUS)

	// Simulate a legacy/uninstrumented deletion, which must be explicit in
	// coverage before subsequent membership writes are allowed to proceed.
	require.NoError(t, s.db.Delete(p2).Error)
	p3 := usagePeer(3)
	require.ErrorIs(t, s.AddPeerToAccount(ctx, p3), usage.ErrConflict)
	*at = at.Add(time.Second)
	require.NoError(t, s.ReconcileDeviceUsage(ctx, "a"))
	require.NoError(t, s.AddPeerToAccount(ctx, p3))
	coverage, err = usage.Coverage(ctx, s.db, "a")
	require.NoError(t, err)
	require.Len(t, coverage, 3)
	require.False(t, coverage[1].Complete)
	require.True(t, coverage[2].Complete)
}

func TestDeviceUsagePostgresAtomicActivation(t *testing.T) {
	dsn := os.Getenv("KARST_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("KARST_TEST_POSTGRES_DSN is not set")
	}
	admin, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	adminSQL, err := admin.DB()
	require.NoError(t, err)
	t.Cleanup(func() { _ = adminSQL.Close() })
	// Isolate the full store schema from concurrently running Karst package
	// tests. The schema identifier consists only of a fixed prefix and UUID.
	schema := "usage_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	require.NoError(t, admin.Exec("CREATE SCHEMA "+schema).Error)
	t.Cleanup(func() { require.NoError(t, admin.Exec("DROP SCHEMA "+schema+" CASCADE").Error) })
	u, err := url.Parse(dsn)
	require.NoError(t, err)
	query := u.Query()
	query.Set("search_path", schema)
	u.RawQuery = query.Encode()
	db, err := gorm.Open(postgres.Open(u.String()), &gorm.Config{})
	require.NoError(t, err)
	sql, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { _ = sql.Close() })
	ctx := context.Background()
	s, err := NewSqlStore(ctx, db, types.PostgresStoreEngine, nil, false)
	require.NoError(t, err)
	require.NoError(t, s.InitializeDeviceUsage())
	require.NoError(t, s.SaveAccount(ctx, &types.Account{Id: "a", Network: types.NewNetwork()}))

	// Independent transactions race activation with enrollment. Whichever
	// wins the account lock, every committed peer must be observed exactly once.
	var wg sync.WaitGroup
	errorsOut := make(chan error, 13)
	start := make(chan struct{})
	wg.Go(func() {
		<-start
		errorsOut <- s.SetDeviceUsageCollection(ctx, "a", true)
	})
	for i := 1; i <= 12; i++ {
		wg.Go(func() {
			<-start
			errorsOut <- s.AddPeerToAccount(ctx, usagePeer(i))
		})
	}
	close(start)
	wg.Wait()
	close(errorsOut)
	for err := range errorsOut {
		require.NoError(t, err)
	}
	require.EqualValues(t, 12, eventCount(t, s))
	coverage, err := usage.Coverage(ctx, db, "a")
	require.NoError(t, err)
	require.Len(t, coverage, 1)
	require.True(t, coverage[0].Complete)

	failure := errors.New("rollback after nested peer removal")
	err = s.ExecuteInTransaction(ctx, func(tx Store) error {
		if err := tx.DeletePeer(ctx, "a", usagePeer(1).ID); err != nil {
			return err
		}
		return failure
	})
	require.ErrorIs(t, err, failure)
	require.EqualValues(t, 12, eventCount(t, s))
	_, err = s.GetPeerByID(ctx, LockingStrengthNone, "a", usagePeer(1).ID)
	require.NoError(t, err)
	account, err := s.GetAccount(ctx, "a")
	require.NoError(t, err)
	require.NoError(t, s.SaveAccount(ctx, account))
	require.EqualValues(t, 12, eventCount(t, s), "account rewrite preserves PostgreSQL generations")
	end := time.Now().UTC().Truncate(time.Microsecond)
	report, err := (usage.Reporter{DB: db}).Devices(ctx, "a", time.UnixMicro(coverage[0].StartUS), end)
	require.NoError(t, err, "report queries and read-only repeatable-read transactions work on PostgreSQL")
	require.True(t, report.Complete)
	require.NotEmpty(t, report.Segments)
	require.EqualValues(t, 12, *report.Segments[len(report.Segments)-1].Devices)
}
