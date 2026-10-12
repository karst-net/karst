// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package billing

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestRelayCapRequiresExplicitAssignmentAndAcknowledgment(t *testing.T) {
	store := testBillingStore(t)
	ctx := WithAccount(context.Background(), "org-cap")
	start, end := testCapPeriod()
	if _, err := store.SetRelaySpendingCap(ctx, start, end, 200, true, "owner-1"); !errors.Is(err, ErrScheduleUnassigned) {
		t.Fatalf("cap without assigned rate schedule = %v, want ErrScheduleUnassigned", err)
	}
	require.NoError(t, store.PutSchedule(ctx, testSchedule()))
	require.NoError(t, store.AssignSchedule(ctx, start, end, testSchedule().Version))
	if _, err := store.SetRelaySpendingCap(ctx, start, end, 200, false, "owner-1"); !errors.Is(err, ErrInvalidPeriod) {
		t.Fatalf("unacknowledged cap = %v, want ErrInvalidPeriod", err)
	}
	if _, err := store.RelaySpendingCap(ctx, start, end); !errors.Is(err, ErrRelayCapNotConfigured) {
		t.Fatalf("unset cap = %v, want ErrRelayCapNotConfigured", err)
	}
}

func TestRelayCapRevisionsAndCrossRelayReservationsShareOneBudget(t *testing.T) {
	store := testBillingStore(t)
	ctx := WithAccount(context.Background(), "org-cap")
	start, end := testCapPeriod()
	schedule := testSchedule() // 10 GB included plus $2.00 = 20 GB maximum.
	require.NoError(t, store.PutSchedule(ctx, schedule))
	require.NoError(t, store.AssignSchedule(ctx, start, end, schedule.Version))

	cap, err := store.SetRelaySpendingCap(ctx, start, end, 200, true, "owner-1")
	require.NoError(t, err)
	require.Equal(t, uint64(1), cap.Revision)
	require.Equal(t, int64(200), cap.OverageMinor)
	capAgain, err := store.SetRelaySpendingCap(ctx, start, end, 200, true, "owner-1")
	require.NoError(t, err)
	require.Equal(t, uint64(1), capAgain.Revision)
	cap, err = store.SetRelaySpendingCap(ctx, start, end, 400, true, "owner-2")
	require.NoError(t, err)
	require.Equal(t, uint64(2), cap.Revision)
	var revisions int64
	require.NoError(t, store.db.Model(&relayCapRevisionRow{}).Where("account_id = ? AND period_start_us = ?", "org-cap", start.UnixMicro()).Count(&revisions).Error)
	require.EqualValues(t, 2, revisions)

	// The $4.00 cap allows 30 GB total. Concurrent relay requests contend on
	// one organization lock; retries reuse their first grant instead of minting
	// a second reservation.
	first, err := store.ReserveRelayCredits(ctx, start, end, "relay-a", "epoch-a", "map-v1", "req-a", 20_000_000_000)
	require.NoError(t, err)
	require.Equal(t, "20000000000", first.GrantedBytes)
	retry, err := store.ReserveRelayCredits(ctx, start, end, "relay-a", "epoch-a", "map-v1", "req-a", 20_000_000_000)
	require.NoError(t, err)
	require.Equal(t, first.GrantID, retry.GrantID)
	if _, err := store.ReserveRelayCredits(ctx, start, end, "relay-a", "epoch-a", "map-v1", "req-a", 1); !errors.Is(err, ErrCreditRequestConflict) {
		t.Fatalf("idempotency key with changed request = %v, want ErrCreditRequestConflict", err)
	}
	second, err := store.ReserveRelayCredits(ctx, start, end, "relay-b", "epoch-b", "map-v1", "req-b", 20_000_000_000)
	require.NoError(t, err)
	require.Equal(t, "10000000000", second.GrantedBytes)
	if _, err := store.SetRelaySpendingCap(ctx, start, end, 100, true, "owner-1"); !errors.Is(err, ErrRelayCapDecrease) {
		t.Fatalf("decrease with outstanding relay grants = %v, want ErrRelayCapDecrease", err)
	}
	if _, err := store.ReserveRelayCredits(ctx, start, end, "relay-c", "epoch-c", "map-v1", "req-c", 1); !errors.Is(err, ErrRelayCapExhausted) {
		t.Fatalf("grant beyond shared budget = %v, want ErrRelayCapExhausted", err)
	}

	// Credits return only after the signed relay's durable surrender/fence has
	// been verified by the HTTP boundary. The backend keeps consumed bytes.
	released, err := store.SurrenderRelayCredits(ctx, first.GrantID, "relay-a", "epoch-a", "5000000000", fmt.Sprintf("%064x", 1))
	require.NoError(t, err)
	require.Equal(t, "20000000000", released.GrantedBytes)
	returned, err := store.ReserveRelayCredits(ctx, start, end, "relay-c", "epoch-c", "map-v1", "req-c", 5_000_000_000)
	require.NoError(t, err)
	require.Equal(t, "5000000000", returned.GrantedBytes)
	if _, err := store.SurrenderRelayCredits(ctx, first.GrantID, "relay-a", "epoch-a", "6000000000", fmt.Sprintf("%064x", 2)); !errors.Is(err, ErrCreditGrantConflict) {
		t.Fatalf("conflicting surrender replay = %v, want ErrCreditGrantConflict", err)
	}
	if _, err := store.SetRelaySpendingCap(ctx, start, end, 100, true, "owner-1"); !errors.Is(err, ErrRelayCapDecrease) {
		t.Fatalf("decrease with outstanding grants = %v, want ErrRelayCapDecrease", err)
	}
	_, err = store.SurrenderRelayCredits(ctx, second.GrantID, "relay-b", "epoch-b", "10000000000", fmt.Sprintf("%064x", 3))
	require.NoError(t, err)
	_, err = store.SurrenderRelayCredits(ctx, returned.GrantID, "relay-c", "epoch-c", "0", fmt.Sprintf("%064x", 4))
	require.NoError(t, err)
	cap, err = store.SetRelaySpendingCap(ctx, start, end, 100, true, "owner-1")
	require.NoError(t, err)
	require.Equal(t, uint64(3), cap.Revision)
	require.EqualValues(t, 3, revisionsCount(t, store, "org-cap", start))
	if _, err := store.SetRelaySpendingCap(ctx, start, end, 50, true, "owner-1"); !errors.Is(err, ErrRelayCapDecrease) {
		t.Fatalf("decrease below already consumed credits = %v, want ErrRelayCapDecrease", err)
	}
}

func revisionsCount(t *testing.T, store *Store, account string, start time.Time) int64 {
	t.Helper()
	var count int64
	require.NoError(t, store.db.Model(&relayCapRevisionRow{}).Where("account_id = ? AND period_start_us = ?", account, start.UnixMicro()).Count(&count).Error)
	return count
}

func TestRelayCapAndGrantsAreAccountScopedAndPersisted(t *testing.T) {
	store := testBillingStore(t)
	ctx := WithAccount(context.Background(), "org-cap")
	start, end := testCapPeriod()
	schedule := testSchedule()
	require.NoError(t, store.PutSchedule(ctx, schedule))
	require.NoError(t, store.AssignSchedule(ctx, start, end, schedule.Version))
	_, err := store.SetRelaySpendingCap(ctx, start, end, 100, true, "owner-1")
	require.NoError(t, err)
	grant, err := store.ReserveRelayCredits(ctx, start, end, "relay-a", "epoch-a", "map-v1", "req-a", 1_000_000_000)
	require.NoError(t, err)

	other := WithAccount(context.Background(), "org-other")
	if _, err := store.RelaySpendingCap(other, start, end); !errors.Is(err, ErrRelayCapNotConfigured) {
		t.Fatalf("other account read cap = %v, want ErrRelayCapNotConfigured", err)
	}
	if _, err := store.SurrenderRelayCredits(other, grant.GrantID, "relay-a", "epoch-a", "0", fmt.Sprintf("%064x", 1)); !errors.Is(err, ErrCreditGrantNotFound) {
		t.Fatalf("other account returned grant = %v, want ErrCreditGrantNotFound", err)
	}
	loaded, err := store.ReserveRelayCredits(ctx, start, end, "relay-a", "epoch-a", "map-v1", "req-a", 1_000_000_000)
	require.NoError(t, err)
	require.Equal(t, grant.GrantID, loaded.GrantID)
}

func TestRelayCapAndCreditGrantSurviveStoreRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "billing.db")
	open := func() *gorm.DB {
		db, err := gorm.Open(sqlite.Open(path), &gorm.Config{Logger: logger.Discard})
		require.NoError(t, err)
		return db
	}
	first, err := NewStore(open())
	require.NoError(t, err)
	ctx := WithAccount(context.Background(), "org-persistent-cap")
	start, end := testCapPeriod()
	schedule := testSchedule()
	require.NoError(t, first.PutSchedule(ctx, schedule))
	require.NoError(t, first.AssignSchedule(ctx, start, end, schedule.Version))
	cap, err := first.SetRelaySpendingCap(ctx, start, end, 200, true, "owner-1")
	require.NoError(t, err)
	grant, err := first.ReserveRelayCredits(ctx, start, end, "relay-a", "epoch-a", "map-v1", "req-a", 3_000_000_000)
	require.NoError(t, err)

	second, err := NewStore(open())
	require.NoError(t, err)
	loadedCap, err := second.RelaySpendingCap(ctx, start, end)
	require.NoError(t, err)
	require.Equal(t, cap, loadedCap)
	loadedGrant, err := second.ReserveRelayCredits(ctx, start, end, "relay-a", "epoch-a", "map-v1", "req-a", 3_000_000_000)
	require.NoError(t, err)
	require.Equal(t, grant, loadedGrant)
}

func TestRelayCreditReservationsAreSerializedAcrossConcurrentRelays(t *testing.T) {
	store := testBillingStore(t)
	ctx := WithAccount(context.Background(), "org-cap-race")
	start, end := testCapPeriod()
	schedule := testSchedule()
	require.NoError(t, store.PutSchedule(ctx, schedule))
	require.NoError(t, store.AssignSchedule(ctx, start, end, schedule.Version))
	_, err := store.SetRelaySpendingCap(ctx, start, end, 200, true, "owner-1") // 20 GB total.
	require.NoError(t, err)

	var wg sync.WaitGroup
	results := make(chan RelayCreditGrant, 2)
	errs := make(chan error, 2)
	for _, id := range []string{"relay-a", "relay-b"} {
		wg.Add(1)
		go func(relayID string) {
			defer wg.Done()
			grant, reserveErr := store.ReserveRelayCredits(ctx, start, end, relayID, "epoch-"+relayID, "map-v1", "request-"+relayID, 15_000_000_000)
			if reserveErr != nil {
				errs <- reserveErr
				return
			}
			results <- grant
		}(id)
	}
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	reserved := new(big.Int)
	count := 0
	for grant := range results {
		bytes, ok := new(big.Int).SetString(grant.GrantedBytes, 10)
		require.True(t, ok)
		reserved.Add(reserved, bytes)
		count++
	}
	require.Equal(t, 2, count)
	require.Equal(t, "20000000000", reserved.String())
}

func testCapPeriod() (time.Time, time.Time) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	return start, start.AddDate(0, 1, 0)
}
