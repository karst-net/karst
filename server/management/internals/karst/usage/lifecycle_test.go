// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package usage_test

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/netbirdio/netbird/management/internals/karst/usage"
)

var epoch = time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC)

func database(t *testing.T, path string) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(path+"?_busy_timeout=5000&_journal_mode=WAL"), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	sql, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { _ = sql.Close() })
	require.NoError(t, usage.Migrate(db))
	return db
}

func fixture(t *testing.T) *gorm.DB {
	t.Helper()
	return database(t, filepath.Join(t.TempDir(), "usage.db"))
}

func change(id, account, generation string, kind usage.Kind, seconds int) usage.Change {
	return usage.Change{ID: id, AccountID: account, GenerationID: generation, Kind: kind, At: epoch.Add(time.Duration(seconds) * time.Second)}
}

func appendChange(db *gorm.DB, c usage.Change) error {
	return db.Transaction(func(tx *gorm.DB) error { return usage.Append(tx, c) })
}

func timeline(t *testing.T, db *gorm.DB, account string, start, end int) []usage.Segment {
	t.Helper()
	segments, err := usage.Timeline(context.Background(), db, account,
		epoch.Add(time.Duration(start)*time.Second), epoch.Add(time.Duration(end)*time.Second))
	require.NoError(t, err)
	return segments
}

func segment(start, end int, count int64) usage.Segment {
	return usage.Segment{Start: epoch.Add(time.Duration(start) * time.Second), End: epoch.Add(time.Duration(end) * time.Second), Devices: count}
}

func TestLifecycleReplayAndReenrollment(t *testing.T) {
	db := fixture(t)
	first := change("enroll", "a", "generation-1", usage.Enrolled, 0)
	require.NoError(t, appendChange(db, first))
	require.NoError(t, appendChange(db, change("revoke", "a", "generation-1", usage.Revoked, 10)))
	// An old committed retry remains valid after revocation; it cannot reopen
	// a generation. Reusing a device key requires a new enrollment generation.
	require.NoError(t, appendChange(db, first))
	require.ErrorIs(t, appendChange(db, change("new-id", "a", "generation-1", usage.Enrolled, 20)), usage.ErrConflict)
	require.NoError(t, appendChange(db, change("enroll-2", "a", "generation-2", usage.Enrolled, 20)))
	require.Equal(t, []usage.Segment{segment(0, 10, 1), segment(10, 20, 0), segment(20, 30, 1)}, timeline(t, db, "a", 0, 30))
	// The ledger has no online-state dependency: the open interval continues.
	require.Equal(t, []usage.Segment{segment(100, 200, 1)}, timeline(t, db, "a", 100, 200))
}

func TestConflictsDoNotAlterHistory(t *testing.T) {
	db := fixture(t)
	c := change("one", "a", "g", usage.Enrolled, 10)
	require.NoError(t, appendChange(db, c))
	cases := []usage.Change{
		change("one", "a", "different", usage.Enrolled, 10),
		change("one", "a", "g", usage.Enrolled, 11),
		change("one", "a", "g", usage.Revoked, 10),
		change("two", "a", "g", usage.Enrolled, 10),
		change("two", "a", "unknown", usage.Revoked, 10),
		change("two", "a", "g", usage.Revoked, 9),
	}
	for _, candidate := range cases {
		require.ErrorIs(t, appendChange(db, candidate), usage.ErrConflict)
	}
	require.Equal(t, []usage.Segment{segment(0, 10, 0), segment(10, 20, 1)}, timeline(t, db, "a", 0, 20))
	require.NoError(t, appendChange(db, change("two", "a", "g", usage.Revoked, 10)))
	require.ErrorIs(t, appendChange(db, change("three", "a", "g", usage.Revoked, 11)), usage.ErrConflict)
	require.Equal(t, []usage.Segment{segment(0, 20, 0)}, timeline(t, db, "a", 0, 20))
}

func TestAccountIsolationAndHalfOpenBoundaries(t *testing.T) {
	db := fixture(t)
	for _, c := range []usage.Change{
		change("one", "a", "g", usage.Enrolled, 0),
		change("two", "a", "h", usage.Enrolled, 10),
		change("three", "a", "g", usage.Revoked, 20),
		change("four", "a", "h", usage.Revoked, 30),
		change("one", "b", "g", usage.Enrolled, 0),
	} {
		require.NoError(t, appendChange(db, c))
	}
	require.Equal(t, []usage.Segment{segment(5, 10, 1), segment(10, 20, 2), segment(20, 25, 1)}, timeline(t, db, "a", 5, 25))
	require.Equal(t, []usage.Segment{segment(10, 20, 2)}, timeline(t, db, "a", 10, 20))
	require.Equal(t, []usage.Segment{segment(30, 40, 0)}, timeline(t, db, "a", 30, 40))
	require.Equal(t, []usage.Segment{segment(0, 40, 1)}, timeline(t, db, "b", 0, 40))
	require.Equal(t, []usage.Segment{segment(0, 40, 0)}, timeline(t, db, "absent", 0, 40))
}

func TestRequiresTransactionAndValidInputs(t *testing.T) {
	db := fixture(t)
	c := change("one", "a", "g", usage.Enrolled, 0)
	require.ErrorIs(t, usage.Append(db, c), usage.ErrTransaction)
	require.ErrorIs(t, usage.Append(nil, c), usage.ErrTransaction)
	for _, mutate := range []func(*usage.Change){
		func(c *usage.Change) { c.AccountID = "" },
		func(c *usage.Change) { c.ID = "" },
		func(c *usage.Change) { c.GenerationID = "" },
		func(c *usage.Change) { c.ID = strings.Repeat("x", 129) },
		func(c *usage.Change) { c.Kind = "online" },
		func(c *usage.Change) { c.At = time.Time{} },
		func(c *usage.Change) { c.At = c.At.Add(time.Nanosecond) },
	} {
		candidate := c
		mutate(&candidate)
		require.ErrorIs(t, appendChange(db, candidate), usage.ErrInvalid)
	}
	_, err := usage.Timeline(context.Background(), db, "", epoch, epoch.Add(time.Second))
	require.ErrorIs(t, err, usage.ErrInvalid)
	_, err = usage.Timeline(context.Background(), db, "a", epoch, epoch)
	require.ErrorIs(t, err, usage.ErrInvalid)
}

// This table stands in for authoritative membership so both failure directions
// exercise the real SQL transaction, rather than a mock post-commit callback.
type membership struct {
	ID string `gorm:"primaryKey"`
}

func TestMembershipAndLedgerRollbackTogether(t *testing.T) {
	db := fixture(t)
	require.NoError(t, db.AutoMigrate(&membership{}))
	c := change("one", "a", "g", usage.Enrolled, 0)
	failure := errors.New("injected failure after ledger append")
	err := db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&membership{ID: "g"}).Error; err != nil {
			return err
		}
		if err := usage.Append(tx, c); err != nil {
			return err
		}
		return failure
	})
	require.ErrorIs(t, err, failure)
	var count int64
	require.NoError(t, db.Model(&membership{}).Count(&count).Error)
	require.Zero(t, count)
	require.Equal(t, []usage.Segment{segment(0, 10, 0)}, timeline(t, db, "a", 0, 10))
	// The rolled-back retry key is reusable, and the next commit is durable.
	require.NoError(t, db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&membership{ID: "g"}).Error; err != nil {
			return err
		}
		return usage.Append(tx, c)
	}))
	// A ledger write failure must also roll back membership deletion.
	require.NoError(t, db.Callback().Create().Before("gorm:create").Register("fail_usage", func(tx *gorm.DB) {
		if tx.Statement.Table == "karst_usage_device_events" {
			tx.AddError(failure)
		}
	}))
	err = db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Delete(&membership{ID: "g"}).Error; err != nil {
			return err
		}
		return usage.Append(tx, change("two", "a", "g", usage.Revoked, 5))
	})
	require.ErrorIs(t, err, failure)
	require.NoError(t, db.Callback().Create().Remove("fail_usage"))
	require.NoError(t, db.Model(&membership{}).Count(&count).Error)
	require.EqualValues(t, 1, count)
	require.Equal(t, []usage.Segment{segment(0, 10, 1)}, timeline(t, db, "a", 0, 10))
}

func TestReopenAndConcurrentRetries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "usage.db")
	db := database(t, path)
	c := change("one", "a", "g", usage.Enrolled, 0)
	require.NoError(t, appendChange(db, c))
	sql, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sql.Close())
	db = database(t, path)
	require.NoError(t, appendChange(db, c))
	require.Equal(t, []usage.Segment{segment(0, 10, 1)}, timeline(t, db, "a", 0, 10))

	var wg sync.WaitGroup
	errorsOut := make(chan error, 16)
	for i := range 16 {
		wg.Go(func() {
			// Two concurrent attempts per unique event; both must succeed but
			// contribute once. Distinct generations must not lose updates.
			event := change(fmt.Sprintf("event-%d", i/2), "a", fmt.Sprintf("g-%d", i/2), usage.Enrolled, 1)
			errorsOut <- appendChange(db, event)
		})
	}
	wg.Wait()
	close(errorsOut)
	for err := range errorsOut {
		require.NoError(t, err)
	}
	require.Equal(t, []usage.Segment{segment(0, 1, 1), segment(1, 10, 9)}, timeline(t, db, "a", 0, 10))
}
