// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package usage_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/netbirdio/netbird/management/internals/karst/usage"
)

type collectedMember struct {
	ID        string `gorm:"primaryKey"`
	AccountID string
}

func collectionFixture(t *testing.T) (*gorm.DB, usage.Snapshot) {
	t.Helper()
	db := fixture(t)
	require.NoError(t, db.AutoMigrate(&collectedMember{}))
	return db, func(tx *gorm.DB) ([]string, error) {
		var ids []string
		err := tx.Model(&collectedMember{}).Where("account_id = ?", "a").Order("id").Pluck("id", &ids).Error
		return ids, err
	}
}

func periods(t *testing.T, db *gorm.DB) []usage.Period {
	t.Helper()
	rows, err := usage.Coverage(context.Background(), db, "a")
	require.NoError(t, err)
	return rows
}

func TestCollectionActivationAndDisabledGap(t *testing.T) {
	db, snapshot := collectionFixture(t)
	at := epoch
	c := usage.Collector{Now: func() time.Time { return at }}
	configure := func(enabled bool) {
		t.Helper()
		require.NoError(t, db.Transaction(func(tx *gorm.DB) error {
			return c.Configure(tx, "a", enabled, snapshot)
		}))
	}
	track := func(fn func(*gorm.DB) error) {
		t.Helper()
		require.NoError(t, db.Transaction(func(tx *gorm.DB) error { return c.Track(tx, "a", snapshot, fn) }))
	}
	track(func(tx *gorm.DB) error { return tx.Create(&collectedMember{ID: "one", AccountID: "a"}).Error })
	require.Empty(t, periods(t, db), "default-off mutations do not claim coverage")
	configure(true)
	configure(true)
	require.Len(t, periods(t, db), 1, "repeated enable does not restart coverage")
	require.Equal(t, []usage.Segment{segment(-10, 0, 0), segment(0, 10, 1)}, timeline(t, db, "a", -10, 10))
	at = epoch.Add(10 * time.Second)
	track(func(tx *gorm.DB) error { return tx.Create(&collectedMember{ID: "two", AccountID: "a"}).Error })
	at = epoch.Add(20 * time.Second)
	configure(false)
	configure(false)
	at = epoch.Add(30 * time.Second)
	track(func(tx *gorm.DB) error {
		if err := tx.Delete(&collectedMember{ID: "one"}).Error; err != nil {
			return err
		}
		return tx.Create(&collectedMember{ID: "three", AccountID: "a"}).Error
	})
	at = epoch.Add(40 * time.Second)
	configure(true)
	coverage := periods(t, db)
	require.Len(t, coverage, 2)
	require.Equal(t, epoch.UnixMicro(), coverage[0].StartUS)
	require.Equal(t, epoch.Add(20*time.Second).UnixMicro(), *coverage[0].EndUS)
	require.Equal(t, at.UnixMicro(), coverage[1].StartUS)
	require.Nil(t, coverage[1].EndUS)
	require.True(t, coverage[0].Complete)
	require.True(t, coverage[1].Complete)
	// Three is observed only at reactivation. No fabricated event at time 30.
	var events int64
	require.NoError(t, db.Table("karst_usage_device_events").Where("at_us = ?", epoch.Add(30*time.Second).UnixMicro()).Count(&events).Error)
	require.Zero(t, events)
	require.Equal(t, []usage.Segment{segment(40, 50, 2)}, timeline(t, db, "a", 40, 50))
	other, err := usage.Coverage(context.Background(), db, "b")
	require.NoError(t, err)
	require.Empty(t, other)
}

func TestCollectionReconciliationPreservesUncertainty(t *testing.T) {
	db, snapshot := collectionFixture(t)
	at := epoch
	c := usage.Collector{Now: func() time.Time { return at }}
	require.NoError(t, db.Transaction(func(tx *gorm.DB) error { return c.Configure(tx, "a", true, snapshot) }))
	// Simulate an uninstrumented writer. Track must not quietly normalize it.
	require.NoError(t, db.Create(&collectedMember{ID: "untracked", AccountID: "a"}).Error)
	at = epoch.Add(10 * time.Second)
	err := db.Transaction(func(tx *gorm.DB) error {
		return c.Track(tx, "a", snapshot, func(tx *gorm.DB) error {
			t.Fatal("mutation must not run with an undisclosed discrepancy")
			return nil
		})
	})
	require.ErrorIs(t, err, usage.ErrConflict)
	require.NoError(t, db.Transaction(func(tx *gorm.DB) error { return c.Reconcile(tx, "a", snapshot) }))
	require.NoError(t, db.Transaction(func(tx *gorm.DB) error { return c.Reconcile(tx, "a", snapshot) }))
	coverage := periods(t, db)
	require.Len(t, coverage, 2)
	require.False(t, coverage[0].Complete)
	require.Equal(t, at.UnixMicro(), *coverage[0].EndUS)
	require.True(t, coverage[1].Complete)
	var discrepancies []usage.Discrepancy
	require.NoError(t, db.Find(&discrepancies).Error)
	require.Len(t, discrepancies, 1)
	require.Equal(t, 1, discrepancies[0].Added)
	require.Zero(t, discrepancies[0].Missing)
	require.Equal(t, []usage.Segment{segment(0, 10, 0), segment(10, 20, 1)}, timeline(t, db, "a", 0, 20))
}

func TestCollectionRollbackAndClockRegression(t *testing.T) {
	db, snapshot := collectionFixture(t)
	at := epoch
	c := usage.Collector{Now: func() time.Time { return at }}
	failure := errors.New("abort activation")
	err := db.Transaction(func(tx *gorm.DB) error {
		if err := c.Configure(tx, "a", true, snapshot); err != nil {
			return err
		}
		return failure
	})
	require.ErrorIs(t, err, failure)
	require.Empty(t, periods(t, db))
	require.NoError(t, db.Transaction(func(tx *gorm.DB) error { return c.Configure(tx, "a", true, snapshot) }))
	at = epoch.Add(-time.Second)
	err = db.Transaction(func(tx *gorm.DB) error {
		return c.Track(tx, "a", snapshot, func(tx *gorm.DB) error {
			return tx.Create(&collectedMember{ID: "rolled-back", AccountID: "a"}).Error
		})
	})
	require.ErrorIs(t, err, usage.ErrConflict)
	var count int64
	require.NoError(t, db.Model(&collectedMember{}).Count(&count).Error)
	require.Zero(t, count, "clock rejection rolls membership back as well")
	require.ErrorIs(t, c.Configure(db, "a", true, snapshot), usage.ErrTransaction)
	require.ErrorIs(t, c.Track(db, "a", snapshot, nil), usage.ErrTransaction)
	require.ErrorIs(t, c.Reconcile(db, "a", snapshot), usage.ErrTransaction)
}
