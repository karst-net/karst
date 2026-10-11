// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package usage_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/netbirdio/netbird/management/internals/karst/usage"
)

func TestReportDistinguishesGapsAndReconciliation(t *testing.T) {
	db, snapshot := collectionFixture(t)
	at := epoch
	c := usage.Collector{Now: func() time.Time { return at }}
	r := usage.Reporter{DB: db, Now: func() time.Time { return epoch.Add(50 * time.Second) }}
	configure := func(enabled bool) {
		t.Helper()
		require.NoError(t, db.Transaction(func(tx *gorm.DB) error { return c.Configure(tx, "a", enabled, snapshot) }))
	}
	require.NoError(t, db.Create(&collectedMember{ID: "one", AccountID: "a"}).Error)
	configure(true)
	at = epoch.Add(10 * time.Second)
	configure(false)
	require.NoError(t, db.Create(&collectedMember{ID: "two", AccountID: "a"}).Error)
	at = epoch.Add(30 * time.Second)
	configure(true)
	report, err := r.Devices(context.Background(), "a", epoch.Add(-10*time.Second), epoch.Add(40*time.Second))
	require.NoError(t, err)
	require.False(t, report.Complete)
	require.Equal(t, "30000000", report.DeviceMicroseconds)
	require.Len(t, report.Segments, 4)
	require.Equal(t, "uncollected", report.Segments[0].Coverage)
	require.Nil(t, report.Segments[0].Devices)
	require.EqualValues(t, 1, *report.Segments[1].Devices)
	require.Equal(t, "uncollected", report.Segments[2].Coverage)
	require.Nil(t, report.Segments[2].Devices)
	require.EqualValues(t, 2, *report.Segments[3].Devices)

	// Lost membership is not silently converted to a precise past count.
	require.NoError(t, db.Delete(&collectedMember{ID: "one"}).Error)
	at = epoch.Add(35 * time.Second)
	require.NoError(t, db.Transaction(func(tx *gorm.DB) error { return c.Reconcile(tx, "a", snapshot) }))
	report, err = r.Devices(context.Background(), "a", epoch, epoch.Add(40*time.Second))
	require.NoError(t, err)
	require.Equal(t, "15000000", report.DeviceMicroseconds)
	require.Len(t, report.Segments, 4)
	require.Equal(t, "incomplete", report.Segments[2].Coverage)
	require.Nil(t, report.Segments[2].Devices)
	require.EqualValues(t, 1, *report.Segments[3].Devices)

	other, err := r.Devices(context.Background(), "another-account", epoch, epoch.Add(40*time.Second))
	require.NoError(t, err)
	require.False(t, other.Complete)
	require.Equal(t, "0", other.DeviceMicroseconds)
	require.Len(t, other.Segments, 1)
	require.Nil(t, other.Segments[0].Devices, "unknown must not become a known zero")
}

func TestReportHalfOpenWindowsAndZeroDurationCoverage(t *testing.T) {
	db, snapshot := collectionFixture(t)
	at := epoch
	c := usage.Collector{Now: func() time.Time { return at }}
	r := usage.Reporter{DB: db, Now: func() time.Time { return epoch.Add(time.Minute) }}
	for _, enabled := range []bool{true, false, true} {
		require.NoError(t, db.Transaction(func(tx *gorm.DB) error { return c.Configure(tx, "a", enabled, snapshot) }))
	}
	for i := 1; i <= 2; i++ {
		at = epoch.Add(time.Duration(i) * 10 * time.Second)
		require.NoError(t, db.Transaction(func(tx *gorm.DB) error {
			return c.Track(tx, "a", snapshot, func(tx *gorm.DB) error {
				return tx.Create(&collectedMember{ID: fmt.Sprint(i), AccountID: "a"}).Error
			})
		}))
	}
	report, err := r.Devices(context.Background(), "a", epoch.Add(10*time.Second), epoch.Add(20*time.Second))
	require.NoError(t, err)
	require.True(t, report.Complete)
	require.Equal(t, "10000000", report.DeviceMicroseconds)
	require.Len(t, report.Segments, 1)
	require.EqualValues(t, 1, *report.Segments[0].Devices)
	zero, err := r.Devices(context.Background(), "a", epoch, epoch.Add(10*time.Second))
	require.NoError(t, err)
	require.True(t, zero.Complete)
	require.Equal(t, "0", zero.DeviceMicroseconds)
	require.NotNil(t, zero.Segments[0].Devices)
	require.Zero(t, *zero.Segments[0].Devices)
	boundary, err := r.Devices(context.Background(), "a", epoch.Add(-time.Second), epoch.Add(10*time.Second))
	require.NoError(t, err)
	require.Len(t, boundary.Segments, 2, "zero-duration coverage must not obscure the open period")
	require.Equal(t, "uncollected", boundary.Segments[0].Coverage)
	require.Equal(t, "complete", boundary.Segments[1].Coverage)
}

func TestReportBoundsAndPrecision(t *testing.T) {
	db := fixture(t)
	r := usage.Reporter{DB: db, Now: func() time.Time { return epoch.Add(time.Hour) }}
	for _, window := range [][2]time.Time{
		{epoch, epoch}, {epoch.Add(time.Second), epoch},
		{epoch.Add(-usage.MaxReportWindow - time.Second), epoch},
		{epoch, epoch.Add(2 * time.Hour)}, {epoch.Add(time.Nanosecond), epoch.Add(time.Second)},
	} {
		_, err := r.Devices(context.Background(), "a", window[0], window[1])
		require.ErrorIs(t, err, usage.ErrInvalid)
	}
	var rows []map[string]any
	for i := 0; i <= usage.MaxReportSegments; i++ {
		rows = append(rows, map[string]any{"account_id": "a", "id": fmt.Sprint(i), "generation_id": fmt.Sprint(i),
			"sequence": i + 1, "kind": "enrolled", "at_us": epoch.Add(time.Duration(i+1) * time.Microsecond).UnixMicro()})
	}
	require.NoError(t, db.Table("karst_usage_device_events").CreateInBatches(rows, 100).Error)
	_, err := r.Devices(context.Background(), "a", epoch, epoch.Add(time.Second))
	require.ErrorIs(t, err, usage.ErrReportLimit, "never silently truncate a dense timeline")
	_, err = r.Devices(context.Background(), "a", epoch, epoch.Add(time.Microsecond))
	require.NoError(t, err, "a narrower window can be reported")
}

func TestReportDoesNotMixCoverageAndLifecycleSnapshots(t *testing.T) {
	db, snapshot := collectionFixture(t)
	c := usage.Collector{Now: func() time.Time { return epoch }}
	require.NoError(t, db.Create(&collectedMember{ID: "one", AccountID: "a"}).Error)
	require.NoError(t, db.Transaction(func(tx *gorm.DB) error { return c.Configure(tx, "a", true, snapshot) }))
	var once sync.Once
	// Commit a separate writer after the report reads coverage but before it
	// reads lifecycle events. WAL permits that writer while the report holds
	// its original snapshot. Mixing snapshots would change the report's total.
	require.NoError(t, db.Callback().Query().After("gorm:query").Register("change_after_coverage", func(tx *gorm.DB) {
		if tx.Statement.Table != "karst_usage_device_coverage" {
			return
		}
		once.Do(func() {
			writer := usage.Collector{Now: func() time.Time { return epoch.Add(10 * time.Second) }}
			err := db.Transaction(func(other *gorm.DB) error {
				if err := writer.Track(other, "a", snapshot, func(other *gorm.DB) error {
					return other.Delete(&collectedMember{ID: "one"}).Error
				}); err != nil {
					return err
				}
				return writer.Configure(other, "a", false, snapshot)
			})
			if err != nil {
				tx.AddError(err)
			}
		})
	}))
	t.Cleanup(func() { require.NoError(t, db.Callback().Query().Remove("change_after_coverage")) })
	r := usage.Reporter{DB: db, Now: func() time.Time { return epoch.Add(time.Minute) }}
	first, err := r.Devices(context.Background(), "a", epoch, epoch.Add(30*time.Second))
	require.NoError(t, err)
	require.True(t, first.Complete)
	require.Equal(t, "30000000", first.DeviceMicroseconds)
	second, err := r.Devices(context.Background(), "a", epoch, epoch.Add(30*time.Second))
	require.NoError(t, err)
	require.False(t, second.Complete)
	require.Equal(t, "10000000", second.DeviceMicroseconds)
}
