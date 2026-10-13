// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package usage_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/karst/usage"
)

func TestPruneFinalizedPeriodCheckpointsOpeningCount(t *testing.T) {
	db := fixture(t)
	start := time.Date(2025, time.January, 1, 0, 0, 0, 0, time.UTC)
	end := start.AddDate(0, 1, 0)
	require.NoError(t, appendChange(db, usage.Change{ID: "enroll-old", AccountID: "a", GenerationID: "old", Kind: usage.Enrolled, At: start.AddDate(0, 0, 2)}))
	require.NoError(t, appendChange(db, usage.Change{ID: "revoke-old", AccountID: "a", GenerationID: "old", Kind: usage.Revoked, At: start.AddDate(0, 0, 20)}))

	finalizedAt := end.Add(time.Hour)
	retentionEnd := end.AddDate(0, 13, 0)
	removed, err := usage.PruneFinalizedPeriod(context.Background(), db, "a", start, end, finalizedAt, retentionEnd.Add(-time.Second))
	require.Error(t, err, "the period must remain until the full thirteen-month retention elapses")
	require.Zero(t, removed)
	var before int64
	require.NoError(t, db.Table("karst_usage_device_events").Count(&before).Error)
	require.EqualValues(t, 2, before)

	removed, err = usage.PruneFinalizedPeriod(context.Background(), db, "a", start, end, finalizedAt, retentionEnd)
	require.NoError(t, err)
	require.EqualValues(t, 2, removed)
	var after int64
	require.NoError(t, db.Table("karst_usage_device_events").Count(&after).Error)
	require.Zero(t, after)
	var checkpointCount int64
	require.NoError(t, db.Table("karst_usage_device_checkpoints").Count(&checkpointCount).Error)
	require.EqualValues(t, 1, checkpointCount)
	require.ErrorIs(t, appendChange(db, usage.Change{ID: "enroll-old", AccountID: "a", GenerationID: "old", Kind: usage.Enrolled, At: start.AddDate(0, 0, 2)}), usage.ErrConflict,
		"a retry older than the retained checkpoint must not recreate pruned history")

	// A new month continues from the checkpointed zero-device boundary. Both
	// Timeline and the coverage-aware report use the checkpoint, not deleted
	// source events, to reconstruct the correct opening count.
	nextEnrollment := retentionEnd.Add(-24 * time.Hour)
	require.NoError(t, appendChange(db, usage.Change{ID: "enroll-next", AccountID: "a", GenerationID: "next", Kind: usage.Enrolled, At: nextEnrollment}))
	reportStart, reportEnd := retentionEnd.Add(-48*time.Hour), retentionEnd.Add(-12*time.Hour)
	require.NoError(t, db.Create(&usage.Period{ID: "coverage", AccountID: "a", StartUS: reportStart.UnixMicro(), Complete: true}).Error)
	r := usage.Reporter{DB: db, Now: func() time.Time { return retentionEnd }}
	_, err = r.Devices(context.Background(), "a", start, start.Add(time.Hour))
	require.ErrorIs(t, err, usage.ErrCheckpoint, "a historical window before the earliest pruned checkpoint must fail closed")
	report, err := r.Devices(context.Background(), "a", reportStart, reportEnd)
	require.NoError(t, err)
	require.True(t, report.Complete)
	require.Equal(t, "43200000000", report.DeviceMicroseconds)
	require.Len(t, report.Segments, 2)
	require.EqualValues(t, 0, *report.Segments[0].Devices)
	require.EqualValues(t, 1, *report.Segments[1].Devices)

	segments, err := usage.Timeline(context.Background(), db, "a", reportStart, reportEnd)
	require.NoError(t, err)
	require.Equal(t, []usage.Segment{
		{Start: reportStart, End: nextEnrollment, Devices: 0},
		{Start: nextEnrollment, End: reportEnd, Devices: 1},
	}, segments)

	// Checkpoint rows are self-verifying; tampering makes a report fail closed.
	require.NoError(t, db.Table("karst_usage_device_checkpoints").Where("account_id = ?", "a").Update("device_count", 1).Error)
	_, err = r.Devices(context.Background(), "a", reportStart, reportEnd)
	require.True(t, errors.Is(err, usage.ErrCheckpoint), "corrupt checkpoint must not produce a plausible report: %v", err)
}

func TestPruneFinalizedPeriodValidatesEvidenceAndCalendar(t *testing.T) {
	db := fixture(t)
	start := time.Date(2025, time.January, 1, 0, 0, 0, 0, time.UTC)
	end := start.AddDate(0, 1, 0)
	now := end.AddDate(0, 13, 0)
	for _, test := range []struct {
		name        string
		start, end  time.Time
		finalizedAt time.Time
		now         time.Time
	}{
		{name: "missing finalization evidence", start: start, end: end, now: now},
		{name: "finalized after supplied clock", start: start, end: end, finalizedAt: now.Add(time.Second), now: now},
		{name: "non-calendar period", start: start.Add(time.Hour), end: end, finalizedAt: end, now: now},
		{name: "retention not elapsed", start: start, end: end, finalizedAt: end, now: now.Add(-time.Second)},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := usage.PruneFinalizedPeriod(context.Background(), db, "a", test.start, test.end, test.finalizedAt, test.now)
			require.Error(t, err)
		})
	}
}

func TestCheckpointRejectsSequenceGapBeforePruning(t *testing.T) {
	db := fixture(t)
	start := time.Date(2025, time.January, 1, 0, 0, 0, 0, time.UTC)
	end := start.AddDate(0, 1, 0)
	require.NoError(t, appendChange(db, usage.Change{ID: "enroll", AccountID: "a", GenerationID: "g", Kind: usage.Enrolled, At: start.Add(time.Hour)}))
	require.NoError(t, appendChange(db, usage.Change{ID: "revoke", AccountID: "a", GenerationID: "g", Kind: usage.Revoked, At: start.Add(2 * time.Hour)}))
	require.NoError(t, db.Exec("DELETE FROM karst_usage_device_events WHERE account_id = ? AND id = ?", "a", "enroll").Error)
	_, err := usage.PruneFinalizedPeriod(context.Background(), db, "a", start, end, end, end.AddDate(0, 13, 0))
	require.ErrorIs(t, err, usage.ErrCheckpoint)
	var remaining int64
	require.NoError(t, db.Table("karst_usage_device_events").Count(&remaining).Error)
	require.EqualValues(t, 1, remaining, "verification failure must roll back pruning")
}
