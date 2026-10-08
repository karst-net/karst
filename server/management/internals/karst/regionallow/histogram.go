// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package regionallow

import (
	"context"
	"errors"
	"fmt"

	"gorm.io/gorm"
)

// Bucket names for a measured anchor RTT — the same four ranges §4a's relay
// histogram uses (RTTUnder20ms/RTT20To50ms/RTT50To100ms/RTTOver100ms in
// relaytelemetry.go), so an operator reading both histograms sees one set of
// buckets, not two conventions for the same kind of measurement.
const (
	BucketUnder20ms = "under_20ms"
	Bucket20To50ms  = "20_to_50ms"
	Bucket50To100ms = "50_to_100ms"
	BucketOver100ms = "over_100ms"
)

func bucketFor(rttMs uint32) string {
	switch {
	case rttMs < 20:
		return BucketUnder20ms
	case rttMs < 50:
		return Bucket20To50ms
	case rttMs < 100:
		return Bucket50To100ms
	default:
		return BucketOver100ms
	}
}

// bucketRow is one (provider, region, bucket)'s running count.
//
// **No node or account identity column, anywhere in this table.** §4b's own
// ADR text calls for the aggregate to discard the reporting node's identity;
// this makes that true by schema rather than by convention — there is no
// column to retain even if a future change wanted to query by reporter, and
// nothing here can be joined back to a node or an account.
type bucketRow struct {
	Provider string `gorm:"primaryKey;size:32"`
	Region   string `gorm:"primaryKey;size:64"`
	Bucket   string `gorm:"primaryKey;size:16"`
	Count    int64
}

func (bucketRow) TableName() string { return "karst_anchor_rtt_histogram" }

// AnchorHistogramEntry is one (provider, region, bucket)'s count, returned by
// AnchorHistogram — Phase 1 Advisor's future input (ADR-0045 §7).
type AnchorHistogramEntry struct {
	Provider string
	Region   string
	Bucket   string
	Count    int64
}

// RecordAnchorRTT buckets rttMs into one of the four ranges above and
// increments that (provider, region, bucket)'s running count by one.
//
// A plain read-then-write transaction, like Reconcile above, rather than a
// dialect-specific upsert: this table is written at most once per node per
// netmap poll interval, far below any contention a transaction's own
// isolation cannot absorb, and a read-then-write stays identical across every
// SQL backend gorm's store.go supports.
func (s *Store) RecordAnchorRTT(ctx context.Context, provider, region string, rttMs uint32) error {
	bucket := bucketFor(rttMs)
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var row bucketRow
		err := tx.Where("provider = ? AND region = ? AND bucket = ?", provider, region, bucket).Take(&row).Error
		switch {
		case errors.Is(err, gorm.ErrRecordNotFound):
			if err := tx.Create(&bucketRow{Provider: provider, Region: region, Bucket: bucket, Count: 1}).Error; err != nil {
				return fmt.Errorf("anchor rtt histogram: create: %w", err)
			}
			return nil
		case err != nil:
			return fmt.Errorf("anchor rtt histogram: lookup: %w", err)
		default:
			if err := tx.Model(&bucketRow{}).
				Where("provider = ? AND region = ? AND bucket = ?", provider, region, bucket).
				Update("count", row.Count+1).Error; err != nil {
				return fmt.Errorf("anchor rtt histogram: increment: %w", err)
			}
			return nil
		}
	})
}

// AnchorHistogram returns every (provider, region, bucket)'s current count,
// sorted deterministically.
func (s *Store) AnchorHistogram(ctx context.Context) ([]AnchorHistogramEntry, error) {
	var rows []bucketRow
	if err := s.db.WithContext(ctx).Order("provider, region, bucket").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("anchor rtt histogram: list: %w", err)
	}
	entries := make([]AnchorHistogramEntry, 0, len(rows))
	for _, r := range rows {
		entries = append(entries, AnchorHistogramEntry{
			Provider: r.Provider,
			Region:   r.Region,
			Bucket:   r.Bucket,
			Count:    r.Count,
		})
	}
	return entries, nil
}
