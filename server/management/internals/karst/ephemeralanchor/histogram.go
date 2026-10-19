// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package ephemeralanchor

import (
	"context"
	"errors"
	"fmt"

	"gorm.io/gorm"

	"github.com/netbirdio/netbird/management/internals/karst/regionallow"
)

// bucketRow is one (label, bucket)'s running count.
//
// **No node or account identity column, anywhere in this table.** The same
// reasoning regionallow's own bucketRow documents for §4b's anchor RTT:
// this makes "no reporting node's identity is retained" true by schema,
// not by convention.
type bucketRow struct {
	Label  string `gorm:"primaryKey;size:128"`
	Bucket string `gorm:"primaryKey;size:16"`
	Count  int64
}

func (bucketRow) TableName() string { return "karst_ephemeral_anchor_rtt_histogram" }

// AnchorHistogramEntry is one (label, bucket)'s count, returned by
// EphemeralAnchorHistogram.
type AnchorHistogramEntry struct {
	Label  string
	Bucket string
	Count  int64
}

// RecordEphemeralAnchorRTT buckets rttMs (reusing regionallow.BucketFor's
// exact boundaries — one set of buckets for every anchor-RTT measurement in
// this codebase, not two conventions) and increments that (label, bucket)'s
// running count by one. Same plain read-then-write transaction shape as
// regionallow.Store.RecordAnchorRTT, for the identical reason: this table is
// written at most once per node per netmap poll interval.
func (s *Store) RecordEphemeralAnchorRTT(ctx context.Context, label string, rttMs uint32) error {
	bucket := regionallow.BucketFor(rttMs)
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var row bucketRow
		err := tx.Where("label = ? AND bucket = ?", label, bucket).Take(&row).Error
		switch {
		case errors.Is(err, gorm.ErrRecordNotFound):
			if err := tx.Create(&bucketRow{Label: label, Bucket: bucket, Count: 1}).Error; err != nil {
				return fmt.Errorf("ephemeral anchor rtt histogram: create: %w", err)
			}
			return nil
		case err != nil:
			return fmt.Errorf("ephemeral anchor rtt histogram: lookup: %w", err)
		default:
			if err := tx.Model(&bucketRow{}).
				Where("label = ? AND bucket = ?", label, bucket).
				Update("count", row.Count+1).Error; err != nil {
				return fmt.Errorf("ephemeral anchor rtt histogram: increment: %w", err)
			}
			return nil
		}
	})
}

// EphemeralAnchorHistogram returns every (label, bucket)'s current count,
// sorted deterministically.
func (s *Store) EphemeralAnchorHistogram(ctx context.Context) ([]AnchorHistogramEntry, error) {
	var rows []bucketRow
	if err := s.db.WithContext(ctx).Order("label, bucket").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("ephemeral anchor rtt histogram: list: %w", err)
	}
	entries := make([]AnchorHistogramEntry, 0, len(rows))
	for _, r := range rows {
		entries = append(entries, AnchorHistogramEntry{Label: r.Label, Bucket: r.Bucket, Count: r.Count})
	}
	return entries, nil
}
