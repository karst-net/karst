// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package ephemeralanchor_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/karst/ephemeralanchor"
	"github.com/netbirdio/netbird/management/internals/karst/regionallow"
)

func TestRecordEphemeralAnchorRTTCreatesABucketOnFirstReport(t *testing.T) {
	store := newStore(t)
	ctx := context.Background()

	require.NoError(t, store.RecordEphemeralAnchorRTT(ctx, "aws:us-west-2-den-1a", 15))

	got, err := store.EphemeralAnchorHistogram(ctx)
	require.NoError(t, err)
	require.Equal(t, []ephemeralanchor.AnchorHistogramEntry{
		{Label: "aws:us-west-2-den-1a", Bucket: regionallow.BucketUnder20ms, Count: 1},
	}, got)
}

func TestRecordEphemeralAnchorRTTIncrementsAnExistingBucket(t *testing.T) {
	store := newStore(t)
	ctx := context.Background()

	require.NoError(t, store.RecordEphemeralAnchorRTT(ctx, "aws:us-west-2-den-1a", 15))
	require.NoError(t, store.RecordEphemeralAnchorRTT(ctx, "aws:us-west-2-den-1a", 18))

	got, err := store.EphemeralAnchorHistogram(ctx)
	require.NoError(t, err)
	require.Equal(t, []ephemeralanchor.AnchorHistogramEntry{
		{Label: "aws:us-west-2-den-1a", Bucket: regionallow.BucketUnder20ms, Count: 2},
	}, got)
}

// TestRecordEphemeralAnchorRTTReusesRegionallowBucketBoundaries ties this
// package's bucketing to regionallow's own exported boundaries, so a future
// change to one can't silently diverge from the other.
func TestRecordEphemeralAnchorRTTReusesRegionallowBucketBoundaries(t *testing.T) {
	cases := []struct {
		rttMs  uint32
		bucket string
	}{
		{0, regionallow.BucketUnder20ms},
		{19, regionallow.BucketUnder20ms},
		{20, regionallow.Bucket20To50ms},
		{49, regionallow.Bucket20To50ms},
		{50, regionallow.Bucket50To100ms},
		{99, regionallow.Bucket50To100ms},
		{100, regionallow.BucketOver100ms},
		{1_000, regionallow.BucketOver100ms},
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("%dms", c.rttMs), func(t *testing.T) {
			store := newStore(t)
			ctx := context.Background()
			require.NoError(t, store.RecordEphemeralAnchorRTT(ctx, "aws:us-west-2-den-1a", c.rttMs))

			got, err := store.EphemeralAnchorHistogram(ctx)
			require.NoError(t, err)
			require.Len(t, got, 1)
			require.Equal(t, c.bucket, got[0].Bucket, "rtt_ms=%d", c.rttMs)
			require.Equal(t, regionallow.BucketFor(c.rttMs), got[0].Bucket)
		})
	}
}

func TestRecordEphemeralAnchorRTTKeepsDistinctLabelsSeparate(t *testing.T) {
	store := newStore(t)
	ctx := context.Background()

	require.NoError(t, store.RecordEphemeralAnchorRTT(ctx, "aws:us-west-2-den-1a", 10))
	require.NoError(t, store.RecordEphemeralAnchorRTT(ctx, "aws:us-east-1-bos-1a", 10))

	got, err := store.EphemeralAnchorHistogram(ctx)
	require.NoError(t, err)
	require.Equal(t, []ephemeralanchor.AnchorHistogramEntry{
		{Label: "aws:us-east-1-bos-1a", Bucket: regionallow.BucketUnder20ms, Count: 1},
		{Label: "aws:us-west-2-den-1a", Bucket: regionallow.BucketUnder20ms, Count: 1},
	}, got)
}

func TestEphemeralAnchorHistogramIsEmptyUntilAReportArrives(t *testing.T) {
	store := newStore(t)
	got, err := store.EphemeralAnchorHistogram(context.Background())
	require.NoError(t, err)
	require.Empty(t, got)
}
