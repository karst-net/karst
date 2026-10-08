// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package regionallow_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/karst/regionallow"
)

func TestRecordAnchorRTTCreatesABucketOnFirstReport(t *testing.T) {
	store := newStore(t)
	ctx := context.Background()

	require.NoError(t, store.RecordAnchorRTT(ctx, "aws", "us-east-1", 15))

	got, err := store.AnchorHistogram(ctx)
	require.NoError(t, err)
	require.Equal(t, []regionallow.AnchorHistogramEntry{
		{Provider: "aws", Region: "us-east-1", Bucket: regionallow.BucketUnder20ms, Count: 1},
	}, got)
}

func TestRecordAnchorRTTIncrementsAnExistingBucket(t *testing.T) {
	store := newStore(t)
	ctx := context.Background()

	require.NoError(t, store.RecordAnchorRTT(ctx, "aws", "us-east-1", 15))
	require.NoError(t, store.RecordAnchorRTT(ctx, "aws", "us-east-1", 18))

	got, err := store.AnchorHistogram(ctx)
	require.NoError(t, err)
	require.Equal(t, []regionallow.AnchorHistogramEntry{
		{Provider: "aws", Region: "us-east-1", Bucket: regionallow.BucketUnder20ms, Count: 2},
	}, got)
}

func TestRecordAnchorRTTBucketBoundaries(t *testing.T) {
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
			require.NoError(t, store.RecordAnchorRTT(ctx, "aws", "us-east-1", c.rttMs))

			got, err := store.AnchorHistogram(ctx)
			require.NoError(t, err)
			require.Len(t, got, 1)
			require.Equal(t, c.bucket, got[0].Bucket, "rtt_ms=%d", c.rttMs)
		})
	}
}

func TestRecordAnchorRTTKeepsDistinctRegionsAndProvidersSeparate(t *testing.T) {
	store := newStore(t)
	ctx := context.Background()

	require.NoError(t, store.RecordAnchorRTT(ctx, "aws", "us-east-1", 10))
	require.NoError(t, store.RecordAnchorRTT(ctx, "aws", "us-west-2", 10))
	require.NoError(t, store.RecordAnchorRTT(ctx, "azure", "us-east-1", 10))

	got, err := store.AnchorHistogram(ctx)
	require.NoError(t, err)
	require.Equal(t, []regionallow.AnchorHistogramEntry{
		{Provider: "aws", Region: "us-east-1", Bucket: regionallow.BucketUnder20ms, Count: 1},
		{Provider: "aws", Region: "us-west-2", Bucket: regionallow.BucketUnder20ms, Count: 1},
		{Provider: "azure", Region: "us-east-1", Bucket: regionallow.BucketUnder20ms, Count: 1},
	}, got)
}

func TestAnchorHistogramIsEmptyUntilAReportArrives(t *testing.T) {
	store := newStore(t)
	got, err := store.AnchorHistogram(context.Background())
	require.NoError(t, err)
	require.Empty(t, got)
}
