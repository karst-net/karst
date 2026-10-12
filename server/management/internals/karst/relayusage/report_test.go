// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package relayusage

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCustomerReportShowsReceivedTotalsAndKnownGapsWithoutClaimingCompleteness(t *testing.T) {
	db, store, key, relayID, mapping := ingestionFixture(t)
	ctx := context.Background()
	ingestNow := time.Now().UTC()
	end := ingestNow.Truncate(time.Minute)
	start := end.Add(-10 * time.Minute)
	windowStart := start.Add(time.Minute)

	first := makeSignedBatch(t, key, [16]byte{1}, 0, mappingPayloadAt(mapping, 123, uint64(windowStart.UnixMicro())))
	firstAuth := makeUploadAuth(t, key, relayID, first, ingestNow, [32]byte{1})
	_, err := store.Ingest(ctx, "POST", UploadPath, firstAuth, first, ingestNow)
	require.NoError(t, err)

	secondStart := windowStart.Add(2 * time.Minute)
	secondPayload := mappingPayloadAt(mapping, 456, uint64(secondStart.UnixMicro()))
	secondPayload[len(secondPayload)-1] = GapClock | GapObservationLost
	second := makeSignedBatch(t, key, [16]byte{1}, 2, secondPayload)
	secondAuth := makeUploadAuth(t, key, relayID, second, ingestNow, [32]byte{2})
	_, err = store.Ingest(ctx, "POST", UploadPath, secondAuth, second, ingestNow)
	require.NoError(t, err)

	report, err := store.Report(ctx, "account-1", start, end)
	require.NoError(t, err)
	require.Equal(t, "received_only", report.Coverage)
	require.False(t, report.Complete)
	require.Equal(t, "579", report.ReportedBytes)
	require.Equal(t, "1", report.MissingSequences)
	require.NotNil(t, report.FirstReceivedWindowStart)
	require.Equal(t, windowStart, *report.FirstReceivedWindowStart)
	require.NotNil(t, report.LastReceivedAt)
	require.Equal(t, ingestNow.Truncate(time.Microsecond), *report.LastReceivedAt)
	require.Len(t, report.Days, 1)
	require.Equal(t, "579", report.Days[0].ReportedBytes)
	require.Equal(t, uint64(2), report.Days[0].ReportedWindows)
	require.Equal(t, uint64(1), report.Days[0].GapWindows)
	require.Equal(t, "1", report.Days[0].MissingSequences)
	require.Equal(t, []string{"clock", "observation_lost"}, report.Days[0].GapReasons)
	require.NotContains(t, report.Limitations, "")

	other, err := store.Report(ctx, "account-2", start, end)
	require.NoError(t, err)
	require.Equal(t, "0", other.ReportedBytes)
	require.Zero(t, other.Days[0].ReportedWindows)
	require.Nil(t, other.FirstReceivedWindowStart)
	require.Nil(t, other.LastReceivedAt)

	var totalRows int64
	require.NoError(t, db.Model(&receivedTotal{}).Count(&totalRows).Error)
	require.EqualValues(t, 2, totalRows)
}

func TestCustomerReportRejectsUnalignedFutureAndOversizedWindows(t *testing.T) {
	_, store, _, _, _ := ingestionFixture(t)
	start := time.Now().UTC().Truncate(time.Minute).Add(-2 * time.Minute)
	for _, bounds := range [][2]time.Time{
		{start, start.Add(time.Minute + time.Second)},
		{start, time.Now().UTC().Add(time.Hour).Truncate(time.Minute)},
		{start, start.Add(MaxReportWindow + time.Minute)},
	} {
		if _, err := store.Report(context.Background(), "account-1", bounds[0], bounds[1]); err != ErrInvalidReport {
			t.Fatalf("report error for %v..%v = %v, want %v", bounds[0], bounds[1], err, ErrInvalidReport)
		}
	}
}
