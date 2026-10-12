// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package relayusage

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/karst/usage"
)

func TestCustomerReportShowsReceivedTotalsAndKnownGapsWithoutClaimingCompleteness(t *testing.T) {
	db, store, key, relayID, mapping := ingestionFixture(t)
	ctx := context.Background()
	ingestNow := time.Now().UTC()
	end := ingestNow.Truncate(time.Minute)
	start := end.Add(-10 * time.Minute)
	windowStart := start.Add(time.Minute)
	var history authorizationHistory
	require.NoError(t, db.Take(&history).Error)
	history.StartedAtUS = start.UnixMicro()
	require.NoError(t, db.Save(&history).Error)
	var period producerMappingInterval
	require.NoError(t, db.Take(&period).Error)
	period.StartUS = start.UnixMicro()
	require.NoError(t, db.Save(&period).Error)

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
	require.Equal(t, "authorized_producers", report.Coverage)
	require.True(t, report.HistoryComplete)
	require.False(t, report.Complete)
	require.Equal(t, uint64(10), report.ExpectedWindows)
	require.Equal(t, uint64(8), report.MissingWindows)
	require.Zero(t, report.UnexpectedWindows)
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
	require.Equal(t, uint64(10), report.Days[0].ExpectedWindows)
	require.Equal(t, uint64(8), report.Days[0].MissingWindows)
	require.Equal(t, "1", report.Days[0].MissingSequences)
	require.Equal(t, []string{"clock", "observation_lost"}, report.Days[0].GapReasons)
	require.NotContains(t, report.Limitations, "")
	require.Contains(t, report.Limitations, "Missing sequence counts are relay-level diagnostics across received batches for producers authorized for this account during the requested window. They may span periods with no expected account usage and are not estimates of missing bytes.")

	other, err := store.Report(ctx, "account-2", start, end)
	require.NoError(t, err)
	require.Equal(t, "0", other.ReportedBytes)
	require.Zero(t, other.Days[0].ReportedWindows)
	require.Zero(t, other.ExpectedWindows)
	require.False(t, other.Complete, "no expected producer windows cannot establish zero usage")
	require.Nil(t, other.FirstReceivedWindowStart)
	require.Nil(t, other.LastReceivedAt)

	var totalRows int64
	require.NoError(t, db.Model(&receivedTotal{}).Count(&totalRows).Error)
	require.EqualValues(t, 2, totalRows)
}

func TestCustomerReportSequenceDiagnosticIncludesOtherAccountBatch(t *testing.T) {
	db, store, key, relayID, accountOneMapping := ingestionFixture(t)
	ctx := context.Background()
	ingestNow := time.Now().UTC()
	end := ingestNow.Truncate(time.Minute)
	start := end.Add(-3 * time.Minute)
	var history authorizationHistory
	require.NoError(t, db.Take(&history).Error)
	history.StartedAtUS = start.UnixMicro()
	require.NoError(t, db.Save(&history).Error)
	var accountOnePeriod producerMappingInterval
	require.NoError(t, db.Where("account_id = ?", "account-1").Take(&accountOnePeriod).Error)
	accountOnePeriod.StartUS = start.UnixMicro()
	accountOnePeriod.EndUS = new(int64)
	*accountOnePeriod.EndUS = start.Add(time.Minute).UnixMicro()
	require.NoError(t, db.Save(&accountOnePeriod).Error)
	resumedAccountOnePeriod := accountOnePeriod
	resumedAccountOnePeriod.ID = 0
	resumedAccountOnePeriod.StartUS = start.Add(2 * time.Minute).UnixMicro()
	resumedAccountOnePeriod.EndUS = nil
	require.NoError(t, db.Create(&resumedAccountOnePeriod).Error)

	accountTwoMapping, err := usage.PersistRelayMapping(ctx, db, "deployment-a", "aquifer-c", "account-2")
	require.NoError(t, err)
	require.NoError(t, store.AllowMapping(ctx, relayID, accountTwoMapping.DeploymentID, accountTwoMapping.Version))
	var accountTwoPeriod producerMappingInterval
	require.NoError(t, db.Where("account_id = ?", "account-2").Take(&accountTwoPeriod).Error)
	accountTwoPeriod.StartUS = start.Add(time.Minute).UnixMicro()
	accountTwoPeriod.EndUS = new(int64)
	*accountTwoPeriod.EndUS = start.Add(2 * time.Minute).UnixMicro()
	require.NoError(t, db.Save(&accountTwoPeriod).Error)

	for _, item := range []struct {
		sequence uint64
		mapping  usage.RelayMapping
		bytes    uint64
	}{
		{sequence: 1, mapping: accountOneMapping, bytes: 100},
		{sequence: 2, mapping: accountTwoMapping, bytes: 200},
		{sequence: 3, mapping: accountOneMapping, bytes: 300},
	} {
		windowStart := start.Add(time.Duration(item.sequence-1) * time.Minute)
		body := makeSignedBatch(t, key, [16]byte{7}, item.sequence, mappingPayloadAt(item.mapping, item.bytes, uint64(windowStart.UnixMicro())))
		auth := makeUploadAuth(t, key, relayID, body, ingestNow, [32]byte{byte(item.sequence)})
		_, err := store.Ingest(ctx, "POST", UploadPath, auth, body, ingestNow)
		require.NoError(t, err)
	}

	report, err := store.Report(ctx, "account-1", start, end)
	require.NoError(t, err)
	require.Equal(t, "400", report.ReportedBytes, "the other account's bytes stay outside this account's total")
	require.Equal(t, "0", report.MissingSequences, "sequence 2 exists even though it belongs to another account")
	require.Equal(t, uint64(2), report.Days[0].ExpectedWindows)
	require.Equal(t, uint64(2), report.Days[0].ReportedWindows)
	require.Zero(t, report.MissingWindows)
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

func TestCustomerReportIsCompleteWhenEveryAuthorizedWindowArrivedWithoutGaps(t *testing.T) {
	db, store, key, relayID, mapping := ingestionFixture(t)
	ctx := context.Background()
	ingestNow := time.Now().UTC()
	end := ingestNow.Truncate(time.Minute)
	start := end.Add(-2 * time.Minute)
	var history authorizationHistory
	require.NoError(t, db.Take(&history).Error)
	history.StartedAtUS = start.UnixMicro()
	require.NoError(t, db.Save(&history).Error)
	var period producerMappingInterval
	require.NoError(t, db.Take(&period).Error)
	period.StartUS = start.UnixMicro()
	require.NoError(t, db.Save(&period).Error)
	for sequence := uint64(4); sequence <= 5; sequence++ {
		windowStart := start.Add(time.Duration(sequence-4) * time.Minute)
		body := makeSignedBatch(t, key, [16]byte{2}, sequence, mappingPayloadAt(mapping, 0, uint64(windowStart.UnixMicro())))
		auth := makeUploadAuth(t, key, relayID, body, ingestNow, [32]byte{byte(sequence)})
		_, err := store.Ingest(ctx, "POST", UploadPath, auth, body, ingestNow)
		require.NoError(t, err)
	}

	report, err := store.Report(ctx, "account-1", start, end)
	require.NoError(t, err)
	require.True(t, report.HistoryComplete)
	require.True(t, report.Complete)
	require.Equal(t, uint64(2), report.ExpectedWindows)
	require.Zero(t, report.MissingWindows)
	require.Zero(t, report.UnexpectedWindows)
	require.Equal(t, "0", report.ReportedBytes)
	require.Equal(t, "0", report.MissingSequences)
}

func TestCustomerReportMarksPeriodsBeforeAuthorizationHistoryUnknown(t *testing.T) {
	db, store, _, _, _ := ingestionFixture(t)
	end := time.Now().UTC().Truncate(time.Minute)
	start := end.Add(-5 * time.Minute)
	var history authorizationHistory
	require.NoError(t, db.Take(&history).Error)
	history.StartedAtUS = start.Add(2 * time.Minute).UnixMicro()
	require.NoError(t, db.Save(&history).Error)

	report, err := store.Report(context.Background(), "account-1", start, end)
	require.NoError(t, err)
	require.Equal(t, time.UnixMicro(history.StartedAtUS).UTC(), report.AuthorizationHistoryStart)
	require.False(t, report.HistoryComplete)
	require.False(t, report.Complete)
	require.Contains(t, report.Limitations, "Authorization history begins during the requested period; producer coverage before the history cutover is unknown.")
}

func TestCustomerReportMergesOverlappingMappingPeriodsForOneProducer(t *testing.T) {
	start := time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)
	end := start.Add(2 * time.Minute)
	firstEnd := start.Add(time.Minute).UnixMicro()
	report := Report{Start: start, End: end, HistoryComplete: true}
	periods := []producerMappingInterval{
		{DeploymentID: "deployment", RelayID: "relay", Version: "mapping-a", AccountID: "account", StartUS: start.UnixMicro(), EndUS: &firstEnd},
		{DeploymentID: "deployment", RelayID: "relay", Version: "mapping-b", AccountID: "account", StartUS: start.UnixMicro()},
	}
	require.NoError(t, composeRelayReport(&report, periods, nil, nil, nil))
	require.Equal(t, uint64(2), report.ExpectedWindows)
	require.Equal(t, uint64(2), report.MissingWindows)
	require.Len(t, report.Days, 1)
	require.Equal(t, uint64(2), report.Days[0].ExpectedWindows)
}

func TestCustomerReportCountsSequenceHolesNumerically(t *testing.T) {
	start := time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)
	windowStart := start.UnixMicro()
	report := Report{Start: start, End: start.Add(time.Minute), HistoryComplete: true}
	windows := []reportWindow{
		{DeploymentID: "deployment", RelayID: "relay", Epoch: "epoch", Sequence: "10", StartUS: windowStart},
		{DeploymentID: "deployment", RelayID: "relay", Epoch: "epoch", Sequence: "2", StartUS: windowStart},
		{DeploymentID: "deployment", RelayID: "relay", Epoch: "epoch", Sequence: "11", StartUS: windowStart},
		{DeploymentID: "deployment", RelayID: "relay", Epoch: "epoch", Sequence: "1", StartUS: windowStart},
	}

	sequences := []reportSequence{
		{DeploymentID: "deployment", RelayID: "relay", Epoch: "epoch", Sequence: "1", StartUS: windowStart},
		{DeploymentID: "deployment", RelayID: "relay", Epoch: "epoch", Sequence: "2", StartUS: windowStart},
		{DeploymentID: "deployment", RelayID: "relay", Epoch: "epoch", Sequence: "10", StartUS: windowStart},
		{DeploymentID: "deployment", RelayID: "relay", Epoch: "epoch", Sequence: "11", StartUS: windowStart},
	}
	require.NoError(t, composeRelayReport(&report, nil, windows, sequences, nil))
	require.Equal(t, "7", report.MissingSequences, "sequences 3 through 9 are missing")
	require.Len(t, report.Days, 1)
	require.Equal(t, "7", report.Days[0].MissingSequences)
}

func TestCustomerReportSequenceDiagnosticsIncludeOtherAccountBatches(t *testing.T) {
	start := time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)
	windowStart := start.UnixMicro()
	report := Report{Start: start, End: start.Add(time.Minute), HistoryComplete: true}
	accountWindows := []reportWindow{
		{DeploymentID: "deployment", RelayID: "relay", Epoch: "epoch", Sequence: "1", StartUS: windowStart},
		{DeploymentID: "deployment", RelayID: "relay", Epoch: "epoch", Sequence: "3", StartUS: windowStart},
	}
	allProducerSequences := []reportSequence{
		{DeploymentID: "deployment", RelayID: "relay", Epoch: "epoch", Sequence: "1", StartUS: windowStart},
		{DeploymentID: "deployment", RelayID: "relay", Epoch: "epoch", Sequence: "2", StartUS: windowStart}, // another account's batch
		{DeploymentID: "deployment", RelayID: "relay", Epoch: "epoch", Sequence: "3", StartUS: windowStart},
	}

	require.NoError(t, composeRelayReport(&report, nil, accountWindows, allProducerSequences, nil))
	require.Equal(t, "0", report.MissingSequences, "a valid batch for another account is still present in the producer sequence")
}
