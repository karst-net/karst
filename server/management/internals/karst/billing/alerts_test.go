// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package billing

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/netbirdio/netbird/management/internals/karst/relayusage"
	"github.com/stretchr/testify/require"
)

func TestEvaluateRelayAlertsIncludesThresholdAndCoverage(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	report := completeRelayReport(start, start.AddDate(0, 1, 0), "9000000000")
	report.AsOf = start.AddDate(0, 0, 15)
	report.End = report.AsOf
	report.Complete = false
	report.MissingWindows = 1

	alerts, err := EvaluateRelayAlerts(report, testSchedule(), nil)
	require.NoError(t, err)
	require.Len(t, alerts, 2)
	require.Equal(t, []uint8{75, 90}, []uint8{alerts[0].Threshold, alerts[1].Threshold})
	require.Equal(t, "7500000000", alerts[0].ThresholdBytes)
	require.Equal(t, "9000000000", alerts[1].ThresholdBytes)
	require.Equal(t, start.AddDate(0, 1, 0), alerts[0].PeriodEnd)
	require.False(t, alerts[0].UsageComplete)
	require.Equal(t, "included_allowance", alerts[0].Target)
}

func TestEvaluateRelayAlertsUsesCappedRelayOverageBudget(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	report := completeRelayReport(start, start.AddDate(0, 1, 0), "18000000000")
	cap := int64(200) // $2.00 of relay overage permits 10 additional decimal GB.

	alerts, err := EvaluateRelayAlerts(report, testSchedule(), &cap)
	require.NoError(t, err)
	var capAlerts []RelayAlertCandidate
	for _, candidate := range alerts {
		if candidate.Target == "spending_cap" {
			capAlerts = append(capAlerts, candidate)
		}
	}
	require.Len(t, capAlerts, 2)
	require.Equal(t, []uint8{75, 90}, []uint8{capAlerts[0].Threshold, capAlerts[1].Threshold})
	require.Equal(t, "15000000000", capAlerts[0].ThresholdBytes)
	require.Equal(t, "18000000000", capAlerts[1].ThresholdBytes)
}

func TestMaxRelayBytesForOverageTruncatesAndAvoidsOverflow(t *testing.T) {
	schedule := testSchedule()
	bytes, err := MaxRelayBytesForOverage(schedule, 1)
	require.NoError(t, err)
	require.Equal(t, "10050000000", bytes.String())

	bytes, err = MaxRelayBytesForOverage(schedule, int64(^uint64(0)>>1))
	require.NoError(t, err)
	require.True(t, bytes.IsUint64() == false, "large cap byte budget should remain exact beyond uint64")

	_, err = MaxRelayBytesForOverage(schedule, -1)
	require.ErrorIs(t, err, ErrInvalidRateSchedule)
}

func TestEvaluateRelayAlertsRejectsInvalidPeriodUsageAndCap(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	report := completeRelayReport(start, start.AddDate(0, 1, 0), "0")
	report.Start = start.Add(time.Hour)
	_, err := EvaluateRelayAlerts(report, testSchedule(), nil)
	require.ErrorIs(t, err, ErrInvalidPeriod)

	report = completeRelayReport(start, start.AddDate(0, 1, 0), "01")
	_, err = EvaluateRelayAlerts(report, testSchedule(), nil)
	require.ErrorIs(t, err, relayusage.ErrReportData)

	report = completeRelayReport(start, start.AddDate(0, 1, 0), "0")
	report.End = start.AddDate(0, 1, 1)
	report.AsOf = report.End
	_, err = EvaluateRelayAlerts(report, testSchedule(), nil)
	require.ErrorIs(t, err, ErrInvalidPeriod)

	report = completeRelayReport(start, start.AddDate(0, 1, 0), "0")
	negativeCap := int64(-1)
	_, err = EvaluateRelayAlerts(report, testSchedule(), &negativeCap)
	require.ErrorIs(t, err, ErrInvalidRateSchedule)

	noRelayPrice := testSchedule()
	noRelayPrice.RelayMinorPerUnit = 0
	cap := int64(1)
	_, err = EvaluateRelayAlerts(report, noRelayPrice, &cap)
	require.ErrorIs(t, err, ErrInvalidRateSchedule)
}

func TestRelayAlertStoreIsAccountScopedAndDeduplicatesThresholds(t *testing.T) {
	store := testBillingStore(t)
	ctx := WithAccount(context.Background(), "org-alert")
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	end := start.AddDate(0, 1, 0)
	schedule := testSchedule()
	require.NoError(t, store.PutSchedule(ctx, schedule))
	require.NoError(t, store.AssignSchedule(ctx, start, end, schedule.Version))
	report := completeRelayReport(start, end, "9000000000")
	alerts, err := EvaluateRelayAlerts(report, schedule, nil)
	require.NoError(t, err)
	require.NoError(t, store.RecordRelayAlerts(ctx, alerts))
	require.NoError(t, store.RecordRelayAlerts(ctx, alerts))

	stored, err := store.RelayAlerts(ctx, start, end)
	require.NoError(t, err)
	require.Equal(t, alerts, stored)
	other, err := store.RelayAlerts(WithAccount(context.Background(), "org-other"), start, end)
	require.NoError(t, err)
	require.Empty(t, other)
	if err := store.RecordRelayAlerts(context.Background(), alerts); !errors.Is(err, ErrNoBillingAccount) {
		t.Fatalf("record without account scope = %v, want ErrNoBillingAccount", err)
	}
}

func TestRelayAlertStoreRequiresAssignedSchedule(t *testing.T) {
	store := testBillingStore(t)
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	end := start.AddDate(0, 1, 0)
	schedule := testSchedule()
	report := completeRelayReport(start, end, "9000000000")
	alerts, err := EvaluateRelayAlerts(report, schedule, nil)
	require.NoError(t, err)
	err = store.RecordRelayAlerts(WithAccount(context.Background(), "org-unassigned"), alerts)
	require.ErrorIs(t, err, ErrScheduleUnassigned)
}
