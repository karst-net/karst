// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package billing

import (
	"context"
	"testing"
	"time"

	"github.com/netbirdio/netbird/management/internals/karst/relayusage"
	"github.com/stretchr/testify/require"
)

type relayAlertReportFunc func(context.Context, string, time.Time, time.Time) (report relayusage.Report, err error)

func (f relayAlertReportFunc) Report(ctx context.Context, account string, start, end time.Time) (relayusage.Report, error) {
	return f(ctx, account, start, end)
}

func TestEvaluateCurrentRelayAlertsOnlyProcessesAssignedAccounts(t *testing.T) {
	store := testBillingStore(t)
	ctx := context.Background()
	now := time.Date(2026, 10, 12, 12, 30, 0, 0, time.UTC)
	start := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	periodEnd := start.AddDate(0, 1, 0)
	schedule := testSchedule()
	accountCtx := WithAccount(ctx, "scheduled-account")
	require.NoError(t, store.PutSchedule(accountCtx, schedule))
	require.NoError(t, store.AssignSchedule(accountCtx, start, periodEnd, schedule.Version))

	reports := 0
	reporter := relayAlertReportFunc(func(_ context.Context, account string, reportStart, reportEnd time.Time) (relayusage.Report, error) {
		reports++
		require.Equal(t, "scheduled-account", account)
		require.Equal(t, start, reportStart)
		require.Equal(t, now.Truncate(time.Minute), reportEnd)
		report := completeRelayReport(start, reportEnd, "9000000000")
		return report, nil
	})
	require.NoError(t, store.EvaluateCurrentRelayAlerts(ctx, reporter, now))
	require.Equal(t, 1, reports)

	alerts, err := store.RelayAlerts(accountCtx, start, periodEnd)
	require.NoError(t, err)
	require.Len(t, alerts, 2)

	other, err := store.RelayAlerts(WithAccount(ctx, "unconfigured-account"), start, periodEnd)
	require.NoError(t, err)
	require.Empty(t, other)
}

func TestEvaluateCurrentRelayAlertsDoesNoWorkWithoutAssignments(t *testing.T) {
	store := testBillingStore(t)
	now := time.Date(2026, 10, 12, 12, 30, 0, 0, time.UTC)
	reports := 0
	reporter := relayAlertReportFunc(func(context.Context, string, time.Time, time.Time) (relayusage.Report, error) {
		reports++
		return relayusage.Report{}, nil
	})
	require.NoError(t, store.EvaluateCurrentRelayAlerts(context.Background(), reporter, now))
	require.Zero(t, reports)
}
