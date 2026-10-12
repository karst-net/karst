// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package billing

import (
	"strconv"
	"testing"
	"time"

	"github.com/netbirdio/netbird/management/internals/karst/relayusage"
	"github.com/netbirdio/netbird/management/internals/karst/usage"
	"github.com/stretchr/testify/require"
)

func TestPilotRateScheduleMatchesApprovedGraduatedPrices(t *testing.T) {
	schedule := PilotRateSchedule()
	require.Equal(t, "pilot-2026-10-12-v1", schedule.Version)
	require.Equal(t, "USD", schedule.Currency)
	require.Equal(t, []DeviceTier{
		{UpToDevices: 10, MinorPerPeriod: 250},
		{UpToDevices: 50, MinorPerPeriod: 150},
		{MinorPerPeriod: 75},
	}, schedule.DeviceTiers)
	require.Equal(t, uint64(10_000_000_000), schedule.RelayIncludedBytes)
	require.Equal(t, uint64(1_000_000_000), schedule.RelayUnitBytes)
	require.Equal(t, int64(20), schedule.RelayMinorPerUnit)
}

func TestPilotRateScheduleProducesApprovedSensitivityExamples(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	end := start.AddDate(0, 1, 0)
	schedule := PilotRateSchedule()
	for _, tc := range []struct {
		devices, relayGB int64
		deviceMinor      string
		relayMinor       string
		totalMinor       string
	}{
		{10, 10, "2500", "0", "2500"},
		{50, 100, "8500", "1800", "10300"},
		{250, 1000, "23500", "19800", "43300"},
	} {
		deviceCount := tc.devices
		deviceReport := usage.DeviceReport{
			Start: start, End: end, AsOf: end, Complete: true,
			Segments: []usage.DeviceSegment{{
				Start: start, End: end, Coverage: "complete", Devices: &deviceCount,
			}},
		}
		relayReport := relayusage.Report{
			Start: start, End: end, AsOf: end, Coverage: "authorized_producers",
			HistoryComplete: true, Complete: true, ExpectedWindows: 1,
			ReportedBytes: strconv.FormatInt(tc.relayGB*1_000_000_000, 10),
		}
		estimate, err := Calculate(deviceReport, relayReport, schedule)
		require.NoError(t, err)
		require.True(t, estimate.UsageComplete)
		require.Equal(t, tc.deviceMinor, estimate.DeviceExact.Numerator)
		require.Equal(t, tc.relayMinor, estimate.RelayExact.Numerator)
		require.Equal(t, "1", estimate.TotalExact.Denominator)
		require.Equal(t, tc.totalMinor, estimate.TotalExact.Numerator)
	}
}
