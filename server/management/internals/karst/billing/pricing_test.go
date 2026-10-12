// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package billing

import (
	"testing"
	"time"

	"github.com/netbirdio/netbird/management/internals/karst/relayusage"
	"github.com/netbirdio/netbird/management/internals/karst/usage"
	"github.com/stretchr/testify/require"
)

func TestCalculateUsesGraduatedDeviceTiers(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(time.Hour)
	devices := completeDeviceReport(start, end, deviceSegment(start, end, 4))
	relays := completeRelayReport(start, end, "0")
	schedule := RateSchedule{
		Version: "v7", Currency: "USD",
		DeviceTiers: []DeviceTier{
			{UpToDevices: 2, MinorPerPeriod: 300},
			{UpToDevices: 4, MinorPerPeriod: 150},
			{MinorPerPeriod: 50},
		},
		RelayUnitBytes: 1_000_000_000,
	}

	estimate, err := Calculate(devices, relays, schedule)
	require.NoError(t, err)
	require.True(t, estimate.UsageComplete)
	require.Empty(t, estimate.Incomplete)
	require.Equal(t, "v7", estimate.ScheduleVersion)
	require.Equal(t, "USD", estimate.Currency)
	require.Equal(t, &ExactAmount{Numerator: "900", Denominator: "1"}, estimate.DeviceExact)
	require.Equal(t, &ExactAmount{Numerator: "0", Denominator: "1"}, estimate.RelayExact)
	require.Equal(t, &ExactAmount{Numerator: "900", Denominator: "1"}, estimate.TotalExact)
}

func TestCalculateProratesTiersAcrossActualReportDuration(t *testing.T) {
	start := time.UnixMicro(100)
	middle := start.Add(10 * time.Minute)
	end := start.Add(30 * time.Minute)
	devices := completeDeviceReport(start, end,
		deviceSegment(start, middle, 2),
		deviceSegment(middle, end, 1),
	)
	relays := completeRelayReport(start, end, "0")
	schedule := RateSchedule{
		Version: "actual-period", Currency: "USD",
		DeviceTiers: []DeviceTier{
			{UpToDevices: 1, MinorPerPeriod: 1200},
			{MinorPerPeriod: 600},
		},
		RelayUnitBytes: 1,
	}

	estimate, err := Calculate(devices, relays, schedule)
	require.NoError(t, err)
	// First third: two devices cost 1,800/3 = 600 minor units.
	// Remaining two thirds: one device costs 1,200*2/3 = 800.
	require.Equal(t, &ExactAmount{Numerator: "1400", Denominator: "1"}, estimate.DeviceExact)
	require.Equal(t, &ExactAmount{Numerator: "1400", Denominator: "1"}, estimate.TotalExact)
}

func TestCalculateRetainsTheExactCombinedAmount(t *testing.T) {
	start := time.UnixMicro(0)
	first := start.Add(time.Microsecond)
	end := start.Add(3 * time.Microsecond)
	devices := completeDeviceReport(start, end,
		deviceSegment(start, first, 1),
		deviceSegment(first, end, 0),
	)
	relays := completeRelayReport(start, end, "2")
	schedule := RateSchedule{
		Version: "fractional", Currency: "USD",
		DeviceTiers:    []DeviceTier{{MinorPerPeriod: 1}},
		RelayUnitBytes: 3, RelayMinorPerUnit: 1,
	}

	estimate, err := Calculate(devices, relays, schedule)
	require.NoError(t, err)
	require.Equal(t, &ExactAmount{Numerator: "1", Denominator: "3"}, estimate.DeviceExact)
	require.Equal(t, &ExactAmount{Numerator: "2", Denominator: "3"}, estimate.RelayExact)
	require.Equal(t, &ExactAmount{Numerator: "1", Denominator: "1"}, estimate.TotalExact)
}

func TestCalculateAppliesOrganizationRelayAllowanceToDecimalBytes(t *testing.T) {
	start := time.UnixMicro(0)
	end := start.Add(time.Second)
	devices := completeDeviceReport(start, end, deviceSegment(start, end, 0))
	schedule := RateSchedule{
		Version: "relay-v1", Currency: "USD",
		DeviceTiers:        []DeviceTier{{MinorPerPeriod: 0}},
		RelayIncludedBytes: 10, RelayUnitBytes: 10, RelayMinorPerUnit: 25,
	}

	within, err := Calculate(devices, completeRelayReport(start, end, "10"), schedule)
	require.NoError(t, err)
	require.Equal(t, &ExactAmount{Numerator: "0", Denominator: "1"}, within.TotalExact)

	overage, err := Calculate(devices, completeRelayReport(start, end, "14"), schedule)
	require.NoError(t, err)
	require.Equal(t, &ExactAmount{Numerator: "10", Denominator: "1"}, overage.RelayExact)
	require.Equal(t, &ExactAmount{Numerator: "10", Denominator: "1"}, overage.TotalExact)
}

func TestCalculateKeepsPartialComponentsOutOfFinalTotal(t *testing.T) {
	start := time.UnixMicro(0)
	end := start.Add(time.Second)
	devices := completeDeviceReport(start, end, deviceSegment(start, end, 3))
	relays := completeRelayReport(start, end, "100")
	relays.Complete = false
	schedule := RateSchedule{
		Version: "v1", Currency: "USD",
		DeviceTiers: []DeviceTier{{MinorPerPeriod: 100}}, RelayUnitBytes: 1,
	}

	estimate, err := Calculate(devices, relays, schedule)
	require.NoError(t, err)
	require.False(t, estimate.UsageComplete)
	require.Equal(t, []string{"relay_usage"}, estimate.Incomplete)
	require.NotNil(t, estimate.DeviceExact)
	require.Nil(t, estimate.RelayExact)
	require.Nil(t, estimate.TotalExact)
}

func TestCalculateRejectsRelayReportsWithDailyGapEvidence(t *testing.T) {
	start := time.UnixMicro(0)
	end := start.Add(time.Second)
	devices := completeDeviceReport(start, end, deviceSegment(start, end, 1))
	relays := completeRelayReport(start, end, "100")
	relays.Days = []relayusage.ReportDay{{GapWindows: 1}}
	schedule := RateSchedule{
		Version: "v1", Currency: "USD",
		DeviceTiers: []DeviceTier{{MinorPerPeriod: 100}}, RelayUnitBytes: 1,
	}

	estimate, err := Calculate(devices, relays, schedule)
	require.NoError(t, err)
	require.False(t, estimate.UsageComplete)
	require.Equal(t, []string{"relay_usage"}, estimate.Incomplete)
	require.Nil(t, estimate.TotalExact)
}

func TestCalculateRejectsNoncanonicalCompleteRelayBytes(t *testing.T) {
	start := time.UnixMicro(0)
	end := start.Add(time.Second)
	devices := completeDeviceReport(start, end, deviceSegment(start, end, 0))
	relays := completeRelayReport(start, end, "01")
	schedule := RateSchedule{
		Version: "v1", Currency: "USD",
		DeviceTiers: []DeviceTier{{MinorPerPeriod: 0}}, RelayUnitBytes: 1,
	}
	_, err := Calculate(devices, relays, schedule)
	require.ErrorIs(t, err, relayusage.ErrReportData)
}

func TestCalculateRequiresMatchingCompleteReportPeriods(t *testing.T) {
	start := time.UnixMicro(0)
	end := start.Add(time.Second)
	devices := completeDeviceReport(start, end, deviceSegment(start, end, 1))
	relays := completeRelayReport(start.Add(time.Microsecond), end, "0")
	schedule := RateSchedule{
		Version: "v1", Currency: "USD",
		DeviceTiers: []DeviceTier{{MinorPerPeriod: 100}}, RelayUnitBytes: 1,
	}

	estimate, err := Calculate(devices, relays, schedule)
	require.NoError(t, err)
	require.False(t, estimate.UsageComplete)
	require.Equal(t, []string{"relay_usage"}, estimate.Incomplete)
	require.Nil(t, estimate.TotalExact)

	subMicroStart := start.Add(500 * time.Nanosecond)
	invalidBoundary := deviceSegment(start, end, 1)
	invalidBoundary.Start = subMicroStart
	devices = completeDeviceReport(start, end, invalidBoundary)
	estimate, err = Calculate(devices, completeRelayReport(start, end, "0"), schedule)
	require.NoError(t, err)
	require.False(t, estimate.UsageComplete)
	require.Equal(t, []string{"device_usage"}, estimate.Incomplete)
	require.Nil(t, estimate.TotalExact)
}

func TestCalculateRejectsMalformedSchedules(t *testing.T) {
	start := time.UnixMicro(0)
	end := start.Add(time.Second)
	devices := completeDeviceReport(start, end, deviceSegment(start, end, 1))
	relays := completeRelayReport(start, end, "0")
	valid := RateSchedule{
		Version: "v1", Currency: "USD",
		DeviceTiers: []DeviceTier{{MinorPerPeriod: 1}}, RelayUnitBytes: 1,
	}

	invalid := valid
	invalid.Currency = "usd"
	_, err := Calculate(devices, relays, invalid)
	require.ErrorIs(t, err, ErrInvalidRateSchedule)
	invalid = valid
	invalid.DeviceTiers = []DeviceTier{{UpToDevices: 1, MinorPerPeriod: 1}}
	_, err = Calculate(devices, relays, invalid)
	require.ErrorIs(t, err, ErrInvalidRateSchedule)
}

func TestCalculateHandlesRelayBytesAboveUint64(t *testing.T) {
	start := time.UnixMicro(0)
	end := start.Add(time.Second)
	devices := completeDeviceReport(start, end, deviceSegment(start, end, 0))
	relays := completeRelayReport(start, end, "100000000000000000000")
	schedule := RateSchedule{
		Version: "large", Currency: "USD",
		DeviceTiers:    []DeviceTier{{MinorPerPeriod: 0}},
		RelayUnitBytes: 1_000_000_000, RelayMinorPerUnit: 20,
	}

	estimate, err := Calculate(devices, relays, schedule)
	require.NoError(t, err)
	require.Equal(t, &ExactAmount{Numerator: "2000000000000", Denominator: "1"}, estimate.RelayExact)
	require.Equal(t, &ExactAmount{Numerator: "2000000000000", Denominator: "1"}, estimate.TotalExact)
}

func completeDeviceReport(start, end time.Time, segments ...usage.DeviceSegment) usage.DeviceReport {
	return usage.DeviceReport{Start: start, End: end, AsOf: end, Complete: true, Segments: segments}
}

func deviceSegment(start, end time.Time, devices int64) usage.DeviceSegment {
	return usage.DeviceSegment{Start: start, End: end, Coverage: "complete", Devices: &devices}
}

func completeRelayReport(start, end time.Time, bytes string) relayusage.Report {
	return relayusage.Report{
		Start: start, End: end, AsOf: end,
		Coverage: "authorized_producers", HistoryComplete: true, Complete: true,
		ExpectedWindows: 1, ReportedBytes: bytes,
	}
}
