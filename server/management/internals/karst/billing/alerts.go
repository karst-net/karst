// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package billing

import (
	"errors"
	"math/big"
	"time"

	"github.com/netbirdio/netbird/management/internals/karst/relayusage"
)

// RelayAlertCandidate is a deterministic threshold crossing. It is not sent or
// persisted; callers must deduplicate on account, period, schedule, target,
// and threshold before delivering it to billing administrators.
type RelayAlertCandidate struct {
	PeriodStart     time.Time `json:"period_start"`
	PeriodEnd       time.Time `json:"period_end"`
	ScheduleVersion string    `json:"schedule_version"`
	Target          string    `json:"target"`
	Threshold       uint8     `json:"threshold_percent"`
	ReportedBytes   string    `json:"reported_bytes"`
	ThresholdBytes  string    `json:"threshold_bytes"`
	AsOf            time.Time `json:"as_of"`
	UsageComplete   bool      `json:"usage_complete"`
}

// EvaluateRelayAlerts finds approved 75%, 90%, and 100% threshold crossings
// for the included relay allowance and optional overage cap. It may return
// lower-bound candidates for incomplete reports; UsageComplete makes that
// limitation explicit for the eventual notification. No alert channel,
// deduplication state, or customer preference is assumed here.
func EvaluateRelayAlerts(report relayusage.Report, schedule RateSchedule, capOverageMinor *int64) ([]RelayAlertCandidate, error) {
	if err := validateRateSchedule(schedule); err != nil {
		return nil, err
	}
	start, end := report.Start.UTC(), report.End.UTC()
	if !validBillingTime(start) || !validBillingTime(end) || !validBillingTime(report.AsOf) ||
		start.Day() != 1 || start.Hour() != 0 || start.Minute() != 0 || start.Second() != 0 || start.Nanosecond() != 0 ||
		!start.Before(end) || end.After(report.AsOf) {
		return nil, ErrInvalidPeriod
	}
	periodEnd := start.AddDate(0, 1, 0)
	if periodEnd.Year() > 9999 || end.After(periodEnd) {
		return nil, ErrInvalidPeriod
	}
	bytes, ok := new(big.Int).SetString(report.ReportedBytes, 10)
	if !ok || bytes.Sign() < 0 || bytes.String() != report.ReportedBytes {
		return nil, relayusage.ErrReportData
	}
	if capOverageMinor != nil && (*capOverageMinor < 0 || schedule.RelayMinorPerUnit == 0) {
		return nil, ErrInvalidRateSchedule
	}
	complete := relayReportComplete(report)
	candidates := make([]RelayAlertCandidate, 0, 6)
	appendCrossings := func(target string, limit *big.Int) {
		if limit.Sign() == 0 {
			return
		}
		for _, pct := range [...]uint8{75, 90, 100} {
			threshold := new(big.Int).Mul(new(big.Int).Set(limit), big.NewInt(int64(pct)))
			threshold.Add(threshold, big.NewInt(99))
			threshold.Quo(threshold, big.NewInt(100))
			if bytes.Cmp(threshold) < 0 {
				continue
			}
			candidates = append(candidates, RelayAlertCandidate{
				PeriodStart: start, PeriodEnd: periodEnd, ScheduleVersion: schedule.Version,
				Target: target, Threshold: pct, ReportedBytes: bytes.String(),
				ThresholdBytes: threshold.String(), AsOf: report.AsOf.UTC(), UsageComplete: complete,
			})
		}
	}
	appendCrossings("included_allowance", new(big.Int).SetUint64(schedule.RelayIncludedBytes))
	if capOverageMinor != nil {
		overageBytes := new(big.Int).Mul(big.NewInt(*capOverageMinor), new(big.Int).SetUint64(schedule.RelayUnitBytes))
		overageBytes.Quo(overageBytes, big.NewInt(schedule.RelayMinorPerUnit))
		capBytes := new(big.Int).Add(new(big.Int).SetUint64(schedule.RelayIncludedBytes), overageBytes)
		appendCrossings("spending_cap", capBytes)
	}
	return candidates, nil
}

func relayReportComplete(report relayusage.Report) bool {
	if !report.Complete || !report.HistoryComplete || report.Coverage != "authorized_producers" || report.ExpectedWindows == 0 ||
		report.MissingWindows != 0 || report.UnexpectedWindows != 0 {
		return false
	}
	for _, day := range report.Days {
		if day.GapWindows != 0 || day.MissingWindows != 0 || day.UnexpectedWindows != 0 {
			return false
		}
	}
	return true
}

func validateRelayAlertCandidate(candidate RelayAlertCandidate) error {
	startUS, endUS, err := billingPeriodMicros(candidate.PeriodStart, candidate.PeriodEnd)
	if err != nil || !isBillingCalendarMonth(startUS, endUS) || !validToken(candidate.ScheduleVersion) ||
		(candidate.Target != "included_allowance" && candidate.Target != "spending_cap") ||
		(candidate.Threshold != 75 && candidate.Threshold != 90 && candidate.Threshold != 100) ||
		!validBillingTime(candidate.AsOf) || candidate.AsOf.Before(candidate.PeriodStart) || candidate.AsOf.After(candidate.PeriodEnd) {
		return errInvalidRelayAlert
	}
	reported, ok := new(big.Int).SetString(candidate.ReportedBytes, 10)
	if !ok || reported.Sign() < 0 || reported.String() != candidate.ReportedBytes {
		return errInvalidRelayAlert
	}
	threshold, ok := new(big.Int).SetString(candidate.ThresholdBytes, 10)
	if !ok || threshold.Sign() <= 0 || threshold.String() != candidate.ThresholdBytes || reported.Cmp(threshold) < 0 {
		return errInvalidRelayAlert
	}
	return nil
}

func isBillingCalendarMonth(startUS, endUS int64) bool {
	start := time.UnixMicro(startUS).UTC()
	end := time.UnixMicro(endUS).UTC()
	if start.Day() != 1 || start.Hour() != 0 || start.Minute() != 0 || start.Second() != 0 || start.Nanosecond() != 0 {
		return false
	}
	return end.Equal(start.AddDate(0, 1, 0))
}

var errInvalidRelayAlert = errors.New("billing: invalid relay alert candidate")
