// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// Package billing contains deterministic billing calculations. It has no
// database, payment-provider, or packet-forwarding side effects.
package billing

import (
	"errors"
	"math/big"
	"strings"
	"time"

	"github.com/netbirdio/netbird/management/internals/karst/relayusage"
	"github.com/netbirdio/netbird/management/internals/karst/usage"
)

var (
	ErrInvalidRateSchedule = errors.New("billing: invalid rate schedule")
)

// DeviceTier uses an inclusive cumulative upper bound. A zero upper bound is
// permitted only on the final tier and means that tier has no device limit.
// MinorPerPeriod is the price for one device for the entire reported period.
// No rates are built in; an account must be assigned an explicit schedule.
type DeviceTier struct {
	UpToDevices    int64
	MinorPerPeriod int64
}

// RateSchedule is an input snapshot; callers retain its version with previews
// and invoices. Relay prices are in integer currency minor units per
// RelayUnitBytes. This calculation layer does not select a currency or rate.
type RateSchedule struct {
	Version            string
	Currency           string
	DeviceTiers        []DeviceTier
	RelayIncludedBytes uint64
	RelayUnitBytes     uint64
	RelayMinorPerUnit  int64
}

// ExactAmount preserves an unrounded rational amount in currency minor units.
// Numerator and Denominator are canonical base-10 integers with a positive
// denominator.
type ExactAmount struct {
	Numerator   string
	Denominator string
}

// Estimate reports exact line items independently. An incomplete component is
// nil, and TotalExact stays nil until both device and relay usage are complete.
// It contains no rounded invoice amount; currency rounding remains an explicit
// product decision.
type Estimate struct {
	ScheduleVersion string
	Currency        string
	DeviceExact     *ExactAmount
	RelayExact      *ExactAmount
	TotalExact      *ExactAmount
	UsageComplete   bool
	Incomplete      []string
}

// Calculate computes graduated device prices and pooled relay overage with
// exact rational arithmetic. It never estimates missing bytes, writes invoice
// state, or contacts a payment provider. The period in both reports must match.
func Calculate(deviceReport usage.DeviceReport, relayReport relayusage.Report, schedule RateSchedule) (Estimate, error) {
	result := Estimate{
		ScheduleVersion: schedule.Version,
		Currency:        schedule.Currency,
		Incomplete:      []string{},
	}
	if err := validateRateSchedule(schedule); err != nil {
		return Estimate{}, err
	}
	var deviceAmount, relayAmount *big.Rat
	if validDeviceReport(deviceReport) {
		deviceExact, err := deviceCharge(deviceReport, schedule.DeviceTiers)
		if err != nil {
			return Estimate{}, err
		}
		deviceAmount = deviceExact
		amount := exactAmount(deviceExact)
		result.DeviceExact = &amount
	} else {
		result.Incomplete = append(result.Incomplete, "device_usage")
	}
	if validRelayReport(relayReport, deviceReport.Start, deviceReport.End) {
		bytes, ok := new(big.Int).SetString(relayReport.ReportedBytes, 10)
		if !ok || bytes.Sign() < 0 || bytes.String() != relayReport.ReportedBytes {
			return Estimate{}, relayusage.ErrReportData
		}
		relayExact := relayCharge(bytes, schedule)
		relayAmount = relayExact
		amount := exactAmount(relayExact)
		result.RelayExact = &amount
	} else {
		result.Incomplete = append(result.Incomplete, "relay_usage")
	}
	if len(result.Incomplete) != 0 {
		return result, nil
	}
	total := exactAmount(new(big.Rat).Add(deviceAmount, relayAmount))
	result.TotalExact = &total
	result.UsageComplete = true
	return result, nil
}

func validateRateSchedule(schedule RateSchedule) error {
	if !validToken(schedule.Version) || len(schedule.Currency) != 3 || strings.ToUpper(schedule.Currency) != schedule.Currency ||
		schedule.RelayUnitBytes == 0 || schedule.RelayMinorPerUnit < 0 || len(schedule.DeviceTiers) == 0 {
		return ErrInvalidRateSchedule
	}
	for _, r := range schedule.Currency {
		if r < 'A' || r > 'Z' {
			return ErrInvalidRateSchedule
		}
	}
	var previous int64
	for i, tier := range schedule.DeviceTiers {
		if tier.MinorPerPeriod < 0 || (tier.UpToDevices != 0 && tier.UpToDevices <= previous) {
			return ErrInvalidRateSchedule
		}
		if tier.UpToDevices == 0 && i != len(schedule.DeviceTiers)-1 {
			return ErrInvalidRateSchedule
		}
		previous = tier.UpToDevices
	}
	if schedule.DeviceTiers[len(schedule.DeviceTiers)-1].UpToDevices != 0 {
		return ErrInvalidRateSchedule
	}
	return nil
}

func validToken(token string) bool {
	if len(token) == 0 || len(token) > 128 {
		return false
	}
	for _, r := range token {
		if !(r >= 'a' && r <= 'z') && !(r >= 'A' && r <= 'Z') && !(r >= '0' && r <= '9') && r != '-' && r != '_' && r != '.' {
			return false
		}
	}
	return true
}

func validDeviceReport(report usage.DeviceReport) bool {
	if !report.Complete || !validBillingTime(report.Start) || !validBillingTime(report.End) || !validBillingTime(report.AsOf) ||
		!report.Start.Before(report.End) || report.End.After(report.AsOf) || len(report.Segments) == 0 {
		return false
	}
	startUS, endUS := report.Start.UnixMicro(), report.End.UnixMicro()
	cursor := startUS
	for _, segment := range report.Segments {
		left, right := segment.Start.UnixMicro(), segment.End.UnixMicro()
		if segment.Coverage != "complete" || segment.Devices == nil || left != cursor || right <= left || right > endUS || *segment.Devices < 0 {
			return false
		}
		cursor = right
	}
	return cursor == endUS
}

func validRelayReport(report relayusage.Report, start, end time.Time) bool {
	if !report.Complete || !report.HistoryComplete || report.Coverage != "authorized_producers" ||
		report.ExpectedWindows == 0 || report.MissingWindows != 0 || report.UnexpectedWindows != 0 ||
		!validBillingTime(report.Start) || !validBillingTime(report.End) || !validBillingTime(report.AsOf) ||
		!report.Start.Equal(start) || !report.End.Equal(end) || !report.End.After(report.Start) || report.End.After(report.AsOf) {
		return false
	}
	for _, day := range report.Days {
		if day.GapWindows != 0 || day.MissingWindows != 0 || day.UnexpectedWindows != 0 {
			return false
		}
	}
	return true
}

func deviceCharge(report usage.DeviceReport, tiers []DeviceTier) (*big.Rat, error) {
	startUS, endUS := report.Start.UnixMicro(), report.End.UnixMicro()
	periodUS := endUS - startUS
	if periodUS <= 0 {
		return nil, ErrInvalidRateSchedule
	}
	numerator := new(big.Int)
	for _, segment := range report.Segments {
		if err := addDeviceCost(numerator, *segment.Devices, segment.End.UnixMicro()-segment.Start.UnixMicro(), tiers); err != nil {
			return nil, err
		}
	}
	return new(big.Rat).SetFrac(numerator, big.NewInt(periodUS)), nil
}

func addDeviceCost(total *big.Int, devices, durationUS int64, tiers []DeviceTier) error {
	remaining := devices
	previousUpper := int64(0)
	for _, tier := range tiers {
		capacity := remaining
		if tier.UpToDevices != 0 {
			capacity = min(remaining, tier.UpToDevices-previousUpper)
		}
		if capacity < 0 {
			return ErrInvalidRateSchedule
		}
		line := new(big.Int).Mul(big.NewInt(capacity), big.NewInt(tier.MinorPerPeriod))
		line.Mul(line, big.NewInt(durationUS))
		total.Add(total, line)
		remaining -= capacity
		if remaining == 0 {
			return nil
		}
		previousUpper = tier.UpToDevices
	}
	if remaining != 0 {
		return ErrInvalidRateSchedule
	}
	return nil
}

func relayCharge(bytes *big.Int, schedule RateSchedule) *big.Rat {
	overage := new(big.Int).Sub(new(big.Int).Set(bytes), new(big.Int).SetUint64(schedule.RelayIncludedBytes))
	if overage.Sign() < 0 {
		overage.SetInt64(0)
	}
	numerator := new(big.Int).Mul(overage, big.NewInt(schedule.RelayMinorPerUnit))
	return new(big.Rat).SetFrac(numerator, new(big.Int).SetUint64(schedule.RelayUnitBytes))
}

func exactAmount(amount *big.Rat) ExactAmount {
	return ExactAmount{Numerator: amount.Num().String(), Denominator: amount.Denom().String()}
}

func validBillingTime(value time.Time) bool {
	return !value.Before(time.Unix(0, 0)) && value.Year() <= 9999 && value.Nanosecond()%1000 == 0
}
