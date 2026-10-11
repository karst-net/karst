// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package usage

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"math/big"
	"sort"
	"time"

	"gorm.io/gorm"
)

const (
	MaxReportWindow   = 93 * 24 * time.Hour
	MaxReportSegments = 10000
)

var ErrReportLimit = errors.New("usage: report is too large; request a shorter window")

// DeviceSegment covers a half-open interval. Devices is deliberately absent
// outside complete coverage: a stored count there is not reliable usage.
type DeviceSegment struct {
	Start    time.Time `json:"start"`
	End      time.Time `json:"end"`
	Coverage string    `json:"coverage"`
	Devices  *int64    `json:"devices"`
}

// DeviceReport includes only fully covered intervals in DeviceMicroseconds.
// The decimal string avoids loss of precision in JavaScript and integer
// overflow for large fleets. It is a usage unit, never a currency amount.
type DeviceReport struct {
	Start              time.Time       `json:"start"`
	End                time.Time       `json:"end"`
	AsOf               time.Time       `json:"as_of"`
	Complete           bool            `json:"complete"`
	DeviceMicroseconds string          `json:"device_microseconds"`
	Segments           []DeviceSegment `json:"segments"`
}

// Reporter reads a consistent ledger/coverage snapshot. Authorization belongs
// to the caller; accountID must come from its authenticated account scope.
type Reporter struct {
	DB  *gorm.DB
	Now func() time.Time
}

func (r Reporter) Devices(ctx context.Context, accountID string, start, end time.Time) (DeviceReport, error) {
	var report DeviceReport
	if !validID(accountID) || !validTime(start) || !validTime(end) || !start.Before(end) || end.Sub(start) > MaxReportWindow {
		return report, ErrInvalid
	}
	err := r.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		now := time.Now
		if r.Now != nil {
			now = r.Now
		}
		asOf := now().UTC().Truncate(time.Microsecond)
		if end.After(asOf) {
			return ErrInvalid
		}
		var periods []Period
		if err := tx.Where("account_id = ? AND start_us < ? AND (end_us IS NULL OR end_us > ?)", accountID, end.UnixMicro(), start.UnixMicro()).
			Order("start_us, id").Limit(MaxReportSegments + 1).Find(&periods).Error; err != nil {
			return err
		}
		if len(periods) > MaxReportSegments {
			return ErrReportLimit
		}
		// Aggregate history in SQL; transfer only changes inside the window.
		// Both queries share this repeatable-read snapshot with coverage.
		var opening int64
		if err := tx.Model(&event{}).Select("COALESCE(SUM(CASE WHEN kind = ? THEN 1 ELSE -1 END), 0)", Enrolled).
			Where("account_id = ? AND at_us <= ?", accountID, start.UnixMicro()).Scan(&opening).Error; err != nil {
			return err
		}
		if opening < 0 {
			return ErrConflict
		}
		var events []event
		if err := tx.Where("account_id = ? AND at_us > ? AND at_us < ?", accountID, start.UnixMicro(), end.UnixMicro()).
			Order("sequence").Limit(MaxReportSegments + 1).Find(&events).Error; err != nil {
			return err
		}
		if len(events) > MaxReportSegments {
			return ErrReportLimit
		}
		var err error
		report, err = composeReport(start.UTC(), end.UTC(), asOf, opening, events, periods)
		return err
	}, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	return report, err
}

func composeReport(start, end, asOf time.Time, count int64, events []event, periods []Period) (DeviceReport, error) {
	report := DeviceReport{Start: start, End: end, AsOf: asOf, Complete: true, Segments: []DeviceSegment{}}
	boundaries := []int64{start.UnixMicro(), end.UnixMicro()}
	deltas := make(map[int64]int64, len(events))
	for _, row := range events {
		boundaries = append(boundaries, row.AtUS)
		if row.Kind == Enrolled {
			deltas[row.AtUS]++
		} else if row.Kind == Revoked {
			deltas[row.AtUS]--
		} else {
			return report, ErrConflict
		}
	}
	var previousEnd int64
	for _, period := range periods {
		finish := end.UnixMicro()
		if period.EndUS != nil && *period.EndUS < finish {
			finish = *period.EndUS
		}
		begin := max(start.UnixMicro(), period.StartUS)
		if finish < begin {
			return report, ErrConflict
		}
		// Zero-duration periods can occur when configuration changes share a
		// clock tick. They do not establish any coverage or overlap.
		if finish == begin {
			continue
		}
		if begin < previousEnd {
			return report, ErrConflict
		}
		previousEnd = finish
		boundaries = append(boundaries, begin, finish)
	}
	sort.Slice(boundaries, func(i, j int) bool { return boundaries[i] < boundaries[j] })
	total := new(big.Int)
	periodIndex := 0
	for i := 0; i+1 < len(boundaries); i++ {
		left, right := boundaries[i], boundaries[i+1]
		if left == right {
			continue
		}
		delta := deltas[left]
		if delta > 0 && count > math.MaxInt64-delta || delta < 0 && count < -delta {
			return report, ErrConflict
		}
		count += delta
		if count < 0 {
			return report, ErrConflict
		}
		state := "uncollected"
		for periodIndex < len(periods) && periods[periodIndex].EndUS != nil && *periods[periodIndex].EndUS <= left {
			periodIndex++
		}
		if periodIndex < len(periods) && periods[periodIndex].StartUS <= left {
			state = "incomplete"
			if periods[periodIndex].Complete {
				state = "complete"
			}
		}
		segment := DeviceSegment{Start: time.UnixMicro(left).UTC(), End: time.UnixMicro(right).UTC(), Coverage: state}
		if state == "complete" {
			devices := count
			segment.Devices = &devices
			total.Add(total, new(big.Int).Mul(big.NewInt(right-left), big.NewInt(count)))
		} else {
			report.Complete = false
		}
		if len(report.Segments) > 0 {
			last := &report.Segments[len(report.Segments)-1]
			if last.Coverage == segment.Coverage && (last.Devices == nil && segment.Devices == nil || last.Devices != nil && segment.Devices != nil && *last.Devices == *segment.Devices) {
				last.End = segment.End
				continue
			}
		}
		report.Segments = append(report.Segments, segment)
		if len(report.Segments) > MaxReportSegments {
			return report, ErrReportLimit
		}
	}
	report.DeviceMicroseconds = total.String()
	return report, nil
}
