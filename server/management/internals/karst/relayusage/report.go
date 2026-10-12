// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package relayusage

import (
	"context"
	"database/sql"
	"errors"
	"math/big"
	"sort"
	"strconv"
	"time"

	"gorm.io/gorm"
)

const (
	MaxReportWindow = 93 * 24 * time.Hour
	maxReportRows   = 250_000
)

var (
	ErrInvalidReport = errors.New("relay usage: invalid report request")
	ErrReportLimit   = errors.New("relay usage: report is too large; request a shorter window")
	ErrReportData    = errors.New("relay usage: invalid stored report value")
)

// ReportDay contains only totals from batches that arrived. A day without
// received windows has no reported total; it does not establish zero traffic.
type ReportDay struct {
	Date             string   `json:"date"`
	ReportedBytes    string   `json:"reported_bytes"`
	ReportedWindows  uint64   `json:"reported_windows"`
	GapWindows       uint64   `json:"gap_windows"`
	MissingSequences string   `json:"missing_sequences"`
	GapReasons       []string `json:"gap_reasons"`
}

// Report is a customer-scoped view of received relay reports, not an invoice
// or a claim that every authorized relay reported. Producer authorization is
// currently mutable rather than historized, so Complete is deliberately false.
type Report struct {
	Start                    time.Time   `json:"start"`
	End                      time.Time   `json:"end"`
	AsOf                     time.Time   `json:"as_of"`
	FirstReceivedWindowStart *time.Time  `json:"first_received_window_start"`
	LastReceivedAt           *time.Time  `json:"last_received_at"`
	Coverage                 string      `json:"coverage"`
	Complete                 bool        `json:"complete"`
	ReportedBytes            string      `json:"reported_bytes"`
	MissingSequences         string      `json:"missing_sequences"`
	Days                     []ReportDay `json:"days"`
	Limitations              []string    `json:"limitations"`
}

type reportWindow struct {
	DeploymentID string
	RelayID      string
	Epoch        string
	Sequence     string
	StartUS      int64
	Gaps         uint8
	ReceivedAt   time.Time
}

type reportTotal struct {
	DeploymentID string
	RelayID      string
	Epoch        string
	Sequence     string
	MappingKey   string
	BytesDecimal string
}

type dayBuilder struct {
	date             string
	bytes            *big.Int
	windows          uint64
	gapWindows       uint64
	missingSequences *big.Int
	gapReasons       map[string]struct{}
}

func (s *Store) Report(ctx context.Context, accountID string, start, end time.Time) (Report, error) {
	var report Report
	if accountID == "" || len(accountID) > 128 || start.IsZero() || end.IsZero() {
		return report, ErrInvalidReport
	}
	start, end = start.UTC(), end.UTC()
	if !start.Before(end) || end.Sub(start) > MaxReportWindow || start.Nanosecond() != 0 || start.Second() != 0 || end.Nanosecond() != 0 || end.Second() != 0 {
		return report, ErrInvalidReport
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	if end.After(now) {
		return report, ErrInvalidReport
	}
	report = Report{
		Start: start, End: end, AsOf: now, Coverage: "received_only", Complete: false,
		ReportedBytes: "0", MissingSequences: "0", Days: []ReportDay{},
		Limitations: []string{
			"Expected relay producers and their authorized intervals are not historized yet, so missing producer reports cannot be detected. A day with no received windows does not prove zero traffic.",
			"Gap flags and sequence gaps between received batches are shown, but absence of a detected gap does not prove end-to-end completeness.",
		},
	}
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var windows []reportWindow
		if err := tx.Table("karst_usage_relay_batch_coverage AS c").
			Select("c.deployment_id, c.relay_id, c.epoch, c.sequence, c.start_us, c.gaps, b.received_at").
			Joins("JOIN karst_usage_relay_batches AS b ON b.deployment_id = c.deployment_id AND b.relay_id = c.relay_id AND b.epoch = c.epoch AND b.sequence = c.sequence").
			Where("c.account_id = ? AND c.start_us >= ? AND c.start_us < ?", accountID, start.UnixMicro(), end.UnixMicro()).
			Order("c.relay_id, c.epoch, c.sequence").Limit(maxReportRows + 1).Find(&windows).Error; err != nil {
			return err
		}
		if len(windows) > maxReportRows {
			return ErrReportLimit
		}
		var totals []reportTotal
		if err := tx.Table("karst_usage_relay_batch_totals AS t").
			Select("t.deployment_id, t.relay_id, t.epoch, t.sequence, t.mapping_key, t.bytes_decimal").
			Joins("JOIN karst_usage_relay_batches AS b ON b.deployment_id = t.deployment_id AND b.relay_id = t.relay_id AND b.epoch = t.epoch AND b.sequence = t.sequence").
			Joins("JOIN karst_usage_relay_batch_coverage AS c ON c.deployment_id = t.deployment_id AND c.relay_id = t.relay_id AND c.epoch = t.epoch AND c.sequence = t.sequence AND c.account_id = t.account_id").
			Where("t.account_id = ? AND b.start_us >= ? AND b.start_us < ?", accountID, start.UnixMicro(), end.UnixMicro()).
			Order("t.relay_id, t.epoch, t.sequence, t.mapping_key").Limit(maxReportRows + 1).Scan(&totals).Error; err != nil {
			return err
		}
		if len(totals) > maxReportRows {
			return ErrReportLimit
		}
		return composeRelayReport(&report, windows, totals)
	}, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	return report, err
}

// composeRelayReport aggregates only received windows and exact decimal byte
// totals. Sequence holes are counted only between two received batches from
// the same relay epoch; no missing head/tail or inactive producer is inferred.
func composeRelayReport(report *Report, windows []reportWindow, totals []reportTotal) error {
	days := make(map[string]*dayBuilder)
	for date := report.Start.Truncate(24 * time.Hour); date.Before(report.End); date = date.Add(24 * time.Hour) {
		key := date.Format("2006-01-02")
		days[key] = &dayBuilder{date: key, bytes: new(big.Int), missingSequences: new(big.Int), gapReasons: make(map[string]struct{})}
	}
	getDay := func(startUS int64) *dayBuilder {
		key := time.UnixMicro(startUS).UTC().Format("2006-01-02")
		day := days[key]
		if day == nil {
			day = &dayBuilder{date: key, bytes: new(big.Int), missingSequences: new(big.Int), gapReasons: make(map[string]struct{})}
			days[key] = day
		}
		return day
	}
	batchBytes := make(map[string]*big.Int, len(totals))
	for _, row := range totals {
		value, ok := new(big.Int).SetString(row.BytesDecimal, 10)
		if !ok || value.Sign() < 0 {
			return ErrReportData
		}
		key := reportBatchKey(row.DeploymentID, row.RelayID, row.Epoch, row.Sequence)
		if batchBytes[key] == nil {
			batchBytes[key] = new(big.Int)
		}
		batchBytes[key].Add(batchBytes[key], value)
	}
	totalBytes := new(big.Int)
	totalMissing := new(big.Int)
	previous := make(map[string]uint64)
	seen := make(map[string]bool)
	for _, window := range windows {
		day := getDay(window.StartUS)
		day.windows++
		windowStart := time.UnixMicro(window.StartUS).UTC()
		if report.FirstReceivedWindowStart == nil || windowStart.Before(*report.FirstReceivedWindowStart) {
			report.FirstReceivedWindowStart = &windowStart
		}
		receivedAt := window.ReceivedAt.UTC()
		if report.LastReceivedAt == nil || receivedAt.After(*report.LastReceivedAt) {
			report.LastReceivedAt = &receivedAt
		}
		batchKey := reportBatchKey(window.DeploymentID, window.RelayID, window.Epoch, window.Sequence)
		if value := batchBytes[batchKey]; value != nil {
			day.bytes.Add(day.bytes, value)
			totalBytes.Add(totalBytes, value)
		}
		for bit, name := range []string{"unresolved_mapping", "capacity", "overflow", "clock", "observation_lost"} {
			if window.Gaps&(1<<bit) != 0 {
				day.gapReasons[name] = struct{}{}
			}
		}
		if window.Gaps != 0 {
			day.gapWindows++
		}
		producerKey := window.DeploymentID + "\x00" + window.RelayID + "\x00" + window.Epoch
		sequence, err := strconv.ParseUint(window.Sequence, 10, 64)
		if err != nil {
			return ErrReportData
		}
		if seen[producerKey] && previous[producerKey] != ^uint64(0) && sequence > previous[producerKey]+1 {
			missing := new(big.Int).SetUint64(sequence - previous[producerKey] - 1)
			day.missingSequences.Add(day.missingSequences, missing)
			totalMissing.Add(totalMissing, missing)
		}
		previous[producerKey], seen[producerKey] = sequence, true
	}
	dateKeys := make([]string, 0, len(days))
	for date := range days {
		dateKeys = append(dateKeys, date)
	}
	sort.Strings(dateKeys)
	for _, date := range dateKeys {
		day := days[date]
		reasons := make([]string, 0, len(day.gapReasons))
		for reason := range day.gapReasons {
			reasons = append(reasons, reason)
		}
		sort.Strings(reasons)
		report.Days = append(report.Days, ReportDay{Date: day.date, ReportedBytes: day.bytes.String(), ReportedWindows: day.windows,
			GapWindows: day.gapWindows, MissingSequences: day.missingSequences.String(), GapReasons: reasons})
	}
	report.ReportedBytes, report.MissingSequences = totalBytes.String(), totalMissing.String()
	return nil
}

func reportBatchKey(deploymentID, relayID, epoch, sequence string) string {
	return deploymentID + "\x00" + relayID + "\x00" + epoch + "\x00" + sequence
}
