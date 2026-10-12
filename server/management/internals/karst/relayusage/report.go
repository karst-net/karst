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
	Date              string   `json:"date"`
	ReportedBytes     string   `json:"reported_bytes"`
	ReportedWindows   uint64   `json:"reported_windows"`
	GapWindows        uint64   `json:"gap_windows"`
	ExpectedWindows   uint64   `json:"expected_windows"`
	MissingWindows    uint64   `json:"missing_windows"`
	UnexpectedWindows uint64   `json:"unexpected_windows"`
	GapReasons        []string `json:"gap_reasons"`
}

// Report is a customer-scoped view of managed producer reports, not an invoice.
// Completeness is bounded by the explicitly authorized producer inventory and
// the authorization history cutover recorded in the control-plane database.
type Report struct {
	Start                     time.Time   `json:"start"`
	End                       time.Time   `json:"end"`
	AsOf                      time.Time   `json:"as_of"`
	AuthorizationHistoryStart time.Time   `json:"authorization_history_start"`
	FirstReceivedWindowStart  *time.Time  `json:"first_received_window_start"`
	LastReceivedAt            *time.Time  `json:"last_received_at"`
	Coverage                  string      `json:"coverage"`
	HistoryComplete           bool        `json:"history_complete"`
	Complete                  bool        `json:"complete"`
	ExpectedWindows           uint64      `json:"expected_windows"`
	MissingWindows            uint64      `json:"missing_windows"`
	UnexpectedWindows         uint64      `json:"unexpected_windows"`
	ReportedBytes             string      `json:"reported_bytes"`
	Days                      []ReportDay `json:"days"`
	Limitations               []string    `json:"limitations"`
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

type reportWindowRange struct {
	StartUS int64
	EndUS   int64
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
	date              string
	bytes             *big.Int
	windows           uint64
	gapWindows        uint64
	expectedWindows   uint64
	missingWindows    uint64
	unexpectedWindows uint64
	gapReasons        map[string]struct{}
}

func (s *Store) Report(ctx context.Context, accountID string, start, end time.Time) (Report, error) {
	var report Report
	if accountID == "" || len(accountID) > 128 || start.IsZero() || end.IsZero() {
		return report, ErrInvalidReport
	}
	start, end = start.UTC(), end.UTC()
	if !start.Before(end) || start.UnixMicro() < 0 || end.UnixMicro() < 0 || end.Sub(start) > MaxReportWindow || start.Nanosecond() != 0 || start.Second() != 0 || end.Nanosecond() != 0 || end.Second() != 0 {
		return report, ErrInvalidReport
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	if end.After(now) {
		return report, ErrInvalidReport
	}
	report = Report{
		Start: start, End: end, AsOf: now, Coverage: "authorized_producers", HistoryComplete: true,
		ReportedBytes: "0", Days: []ReportDay{},
		Limitations: []string{
			"Completeness covers explicitly authorized managed producer and account-mapping intervals only; managed relays absent from that operator inventory are outside the expected set.",
			"Batch gap flags indicate measurement uncertainty even when every expected producer window arrived.",
			"Relay batch sequence diagnostics are not included because sequences are producer-wide and could reveal activity outside this account. Missing-minute counts and gap flags are scoped to the authorized account mappings.",
		},
	}
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var history authorizationHistory
		if err := tx.Take(&history, "id = ?", 1).Error; err != nil {
			return err
		}
		report.AuthorizationHistoryStart = time.UnixMicro(history.StartedAtUS).UTC()
		if start.UnixMicro() < history.StartedAtUS {
			report.HistoryComplete = false
			report.Limitations = append(report.Limitations, "Authorization history begins during the requested period; producer coverage before the history cutover is unknown.")
		}
		var periods []producerMappingInterval
		if err := tx.Where("account_id = ? AND start_us < ? AND (end_us IS NULL OR end_us > ?)", accountID, end.UnixMicro(), start.UnixMicro()).
			Order("deployment_id, relay_id, start_us").Limit(maxReportRows + 1).Find(&periods).Error; err != nil {
			return err
		}
		if len(periods) > maxReportRows {
			return ErrReportLimit
		}
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
		return composeRelayReport(&report, periods, windows, totals)
	}, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	return report, err
}

// composeRelayReport aggregates exact received totals and compares account-minute
// receipts with retained authorization intervals. Sequence holes remain a
// separate signal because late batches can arrive out of order.
func composeRelayReport(report *Report, periods []producerMappingInterval, windows []reportWindow, totals []reportTotal) error {
	days := make(map[string]*dayBuilder)
	for date := report.Start.Truncate(24 * time.Hour); date.Before(report.End); date = date.Add(24 * time.Hour) {
		key := date.Format("2006-01-02")
		days[key] = &dayBuilder{date: key, bytes: new(big.Int), gapReasons: make(map[string]struct{})}
	}
	getDay := func(startUS int64) *dayBuilder {
		key := time.UnixMicro(startUS).UTC().Format("2006-01-02")
		day := days[key]
		if day == nil {
			day = &dayBuilder{date: key, bytes: new(big.Int), gapReasons: make(map[string]struct{})}
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
	expected := make(map[string]int64)
	rangesByProducer := make(map[string][]reportWindowRange)
	for _, period := range periods {
		periodEnd := report.End.UnixMicro()
		if period.EndUS != nil && *period.EndUS < periodEnd {
			periodEnd = *period.EndUS
		}
		periodStart := period.StartUS
		if periodStart < report.Start.UnixMicro() {
			periodStart = report.Start.UnixMicro()
		}
		if periodEnd <= periodStart {
			continue
		}
		firstWindow := periodStart - periodStart%int64(minuteMicros)
		endWindow := periodEnd
		if remainder := endWindow % int64(minuteMicros); remainder != 0 {
			endWindow += int64(minuteMicros) - remainder
		}
		if endWindow > report.End.UnixMicro() {
			endWindow = report.End.UnixMicro()
		}
		if firstWindow < report.Start.UnixMicro() {
			firstWindow = report.Start.UnixMicro()
		}
		ownerKey := period.DeploymentID + "\x00" + period.RelayID
		rangesByProducer[ownerKey] = append(rangesByProducer[ownerKey], reportWindowRange{StartUS: firstWindow, EndUS: endWindow})
	}
	for ownerKey, ranges := range rangesByProducer {
		sort.Slice(ranges, func(i, j int) bool { return ranges[i].StartUS < ranges[j].StartUS })
		merged := ranges[:0]
		for _, current := range ranges {
			count := len(merged)
			if count > 0 && current.StartUS <= merged[count-1].EndUS {
				if current.EndUS > merged[count-1].EndUS {
					merged[count-1].EndUS = current.EndUS
				}
				continue
			}
			merged = append(merged, current)
		}
		for _, period := range merged {
			for windowStart := period.StartUS; windowStart < period.EndUS; windowStart += int64(minuteMicros) {
				key := reportWindowKeyFromOwner(ownerKey, windowStart)
				if len(expected) >= maxReportRows {
					return ErrReportLimit
				}
				expected[key] = windowStart
				getDay(windowStart).expectedWindows++
			}
		}
	}
	receivedExpected := make(map[string]struct{}, len(expected))
	for _, window := range windows {
		day := getDay(window.StartUS)
		day.windows++
		windowKey := reportWindowKey(window.DeploymentID, window.RelayID, window.StartUS)
		if _, ok := expected[windowKey]; ok {
			receivedExpected[windowKey] = struct{}{}
		} else {
			day.unexpectedWindows++
			report.UnexpectedWindows++
		}
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
	}
	for key, startUS := range expected {
		if _, ok := receivedExpected[key]; ok {
			continue
		}
		day := getDay(startUS)
		day.missingWindows++
		report.MissingWindows++
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
		report.ExpectedWindows += day.expectedWindows
		report.Days = append(report.Days, ReportDay{Date: day.date, ReportedBytes: day.bytes.String(), ReportedWindows: day.windows,
			GapWindows: day.gapWindows, ExpectedWindows: day.expectedWindows, MissingWindows: day.missingWindows, UnexpectedWindows: day.unexpectedWindows,
			GapReasons: reasons})
	}
	report.ReportedBytes = totalBytes.String()
	report.Complete = report.HistoryComplete && report.ExpectedWindows > 0 && report.MissingWindows == 0 && report.UnexpectedWindows == 0
	for _, day := range report.Days {
		if day.GapWindows != 0 {
			report.Complete = false
			break
		}
	}
	return nil
}

func reportWindowKey(deploymentID, relayID string, startUS int64) string {
	return reportWindowKeyFromOwner(deploymentID+"\x00"+relayID, startUS)
}

func reportWindowKeyFromOwner(ownerKey string, startUS int64) string {
	return ownerKey + "\x00" + strconv.FormatInt(startUS, 10)
}

func reportBatchKey(deploymentID, relayID, epoch, sequence string) string {
	return deploymentID + "\x00" + relayID + "\x00" + epoch + "\x00" + sequence
}
