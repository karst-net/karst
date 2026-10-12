// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package billing

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/netbirdio/netbird/management/internals/karst/relayusage"
	"github.com/netbirdio/netbird/management/internals/karst/usage"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var (
	ErrNoBillingAccount   = errors.New("billing: account scope missing")
	ErrScheduleNotFound   = errors.New("billing: rate schedule not found")
	ErrScheduleConflict   = errors.New("billing: schedule version already has different contents")
	ErrScheduleUnassigned = errors.New("billing: no schedule assigned for period")
	ErrAssignmentConflict = errors.New("billing: period overlaps or conflicts with an existing assignment")
	ErrInvalidPeriod      = errors.New("billing: invalid explicit period")
	ErrInvoiceIncomplete  = errors.New("billing: cannot finalize incomplete usage")
	ErrInvoiceConflict    = errors.New("billing: finalized invoice inputs conflict")
)

type billingAccountContextKey struct{}

// WithAccount scopes assignment reads and writes to the authenticated account.
func WithAccount(ctx context.Context, accountID string) context.Context {
	return context.WithValue(ctx, billingAccountContextKey{}, accountID)
}

func billingAccountFromContext(ctx context.Context) (string, error) {
	accountID, _ := ctx.Value(billingAccountContextKey{}).(string)
	if accountID == "" {
		return "", ErrNoBillingAccount
	}
	return accountID, nil
}

type rateScheduleRow struct {
	Version   string    `gorm:"primaryKey;size:128"`
	Digest    string    `gorm:"size:64;not null"`
	Snapshot  []byte    `gorm:"not null"`
	CreatedAt time.Time `gorm:"not null"`
}

func (rateScheduleRow) TableName() string { return "karst_billing_rate_schedules" }

// rateAssignmentRow is immutable once written. Period boundaries are explicit
// inputs; this store does not choose a billing calendar or prorate usage.
type rateAssignmentRow struct {
	AccountID       string    `gorm:"primaryKey;size:128"`
	PeriodStartUS   int64     `gorm:"primaryKey"`
	PeriodEndUS     int64     `gorm:"not null;index:idx_billing_assignment_period"`
	ScheduleVersion string    `gorm:"size:128;not null;index"`
	CreatedAt       time.Time `gorm:"not null"`
}

func (rateAssignmentRow) TableName() string { return "karst_billing_rate_assignments" }

// billingAccountLock serializes period assignment changes for one account.
// PostgreSQL uses the row lock below; SQLite's write transaction serializes
// the guard-row upsert.
type billingAccountLock struct {
	AccountID string `gorm:"primaryKey;size:128"`
}

func (billingAccountLock) TableName() string { return "karst_billing_account_locks" }

type invoiceRow struct {
	AccountID     string    `gorm:"primaryKey;size:128"`
	PeriodStartUS int64     `gorm:"primaryKey"`
	PeriodEndUS   int64     `gorm:"not null"`
	Digest        string    `gorm:"size:64;not null"`
	Snapshot      []byte    `gorm:"not null"`
	FinalizedAt   time.Time `gorm:"not null"`
}

func (invoiceRow) TableName() string { return "karst_billing_invoices" }

// Assignment identifies an immutable schedule snapshot for one explicit
// account period. It does not imply that usage is complete or chargeable.
type Assignment struct {
	AccountID       string    `json:"account_id"`
	PeriodStart     time.Time `json:"period_start"`
	PeriodEnd       time.Time `json:"period_end"`
	ScheduleVersion string    `json:"schedule_version"`
}

// Store persists immutable rate snapshots and explicit, opt-in assignments.
// Missing assignments have no billing effect.
type Store struct{ db *gorm.DB }

// NewStore migrates billing schedule, assignment, and finalized invoice-input
// tables. Billing remains opt-in at the account level.
func NewStore(db *gorm.DB) (*Store, error) {
	if db == nil {
		return nil, errors.New("billing: nil database")
	}
	if err := db.AutoMigrate(&rateScheduleRow{}, &rateAssignmentRow{}, &billingAccountLock{}, &invoiceRow{}); err != nil {
		return nil, fmt.Errorf("billing: migrate schedules: %w", err)
	}
	return &Store{db: db}, nil
}

// FinalizeInvoice persists an immutable invoice-input snapshot for an assigned
// account period. It is safe to retry with identical inputs; later changes to
// usage or estimates cannot replace a finalized snapshot. This records amounts
// only and does not create a provider charge or payment.
func (s *Store) FinalizeInvoice(ctx context.Context, deviceReport usage.DeviceReport, relayReport relayusage.Report) (FinalInvoice, error) {
	accountID, err := billingAccountFromContext(ctx)
	if err != nil {
		return FinalInvoice{}, err
	}
	start, end := deviceReport.Start, deviceReport.End
	startUS, endUS, err := billingPeriodMicros(start, end)
	if err != nil {
		return FinalInvoice{}, err
	}
	if !isUTCCalendarMonth(startUS, endUS) {
		return FinalInvoice{}, ErrInvalidPeriod
	}
	estimate, err := s.Calculate(ctx, deviceReport, relayReport)
	if err != nil {
		return FinalInvoice{}, err
	}
	if !estimate.UsageComplete || len(estimate.Incomplete) != 0 || estimate.DeviceExact == nil || estimate.RelayExact == nil || estimate.TotalExact == nil {
		return FinalInvoice{}, ErrInvoiceIncomplete
	}
	assignment, err := s.Assignment(ctx, start, end)
	if err != nil {
		return FinalInvoice{}, err
	}
	if estimate.ScheduleVersion != assignment.ScheduleVersion {
		return FinalInvoice{}, ErrScheduleUnassigned
	}
	schedule, err := s.Schedule(ctx, assignment.ScheduleVersion)
	if err != nil {
		return FinalInvoice{}, err
	}
	if estimate.Currency != schedule.Currency {
		return FinalInvoice{}, ErrInvalidRateSchedule
	}
	deviceInputHash, err := digestJSON(deviceReport)
	if err != nil {
		return FinalInvoice{}, fmt.Errorf("billing: hash device invoice input: %w", err)
	}
	relayInputHash, err := digestJSON(relayReport)
	if err != nil {
		return FinalInvoice{}, fmt.Errorf("billing: hash relay invoice input: %w", err)
	}
	deviceExact, err := parseExactNonnegative(*estimate.DeviceExact)
	if err != nil {
		return FinalInvoice{}, err
	}
	relayExact, err := parseExactNonnegative(*estimate.RelayExact)
	if err != nil {
		return FinalInvoice{}, err
	}
	totalExact, err := parseExactNonnegative(*estimate.TotalExact)
	if err != nil {
		return FinalInvoice{}, err
	}
	if new(big.Rat).Add(deviceExact, relayExact).Cmp(totalExact) != 0 {
		return FinalInvoice{}, errors.New("billing: invoice total does not equal its line inputs")
	}
	deviceMinor, err := truncateMinor(deviceExact)
	if err != nil {
		return FinalInvoice{}, err
	}
	relayMinor, err := truncateMinor(relayExact)
	if err != nil {
		return FinalInvoice{}, err
	}
	if deviceMinor > int64(^uint64(0)>>1)-relayMinor {
		return FinalInvoice{}, errors.New("billing: invoice total exceeds supported amount")
	}
	invoice := FinalInvoice{
		SchemaVersion: "invoice-inputs-v1", AccountID: accountID,
		PeriodStart: time.UnixMicro(startUS).UTC(), PeriodEnd: time.UnixMicro(endUS).UTC(),
		ScheduleVersion: schedule.Version, Currency: schedule.Currency,
		DeviceUsage: deviceReport, RelayUsage: relayReport,
		DeviceInputHash: deviceInputHash, RelayInputHash: relayInputHash,
		DeviceExact: *estimate.DeviceExact, RelayExact: *estimate.RelayExact, TotalExact: *estimate.TotalExact,
		DeviceMinor: deviceMinor, RelayMinor: relayMinor, TotalMinor: deviceMinor + relayMinor,
		FinalizedAt: time.Now().UTC(),
	}
	snapshot, err := json.Marshal(invoice)
	if err != nil {
		return FinalInvoice{}, fmt.Errorf("billing: encode invoice: %w", err)
	}
	digest := sha256.Sum256(snapshot)
	row := invoiceRow{AccountID: accountID, PeriodStartUS: startUS, PeriodEndUS: endUS, Digest: hex.EncodeToString(digest[:]), Snapshot: snapshot, FinalizedAt: invoice.FinalizedAt}
	result := s.db.WithContext(ctx).Clauses(clause.OnConflict{DoNothing: true}).Create(&row)
	if result.Error != nil {
		return FinalInvoice{}, fmt.Errorf("billing: finalize invoice: %w", result.Error)
	}
	if result.RowsAffected != 0 {
		return invoice, nil
	}
	stored, err := s.Invoice(ctx, start, end)
	if err != nil {
		return FinalInvoice{}, err
	}
	if !sameInvoiceInputs(invoice, stored) {
		return FinalInvoice{}, ErrInvoiceConflict
	}
	return stored, nil
}

func isUTCCalendarMonth(startUS, endUS int64) bool {
	start := time.UnixMicro(startUS).UTC()
	end := time.UnixMicro(endUS).UTC()
	if start.Day() != 1 || start.Hour() != 0 || start.Minute() != 0 || start.Second() != 0 || start.Nanosecond() != 0 {
		return false
	}
	expectedEnd := start.AddDate(0, 1, 0)
	return end.Equal(expectedEnd)
}

// Invoice returns and verifies an immutable finalized input snapshot.
func (s *Store) Invoice(ctx context.Context, start, end time.Time) (FinalInvoice, error) {
	accountID, err := billingAccountFromContext(ctx)
	if err != nil {
		return FinalInvoice{}, err
	}
	startUS, endUS, err := billingPeriodMicros(start, end)
	if err != nil {
		return FinalInvoice{}, err
	}
	var row invoiceRow
	if err := s.db.WithContext(ctx).Where("account_id = ? AND period_start_us = ?", accountID, startUS).Take(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return FinalInvoice{}, ErrInvoiceNotFound
		}
		return FinalInvoice{}, fmt.Errorf("billing: load invoice: %w", err)
	}
	if row.PeriodEndUS != endUS {
		return FinalInvoice{}, ErrInvoiceNotFound
	}
	digest := sha256.Sum256(row.Snapshot)
	if hex.EncodeToString(digest[:]) != row.Digest {
		return FinalInvoice{}, errors.New("billing: invoice snapshot digest mismatch")
	}
	var invoice FinalInvoice
	if err := json.Unmarshal(row.Snapshot, &invoice); err != nil {
		return FinalInvoice{}, fmt.Errorf("billing: decode invoice: %w", err)
	}
	if invoice.AccountID != accountID || invoice.SchemaVersion != "invoice-inputs-v1" || invoice.PeriodStart.UnixMicro() != startUS || invoice.PeriodEnd.UnixMicro() != endUS || invoice.FinalizedAt.IsZero() || !isUTCCalendarMonth(startUS, endUS) {
		return FinalInvoice{}, errors.New("billing: stored invoice snapshot is invalid")
	}
	deviceHash, err := digestJSON(invoice.DeviceUsage)
	if err != nil || deviceHash != invoice.DeviceInputHash {
		return FinalInvoice{}, errors.New("billing: device invoice input digest mismatch")
	}
	relayHash, err := digestJSON(invoice.RelayUsage)
	if err != nil || relayHash != invoice.RelayInputHash {
		return FinalInvoice{}, errors.New("billing: relay invoice input digest mismatch")
	}
	schedule, err := s.Schedule(ctx, invoice.ScheduleVersion)
	if err != nil {
		return FinalInvoice{}, err
	}
	if schedule.Currency != invoice.Currency {
		return FinalInvoice{}, errors.New("billing: invoice currency differs from its schedule")
	}
	estimate, err := Calculate(invoice.DeviceUsage, invoice.RelayUsage, schedule)
	if err != nil || !estimate.UsageComplete || estimate.DeviceExact == nil || estimate.RelayExact == nil || estimate.TotalExact == nil ||
		*estimate.DeviceExact != invoice.DeviceExact || *estimate.RelayExact != invoice.RelayExact || *estimate.TotalExact != invoice.TotalExact {
		return FinalInvoice{}, errors.New("billing: invoice amounts do not match their usage inputs")
	}
	deviceAmount, err := parseExactNonnegative(invoice.DeviceExact)
	if err != nil {
		return FinalInvoice{}, errors.New("billing: invalid finalized device exact amount")
	}
	relayAmount, err := parseExactNonnegative(invoice.RelayExact)
	if err != nil {
		return FinalInvoice{}, errors.New("billing: invalid finalized relay exact amount")
	}
	totalAmount, err := parseExactNonnegative(invoice.TotalExact)
	if err != nil || new(big.Rat).Add(deviceAmount, relayAmount).Cmp(totalAmount) != 0 {
		return FinalInvoice{}, errors.New("billing: invalid finalized total exact amount")
	}
	deviceMinor, err := truncateMinor(deviceAmount)
	if err != nil || deviceMinor != invoice.DeviceMinor {
		return FinalInvoice{}, errors.New("billing: invalid finalized device line amount")
	}
	relayMinor, err := truncateMinor(relayAmount)
	if err != nil || relayMinor != invoice.RelayMinor || deviceMinor > int64(^uint64(0)>>1)-relayMinor || deviceMinor+relayMinor != invoice.TotalMinor {
		return FinalInvoice{}, errors.New("billing: invalid finalized relay or total amount")
	}
	return invoice, nil
}

// WithDB binds the store to a caller-owned GORM transaction. Callers that
// expose assignment changes can write the audit event in that same transaction.
func (s *Store) WithDB(db *gorm.DB) *Store { return &Store{db: db} }

// PutSchedule inserts an immutable schedule snapshot. Repeating the same
// version and content is idempotent; reusing a version for different prices is
// rejected so historical calculations remain reproducible.
func (s *Store) PutSchedule(ctx context.Context, schedule RateSchedule) error {
	if err := validateRateSchedule(schedule); err != nil {
		return err
	}
	snapshot, err := json.Marshal(schedule)
	if err != nil {
		return fmt.Errorf("billing: encode schedule: %w", err)
	}
	digest := sha256.Sum256(snapshot)
	row := rateScheduleRow{
		Version: schedule.Version, Digest: hex.EncodeToString(digest[:]),
		Snapshot: snapshot, CreatedAt: time.Now().UTC(),
	}
	result := s.db.WithContext(ctx).Clauses(clause.OnConflict{DoNothing: true}).Create(&row)
	if result.Error != nil {
		return fmt.Errorf("billing: store schedule: %w", result.Error)
	}
	if result.RowsAffected != 0 {
		return nil
	}
	var existing rateScheduleRow
	if err := s.db.WithContext(ctx).Where("version = ?", schedule.Version).Take(&existing).Error; err != nil {
		return fmt.Errorf("billing: verify existing schedule: %w", err)
	}
	if existing.Digest != row.Digest || string(existing.Snapshot) != string(row.Snapshot) {
		return ErrScheduleConflict
	}
	return nil
}

// Schedule returns the immutable snapshot stored for version.
func (s *Store) Schedule(ctx context.Context, version string) (RateSchedule, error) {
	var row rateScheduleRow
	if err := s.db.WithContext(ctx).Where("version = ?", version).Take(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return RateSchedule{}, ErrScheduleNotFound
		}
		return RateSchedule{}, fmt.Errorf("billing: load schedule: %w", err)
	}
	var schedule RateSchedule
	if err := json.Unmarshal(row.Snapshot, &schedule); err != nil {
		return RateSchedule{}, fmt.Errorf("billing: decode schedule snapshot: %w", err)
	}
	if schedule.Version != row.Version || validateRateSchedule(schedule) != nil {
		return RateSchedule{}, errors.New("billing: stored schedule snapshot is invalid")
	}
	digest := sha256.Sum256(row.Snapshot)
	if hex.EncodeToString(digest[:]) != row.Digest {
		return RateSchedule{}, errors.New("billing: stored schedule snapshot digest mismatch")
	}
	return schedule, nil
}

// AssignSchedule explicitly enables one schedule version for one exact
// account period. It rejects overlapping periods and never replaces an
// existing assignment. The caller supplies period boundaries; no calendar,
// rounding, invoice-finalization, or enforcement policy is inferred here.
func (s *Store) AssignSchedule(ctx context.Context, start, end time.Time, version string) error {
	accountID, err := billingAccountFromContext(ctx)
	if err != nil {
		return err
	}
	startUS, endUS, err := billingPeriodMicros(start, end)
	if err != nil {
		return err
	}
	if _, err := s.Schedule(ctx, version); err != nil {
		return fmt.Errorf("billing: verify assigned schedule: %w", err)
	}
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		guard := billingAccountLock{AccountID: accountID}
		if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&guard).Error; err != nil {
			return fmt.Errorf("billing: lock account assignment: %w", err)
		}
		var locked billingAccountLock
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("account_id = ?", accountID).Take(&locked).Error; err != nil {
			return fmt.Errorf("billing: lock account assignment: %w", err)
		}
		var overlaps []rateAssignmentRow
		if err := tx.Where("account_id = ? AND period_start_us < ? AND period_end_us > ?", accountID, endUS, startUS).Find(&overlaps).Error; err != nil {
			return fmt.Errorf("billing: check overlapping assignments: %w", err)
		}
		if len(overlaps) != 0 {
			if len(overlaps) == 1 && overlaps[0].PeriodStartUS == startUS && overlaps[0].PeriodEndUS == endUS && overlaps[0].ScheduleVersion == version {
				return nil
			}
			return ErrAssignmentConflict
		}
		row := rateAssignmentRow{
			AccountID: accountID, PeriodStartUS: startUS, PeriodEndUS: endUS,
			ScheduleVersion: version, CreatedAt: time.Now().UTC(),
		}
		if err := tx.Create(&row).Error; err != nil {
			return fmt.Errorf("billing: assign schedule: %w", err)
		}
		return nil
	}, &sql.TxOptions{Isolation: sql.LevelSerializable})
}

// Assignment returns the exact account-period assignment. It never falls back
// to a default schedule, preserving unchanged behavior for unconfigured accounts.
func (s *Store) Assignment(ctx context.Context, start, end time.Time) (Assignment, error) {
	accountID, err := billingAccountFromContext(ctx)
	if err != nil {
		return Assignment{}, err
	}
	startUS, endUS, err := billingPeriodMicros(start, end)
	if err != nil {
		return Assignment{}, err
	}
	var row rateAssignmentRow
	if err := s.db.WithContext(ctx).Where("account_id = ? AND period_start_us = ?", accountID, startUS).Take(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return Assignment{}, ErrScheduleUnassigned
		}
		return Assignment{}, fmt.Errorf("billing: load assignment: %w", err)
	}
	if row.PeriodEndUS != endUS {
		return Assignment{}, ErrScheduleUnassigned
	}
	return Assignment{
		AccountID:       row.AccountID,
		PeriodStart:     time.UnixMicro(row.PeriodStartUS).UTC(),
		PeriodEnd:       time.UnixMicro(row.PeriodEndUS).UTC(),
		ScheduleVersion: row.ScheduleVersion,
	}, nil
}

// AssignedSchedule loads the exact assigned snapshot for one period.
func (s *Store) AssignedSchedule(ctx context.Context, start, end time.Time) (RateSchedule, error) {
	assignment, err := s.Assignment(ctx, start, end)
	if err != nil {
		return RateSchedule{}, err
	}
	return s.Schedule(ctx, assignment.ScheduleVersion)
}

// Calculate estimates exact charges using only the rate schedule explicitly
// assigned to the device report's account and period. It does not persist an
// invoice or create a charge; unassigned periods return ErrScheduleUnassigned.
func (s *Store) Calculate(ctx context.Context, deviceReport usage.DeviceReport, relayReport relayusage.Report) (Estimate, error) {
	schedule, err := s.AssignedSchedule(ctx, deviceReport.Start, deviceReport.End)
	if err != nil {
		return Estimate{}, err
	}
	return Calculate(deviceReport, relayReport, schedule)
}

func billingPeriodMicros(start, end time.Time) (int64, int64, error) {
	start = start.UTC()
	end = end.UTC()
	if !validBillingTime(start) || !validBillingTime(end) || !start.Before(end) {
		return 0, 0, ErrInvalidPeriod
	}
	return start.UnixMicro(), end.UnixMicro(), nil
}
