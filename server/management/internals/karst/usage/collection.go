// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package usage

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Collector coordinates coverage and membership changes in their caller's SQL
// transaction. Every writer to the membership source must participate. Now is
// sampled after acquiring the account lock; nil uses the system clock.
type Collector struct {
	Now func() time.Time
}

// Snapshot reads authoritative enrollment IDs using the supplied transaction.
// IDs must survive reconnects and key changes, but change on re-enrollment.
type Snapshot func(*gorm.DB) ([]string, error)

type collection struct {
	AccountID string `gorm:"primaryKey;size:128"`
	Enabled   bool
	PeriodID  string `gorm:"size:36"`
	LastAtUS  int64
}

func (collection) TableName() string { return "karst_usage_device_collection" }

// Period records collection coverage, not a billing period. Complete is false
// when reconciliation detected unrecorded membership changes. An open period
// only covers observations up to the reporting snapshot, never future time.
type Period struct {
	ID        string `gorm:"primaryKey;size:36"`
	AccountID string `gorm:"size:128;not null;index"`
	StartUS   int64
	EndUS     *int64
	Complete  bool
}

func (Period) TableName() string { return "karst_usage_device_coverage" }

type enrollment struct {
	AccountID    string `gorm:"primaryKey;size:128"`
	DeviceID     string `gorm:"primaryKey;size:128"`
	GenerationID string `gorm:"size:36;not null"`
}

func (enrollment) TableName() string { return "karst_usage_device_enrollments" }

// Discrepancy preserves evidence of reconciliation. The original lifecycle
// events stay immutable; only the affected coverage period becomes incomplete.
type Discrepancy struct {
	ID        string `gorm:"primaryKey;size:36"`
	AccountID string `gorm:"size:128;not null;index"`
	AtUS      int64
	Missing   int
	Added     int
}

func (Discrepancy) TableName() string { return "karst_usage_device_discrepancies" }

func lockCollection(tx *gorm.DB, accountID string) (*gorm.DB, collection, error) {
	var state collection
	if tx == nil || tx.Statement == nil {
		return nil, state, ErrTransaction
	}
	if _, ok := tx.Statement.ConnPool.(gorm.TxCommitter); !ok {
		return nil, state, ErrTransaction
	}
	if !validID(accountID) {
		return nil, state, ErrInvalid
	}
	db := tx.Session(&gorm.Session{NewDB: true})
	if err := db.Clauses(clause.OnConflict{DoNothing: true}).Create(&collection{AccountID: accountID}).Error; err != nil {
		return nil, state, err
	}
	if err := db.Model(&collection{}).Where("account_id = ?", accountID).
		UpdateColumn("last_at_us", gorm.Expr("last_at_us + 0")).Error; err != nil {
		return nil, state, err
	}
	err := db.Clauses(clause.Locking{Strength: "UPDATE"}).Where("account_id = ?", accountID).Take(&state).Error
	return db, state, err
}

func (c Collector) timestamp(state collection) (time.Time, error) {
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	at := now().UTC().Truncate(time.Microsecond)
	if !validTime(at) || at.UnixMicro() < state.LastAtUS {
		return time.Time{}, fmt.Errorf("%w: collection clock regressed", ErrConflict)
	}
	return at, nil
}

func membership(db *gorm.DB, snapshot Snapshot) (map[string]bool, error) {
	ids, err := snapshot(db)
	if err != nil {
		return nil, err
	}
	wanted := make(map[string]bool, len(ids))
	for _, id := range ids {
		if !validID(id) || wanted[id] {
			return nil, ErrInvalid
		}
		wanted[id] = true
	}
	return wanted, nil
}

func activeEnrollments(db *gorm.DB, accountID string) ([]enrollment, error) {
	var rows []enrollment
	err := db.Clauses(clause.Locking{Strength: "UPDATE"}).Where("account_id = ?", accountID).
		Order("device_id").Find(&rows).Error
	return rows, err
}

func difference(rows []enrollment, wanted map[string]bool) (missing, added int) {
	added = len(wanted)
	for _, row := range rows {
		if wanted[row.DeviceID] {
			added--
		} else {
			missing++
		}
	}
	return missing, added
}

func synchronize(db *gorm.DB, accountID string, at time.Time, rows []enrollment, wanted map[string]bool) error {
	remaining := make(map[string]bool, len(wanted))
	for id := range wanted {
		remaining[id] = true
	}
	for _, row := range rows {
		if remaining[row.DeviceID] {
			delete(remaining, row.DeviceID)
			continue
		}
		if err := Append(db, Change{ID: row.GenerationID + ":revoke", AccountID: accountID,
			GenerationID: row.GenerationID, Kind: Revoked, At: at}); err != nil {
			return err
		}
		if err := db.Delete(&row).Error; err != nil {
			return err
		}
	}
	ids := make([]string, 0, len(remaining))
	for id := range remaining {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		generation := uuid.NewString()
		if err := Append(db, Change{ID: generation + ":enroll", AccountID: accountID,
			GenerationID: generation, Kind: Enrolled, At: at}); err != nil {
			return err
		}
		if err := db.Create(&enrollment{AccountID: accountID, DeviceID: id, GenerationID: generation}).Error; err != nil {
			return err
		}
	}
	return nil
}

func startPeriod(db *gorm.DB, state *collection, at time.Time) error {
	state.PeriodID = uuid.NewString()
	state.Enabled = true
	return db.Create(&Period{ID: state.PeriodID, AccountID: state.AccountID, StartUS: at.UnixMicro(), Complete: true}).Error
}

func closePeriod(db *gorm.DB, state collection, at time.Time, complete bool) error {
	return db.Model(&Period{}).Where("id = ? AND account_id = ?", state.PeriodID, state.AccountID).
		Updates(map[string]any{"end_us": at.UnixMicro(), "complete": complete}).Error
}

func saveCollection(db *gorm.DB, state collection, at time.Time) error {
	return db.Model(&collection{}).Where("account_id = ?", state.AccountID).
		Updates(map[string]any{"enabled": state.Enabled, "period_id": state.PeriodID, "last_at_us": at.UnixMicro()}).Error
}

// Configure activates or disables collection. Activation snapshots existing
// enrollment under the same lock used by Track. Disabling closes coverage only;
// it does not revoke devices. Re-enabling reconciles at the new boundary without
// inventing events in the disabled gap. Repeated configuration is idempotent.
func (c Collector) Configure(tx *gorm.DB, accountID string, enabled bool, snapshot Snapshot) error {
	db, state, err := lockCollection(tx, accountID)
	if err != nil || state.Enabled == enabled {
		return err
	}
	at, err := c.timestamp(state)
	if err != nil {
		return err
	}
	if enabled {
		wanted, err := membership(db, snapshot)
		if err != nil {
			return err
		}
		rows, err := activeEnrollments(db, accountID)
		if err != nil {
			return err
		}
		if err := synchronize(db, accountID, at, rows, wanted); err != nil {
			return err
		}
		if err := startPeriod(db, &state, at); err != nil {
			return err
		}
	} else {
		if err := closePeriod(db, state, at, true); err != nil {
			return err
		}
		state.Enabled = false
	}
	return saveCollection(db, state, at)
}

// Track wraps a semantic membership mutation, not individual SQL statements.
// Account save may delete and recreate associations without changing enrollment.
// Every error must abort the caller's transaction. A detected discrepancy needs
// explicit Reconcile before mutation, rather than silently hiding missing data.
func (c Collector) Track(tx *gorm.DB, accountID string, snapshot Snapshot, mutate func(*gorm.DB) error) error {
	db, state, err := lockCollection(tx, accountID)
	if err != nil {
		return err
	}
	if !state.Enabled {
		return mutate(db)
	}
	before, err := membership(db, snapshot)
	if err != nil {
		return err
	}
	rows, err := activeEnrollments(db, accountID)
	if err != nil {
		return err
	}
	if missing, added := difference(rows, before); missing != 0 || added != 0 {
		return fmt.Errorf("%w: membership discrepancy requires reconciliation", ErrConflict)
	}
	if err := mutate(db); err != nil {
		return err
	}
	after, err := membership(db, snapshot)
	if err != nil {
		return err
	}
	at, err := c.timestamp(state)
	if err != nil {
		return err
	}
	if err := synchronize(db, accountID, at, rows, after); err != nil {
		return err
	}
	return saveCollection(db, state, at)
}

// Reconcile repairs current state at the observation boundary, retaining the
// original events and marking the whole affected coverage period incomplete.
// It cannot discover changes that both occurred and were undone outside Track;
// all membership writers must be instrumented before collection is enabled.
func (c Collector) Reconcile(tx *gorm.DB, accountID string, snapshot Snapshot) error {
	db, state, err := lockCollection(tx, accountID)
	if err != nil || !state.Enabled {
		return err
	}
	wanted, err := membership(db, snapshot)
	if err != nil {
		return err
	}
	rows, err := activeEnrollments(db, accountID)
	if err != nil {
		return err
	}
	missing, added := difference(rows, wanted)
	if missing == 0 && added == 0 {
		return nil
	}
	at, err := c.timestamp(state)
	if err != nil {
		return err
	}
	if err := db.Create(&Discrepancy{ID: uuid.NewString(), AccountID: accountID, AtUS: at.UnixMicro(), Missing: missing, Added: added}).Error; err != nil {
		return err
	}
	if err := closePeriod(db, state, at, false); err != nil {
		return err
	}
	if err := synchronize(db, accountID, at, rows, wanted); err != nil {
		return err
	}
	if err := startPeriod(db, &state, at); err != nil {
		return err
	}
	return saveCollection(db, state, at)
}

// Coverage returns account-scoped evidence. Callers must authorize access and
// cap an open interval at the report's snapshot time. Absence is unknown, not
// complete zero usage. This is intentionally not a public API handler.
func Coverage(ctx context.Context, db *gorm.DB, accountID string) ([]Period, error) {
	if !validID(accountID) {
		return nil, ErrInvalid
	}
	var periods []Period
	err := db.WithContext(ctx).Where("account_id = ?", accountID).Order("start_us, id").Find(&periods).Error
	return periods, err
}
