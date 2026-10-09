// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// Package usage provides the device lifecycle ledger proposed in ADR-0050.
// It is not wired to production: coverage activation and all membership
// mutation paths must be integrated before these records represent usage.
package usage

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Kind describes a change to an enrollment generation, independent of whether
// the device is online. Key rotation and reconnect do not create changes.
type Kind string

const (
	Enrolled Kind = "enrolled"
	Revoked  Kind = "revoked"
)

var (
	ErrInvalid     = errors.New("usage: invalid lifecycle change")
	ErrConflict    = errors.New("usage: lifecycle conflict")
	ErrTransaction = errors.New("usage: membership transaction required")
)

// Change is an immutable event. ID is the caller's stable retry key, scoped to
// AccountID. GenerationID identifies one enrollment, not a reusable device key.
// At must be UTC-representable, at or after the Unix epoch, with microsecond
// precision; rejecting sub-microsecond input prevents silent boundary rounding.
type Change struct {
	ID           string
	AccountID    string
	GenerationID string
	Kind         Kind
	At           time.Time
}

type stream struct {
	AccountID string `gorm:"primaryKey;size:128"`
	Sequence  int64
	LastAtUS  int64
}

func (stream) TableName() string { return "karst_usage_device_streams" }

type event struct {
	AccountID    string `gorm:"primaryKey;size:128;uniqueIndex:usage_generation_kind,priority:1"`
	ID           string `gorm:"primaryKey;size:128"`
	Sequence     int64  `gorm:"not null;index"`
	GenerationID string `gorm:"size:128;not null;uniqueIndex:usage_generation_kind,priority:2"`
	Kind         Kind   `gorm:"size:16;not null;uniqueIndex:usage_generation_kind,priority:3"`
	AtUS         int64  `gorm:"not null;index"`
}

func (event) TableName() string { return "karst_usage_device_events" }

// Migrate creates the additive ledger tables. Bootstrap intentionally does not
// call this yet. Tables have no cascading foreign keys to live membership: a
// deletion must not destroy historical evidence.
func Migrate(db *gorm.DB) error {
	return db.AutoMigrate(&stream{}, &event{})
}

func validTime(t time.Time) bool {
	return !t.Before(time.Unix(0, 0)) && t.Year() <= 9999 && t.Nanosecond()%1000 == 0
}

func validID(s string) bool { return len(s) > 0 && len(s) <= 128 }

// Append records c in the SAME database transaction as the authoritative
// membership mutation. The caller must propagate every error and roll back the
// transaction; passing a normal database handle is rejected. It neither starts
// nor commits a transaction and must not be called as a post-commit callback.
//
// Per-account writes serialize on a stream row. Retry a serialization/deadlock
// failure by retrying the entire membership transaction. A committed event can
// be replayed with identical content even after later events have been written.
func Append(tx *gorm.DB, c Change) error {
	if tx == nil || tx.Statement == nil {
		return ErrTransaction
	}
	if _, ok := tx.Statement.ConnPool.(gorm.TxCommitter); !ok {
		return ErrTransaction
	}
	if !validID(c.ID) || !validID(c.AccountID) || !validID(c.GenerationID) ||
		(c.Kind != Enrolled && c.Kind != Revoked) || !validTime(c.At) {
		return ErrInvalid
	}
	// Clear caller query clauses while retaining its connection and context.
	db := tx.Session(&gorm.Session{NewDB: true})
	if err := db.Clauses(clause.OnConflict{DoNothing: true}).Create(&stream{AccountID: c.AccountID}).Error; err != nil {
		return err
	}
	// A write locks this row on supported SQL engines, including SQLite where
	// SELECT FOR UPDATE is unavailable. Lock before reading event/state data.
	if err := db.Model(&stream{}).Where("account_id = ?", c.AccountID).
		UpdateColumn("sequence", gorm.Expr("sequence + 0")).Error; err != nil {
		return err
	}
	// Locking reads also avoid an older repeatable-read snapshot on MySQL
	// when the membership transaction read other tables before this call.
	var prior event
	err := db.Clauses(clause.Locking{Strength: "UPDATE"}).
		Where("account_id = ? AND id = ?", c.AccountID, c.ID).Take(&prior).Error
	if err == nil {
		if prior.GenerationID == c.GenerationID && prior.Kind == c.Kind && prior.AtUS == c.At.UnixMicro() {
			return nil
		}
		return fmt.Errorf("%w: retry key has different content", ErrConflict)
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}
	var state stream
	if err := db.Clauses(clause.Locking{Strength: "UPDATE"}).Where("account_id = ?", c.AccountID).Take(&state).Error; err != nil {
		return err
	}
	if c.At.UnixMicro() < state.LastAtUS || state.Sequence == math.MaxInt64 {
		return fmt.Errorf("%w: regressing timestamp or exhausted sequence", ErrConflict)
	}
	var history []event
	if err := db.Clauses(clause.Locking{Strength: "UPDATE"}).
		Where("account_id = ? AND generation_id = ?", c.AccountID, c.GenerationID).
		Order("sequence").Find(&history).Error; err != nil {
		return err
	}
	if (c.Kind == Enrolled && len(history) != 0) ||
		(c.Kind == Revoked && (len(history) != 1 || history[0].Kind != Enrolled)) {
		return fmt.Errorf("%w: invalid enrollment transition", ErrConflict)
	}
	row := event{AccountID: c.AccountID, ID: c.ID, Sequence: state.Sequence + 1,
		GenerationID: c.GenerationID, Kind: c.Kind, AtUS: c.At.UnixMicro()}
	if err := db.Create(&row).Error; err != nil {
		return err
	}
	return db.Model(&stream{}).Where("account_id = ?", c.AccountID).
		Updates(map[string]any{"sequence": row.Sequence, "last_at_us": row.AtUS}).Error
}

// Segment is a half-open interval with a constant eligible device count. Equal
// timestamp changes are coalesced. Keeping this timeline (rather than only an
// average) permits graduated pricing to be defined later without losing data.
type Segment struct {
	Start   time.Time
	End     time.Time
	Devices int64
}

// Timeline reconstructs only recorded lifecycle state in [start, end). This is
// an INTERNAL evidence query, not a billing report: it makes no claim that the
// window has collection coverage. Callers must authorize account access and
// intersect with collection coverage before reporting billable usage. An empty
// ledger therefore must never be presented to a customer as complete zero use.
func Timeline(ctx context.Context, db *gorm.DB, accountID string, start, end time.Time) ([]Segment, error) {
	if !validID(accountID) || !validTime(start) || !validTime(end) || !start.Before(end) {
		return nil, ErrInvalid
	}
	// One ordered statement gives a consistent event set without mixing a
	// separately queried opening count with concurrently committed events.
	var rows []event
	if err := db.WithContext(ctx).Where("account_id = ? AND at_us < ?", accountID, end.UnixMicro()).
		Order("sequence").Find(&rows).Error; err != nil {
		return nil, err
	}
	cursor := start.UTC()
	var count int64
	var segments []Segment
	for _, row := range rows {
		at := time.UnixMicro(row.AtUS).UTC()
		if at.After(cursor) {
			segments = append(segments, Segment{Start: cursor, End: at, Devices: count})
			cursor = at
		}
		switch row.Kind {
		case Enrolled:
			if count == math.MaxInt64 {
				return nil, ErrConflict
			}
			count++
		case Revoked:
			count--
		default:
			return nil, ErrConflict
		}
		if count < 0 {
			return nil, ErrConflict
		}
	}
	segments = append(segments, Segment{Start: cursor, End: end.UTC(), Devices: count})
	// Changes at the same instant can leave the count unchanged. Merge their
	// adjacent segments without returning zero-length or redundant intervals.
	merged := segments[:0]
	for _, segment := range segments {
		if len(merged) > 0 && merged[len(merged)-1].Devices == segment.Devices {
			merged[len(merged)-1].End = segment.End
		} else {
			merged = append(merged, segment)
		}
	}
	return merged, nil
}
