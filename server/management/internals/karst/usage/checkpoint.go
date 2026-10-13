// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package usage

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"math"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// deviceCheckpoint preserves the count needed to open future reports after a
// finalized invoice period's raw membership events are pruned. Checkpoints are
// immutable and form a SHA-256 chain over the source event ledger.
type deviceCheckpoint struct {
	AccountID      string    `gorm:"primaryKey;size:128"`
	Sequence       int64     `gorm:"primaryKey"`
	BoundaryUS     int64     `gorm:"not null"`
	DeviceCount    int64     `gorm:"not null"`
	PreviousSeq    int64     `gorm:"not null"`
	PreviousDigest string    `gorm:"size:64;not null"`
	RangeDigest    string    `gorm:"size:64;not null"`
	SourceDigest   string    `gorm:"size:64;not null"`
	CreatedAt      time.Time `gorm:"not null"`
}

func (deviceCheckpoint) TableName() string { return "karst_usage_device_checkpoints" }

// PruneFinalizedPeriod checkpoints the account's event ledger and removes the
// raw events in one already-finalized UTC calendar month after the approved
// retention window. Callers must supply the finalization time from a verified,
// immutable invoice record. An absent or invalid invoice must never be treated
// as permission to prune.
//
// The checkpoint is committed before deletion in the same transaction. It
// records the device count and sequence at the period boundary and a digest of
// the source ledger prefix. Other periods' raw events remain until their own
// invoice retention window expires.
func PruneFinalizedPeriod(ctx context.Context, db *gorm.DB, accountID string, periodStart, periodEnd, finalizedAt, now time.Time) (int64, error) {
	if db == nil || !validID(accountID) || !validCalendarMonth(periodStart, periodEnd) ||
		finalizedAt.IsZero() || finalizedAt.Before(periodEnd) || now.IsZero() {
		return 0, ErrInvalid
	}
	periodStart, periodEnd, finalizedAt, now = periodStart.UTC(), periodEnd.UTC(), finalizedAt.UTC(), now.UTC()
	if now.Before(finalizedAt) || now.Before(periodEnd.AddDate(0, 13, 0)) {
		return 0, errors.New("usage: device event retention window has not elapsed")
	}
	startUS, endUS := periodStart.UnixMicro(), periodEnd.UnixMicro()
	boundaryUS := endUS - 1 // Periods are microsecond aligned and half-open.
	var removed int64
	err := db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Appends acquire the same stream-row write lock. This prevents a late
		// membership event from landing inside the checkpoint boundary while
		// the event range is verified and pruned.
		var state stream
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("account_id = ?", accountID).Take(&state).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil
			}
			return err
		}
		if err := tx.Model(&stream{}).Where("account_id = ?", accountID).
			UpdateColumn("sequence", gorm.Expr("sequence + 0")).Error; err != nil {
			return err
		}

		checkpoints, err := readCheckpoints(tx, accountID)
		if err != nil {
			return err
		}
		latest := checkpointState{}
		if len(checkpoints) != 0 {
			latest = checkpoints[len(checkpoints)-1]
		}
		if latest.Sequence > state.Sequence {
			return ErrCheckpoint
		}

		var inPeriod int64
		if err := tx.Model(&event{}).Where("account_id = ? AND at_us >= ? AND at_us < ?", accountID, startUS, endUS).Count(&inPeriod).Error; err != nil {
			return err
		}
		if inPeriod == 0 {
			return nil
		}

		if boundaryUS > latest.BoundaryUS {
			var newCheckpoint *deviceCheckpoint
			newCheckpoint, err = buildCheckpoint(tx, accountID, state, latest, boundaryUS)
			if err != nil {
				return err
			}
			if newCheckpoint != nil {
				if err := tx.Create(newCheckpoint).Error; err != nil {
					return err
				}
			}
		}

		result := tx.Where("account_id = ? AND at_us >= ? AND at_us < ?", accountID, startUS, endUS).Delete(&event{})
		if result.Error != nil {
			return result.Error
		}
		removed = result.RowsAffected
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("usage: checkpoint and prune device events: %w", err)
	}
	return removed, nil
}

func validCalendarMonth(start, end time.Time) bool {
	if !validTime(start) || !validTime(end) {
		return false
	}
	start, end = start.UTC(), end.UTC()
	return start.Day() == 1 && start.Hour() == 0 && start.Minute() == 0 && start.Second() == 0 && start.Nanosecond() == 0 &&
		end.Equal(start.AddDate(0, 1, 0))
}

type checkpointState struct {
	Sequence     int64
	BoundaryUS   int64
	DeviceCount  int64
	SourceDigest string
}

func readCheckpoints(db *gorm.DB, accountID string) ([]checkpointState, error) {
	var rows []deviceCheckpoint
	if err := db.Where("account_id = ?", accountID).Order("sequence").Find(&rows).Error; err != nil {
		return nil, err
	}
	previous := checkpointState{}
	for _, row := range rows {
		if row.PreviousSeq != previous.Sequence || row.Sequence <= previous.Sequence || row.BoundaryUS <= previous.BoundaryUS ||
			row.DeviceCount < 0 || !validDigest(row.RangeDigest) ||
			row.PreviousDigest != previous.SourceDigest || !validDigest(row.SourceDigest) ||
			checkpointDigest(accountID, row.PreviousSeq, row.PreviousDigest, row.Sequence, row.BoundaryUS, row.DeviceCount, row.RangeDigest) != row.SourceDigest {
			return nil, ErrCheckpoint
		}
		previous = checkpointState{Sequence: row.Sequence, BoundaryUS: row.BoundaryUS, DeviceCount: row.DeviceCount, SourceDigest: row.SourceDigest}
	}
	return rowsToStates(rows), nil
}

func rowsToStates(rows []deviceCheckpoint) []checkpointState {
	states := make([]checkpointState, len(rows))
	for index, row := range rows {
		states[index] = checkpointState{Sequence: row.Sequence, BoundaryUS: row.BoundaryUS, DeviceCount: row.DeviceCount, SourceDigest: row.SourceDigest}
	}
	return states
}

func validDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && hex.EncodeToString(decoded) == value
}

func buildCheckpoint(db *gorm.DB, accountID string, streamState stream, previous checkpointState, boundaryUS int64) (*deviceCheckpoint, error) {
	rows, err := db.Model(&event{}).Where("account_id = ? AND sequence > ? AND at_us <= ?", accountID, previous.Sequence, boundaryUS).
		Order("sequence").Rows()
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	h := sha256.New()
	count := previous.DeviceCount
	sequence := previous.Sequence
	for rows.Next() {
		var row event
		if err := db.ScanRows(rows, &row); err != nil {
			return nil, err
		}
		if row.Sequence != sequence+1 || row.AccountID != accountID {
			return nil, ErrCheckpoint
		}
		if err := digestEvent(h, row); err != nil {
			return nil, err
		}
		switch row.Kind {
		case Enrolled:
			if count == math.MaxInt64 {
				return nil, ErrCheckpoint
			}
			count++
		case Revoked:
			count--
		default:
			return nil, ErrCheckpoint
		}
		if count < 0 {
			return nil, ErrCheckpoint
		}
		sequence = row.Sequence
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if sequence > streamState.Sequence {
		return nil, ErrCheckpoint
	}
	if sequence == previous.Sequence {
		return nil, nil
	}
	rangeDigest := hex.EncodeToString(h.Sum(nil))
	sourceDigest := checkpointDigest(accountID, previous.Sequence, previous.SourceDigest, sequence, boundaryUS, count, rangeDigest)
	return &deviceCheckpoint{
		AccountID: accountID, Sequence: sequence, BoundaryUS: boundaryUS, DeviceCount: count,
		PreviousSeq: previous.Sequence, PreviousDigest: previous.SourceDigest, RangeDigest: rangeDigest,
		SourceDigest: sourceDigest, CreatedAt: time.Now().UTC(),
	}, nil
}

func checkpointDigest(accountID string, previousSequence int64, previousDigest string, sequence, boundaryUS, deviceCount int64, rangeDigest string) string {
	h := sha256.New()
	writeString(h, "karst-device-usage-checkpoint-v1")
	writeString(h, accountID)
	writeInt64(h, previousSequence)
	writeString(h, previousDigest)
	writeInt64(h, sequence)
	writeInt64(h, boundaryUS)
	writeInt64(h, deviceCount)
	writeString(h, rangeDigest)
	return hex.EncodeToString(h.Sum(nil))
}

func digestEvent(h hash.Hash, row event) error {
	writeString(h, row.AccountID)
	writeString(h, row.ID)
	writeInt64(h, row.Sequence)
	writeString(h, row.GenerationID)
	writeString(h, string(row.Kind))
	writeInt64(h, row.AtUS)
	return nil
}

func writeString(h hash.Hash, value string) {
	writeInt64(h, int64(len(value)))
	_, _ = h.Write([]byte(value))
}

func writeInt64(h hash.Hash, value int64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], uint64(value))
	_, _ = h.Write(encoded[:])
}

func checkpointAt(db *gorm.DB, accountID string, atUS int64) (checkpointState, error) {
	rows, err := readCheckpoints(db, accountID)
	if err != nil {
		return checkpointState{}, err
	}
	var selected checkpointState
	for _, row := range rows {
		if row.BoundaryUS > atUS {
			break
		}
		selected = row
	}
	return selected, nil
}

func openingCount(db *gorm.DB, accountID string, atUS int64, checkpoint checkpointState) (int64, int64, error) {
	var aggregate struct {
		RowCount    int64
		MaxSequence *int64
		DeltaCount  *int64
	}
	if err := db.Model(&event{}).Select("COUNT(*) AS row_count, MAX(sequence) AS max_sequence, COALESCE(SUM(CASE WHEN kind = ? THEN 1 ELSE -1 END), 0) AS delta_count", Enrolled).
		Where("account_id = ? AND sequence > ? AND at_us <= ?", accountID, checkpoint.Sequence, atUS).Scan(&aggregate).Error; err != nil {
		return 0, 0, err
	}
	if aggregate.MaxSequence != nil && aggregate.RowCount != *aggregate.MaxSequence-checkpoint.Sequence {
		return 0, 0, ErrCheckpoint
	}
	count := checkpoint.DeviceCount
	sequence := checkpoint.Sequence
	if aggregate.DeltaCount != nil {
		if (*aggregate.DeltaCount > 0 && count > math.MaxInt64-*aggregate.DeltaCount) || (*aggregate.DeltaCount < 0 && count < -*aggregate.DeltaCount) {
			return 0, 0, ErrCheckpoint
		}
		count += *aggregate.DeltaCount
	}
	if aggregate.MaxSequence != nil {
		sequence = *aggregate.MaxSequence
	}
	if count < 0 {
		return 0, 0, ErrCheckpoint
	}
	return count, sequence, nil
}
