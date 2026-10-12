// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package billing

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/netbirdio/netbird/management/internals/karst/relayusage"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var (
	ErrRelayCapNotConfigured = errors.New("billing: relay spending cap not configured")
	ErrRelayCapConflict      = errors.New("billing: relay spending cap conflicts with stored settings")
	ErrRelayCapDecrease      = errors.New("billing: relay spending cap cannot be safely decreased within this period")
	ErrRelayCapExhausted     = errors.New("billing: relay spending cap has no remaining byte credits")
	ErrCreditRequestConflict = errors.New("billing: relay credit request id reused with different inputs")
	ErrCreditGrantNotFound   = errors.New("billing: relay credit grant not found")
	ErrCreditGrantConflict   = errors.New("billing: relay credit grant conflicts with stored state")
)

type relayCapRow struct {
	AccountID       string    `gorm:"primaryKey;size:128"`
	PeriodStartUS   int64     `gorm:"primaryKey"`
	PeriodEndUS     int64     `gorm:"not null"`
	ScheduleVersion string    `gorm:"size:128;not null"`
	OverageMinor    int64     `gorm:"not null"`
	Revision        uint64    `gorm:"not null"`
	Acknowledged    bool      `gorm:"not null"`
	UpdatedBy       string    `gorm:"size:128;not null"`
	UpdatedAt       time.Time `gorm:"not null"`
}

func (relayCapRow) TableName() string { return "karst_billing_relay_caps" }

type relayCapRevisionRow struct {
	AccountID       string    `gorm:"primaryKey;size:128"`
	PeriodStartUS   int64     `gorm:"primaryKey"`
	Revision        uint64    `gorm:"primaryKey"`
	PeriodEndUS     int64     `gorm:"not null"`
	ScheduleVersion string    `gorm:"size:128;not null"`
	OverageMinor    int64     `gorm:"not null"`
	Acknowledged    bool      `gorm:"not null"`
	Actor           string    `gorm:"size:128;not null"`
	CreatedAt       time.Time `gorm:"not null"`
}

func (relayCapRevisionRow) TableName() string { return "karst_billing_relay_cap_revisions" }

type relayCreditGrantRow struct {
	GrantID         string    `gorm:"primaryKey;size:32"`
	AccountID       string    `gorm:"size:128;not null;uniqueIndex:idx_credit_request"`
	PeriodStartUS   int64     `gorm:"not null;uniqueIndex:idx_credit_request"`
	RelayID         string    `gorm:"size:128;not null;uniqueIndex:idx_credit_request"`
	Generation      string    `gorm:"size:128;not null;uniqueIndex:idx_credit_request"`
	RequestID       string    `gorm:"size:128;not null;uniqueIndex:idx_credit_request"`
	MappingVersion  string    `gorm:"size:128;not null"`
	ScheduleVersion string    `gorm:"size:128;not null"`
	CapRevision     uint64    `gorm:"not null"`
	RequestedBytes  string    `gorm:"size:20;not null"`
	GrantedBytes    string    `gorm:"size:80;not null"`
	ConsumedBytes   string    `gorm:"size:80;not null"`
	State           string    `gorm:"size:16;not null;index"`
	SurrenderDigest string    `gorm:"size:64"`
	CreatedAt       time.Time `gorm:"not null"`
	UpdatedAt       time.Time `gorm:"not null"`
}

func (relayCreditGrantRow) TableName() string { return "karst_billing_relay_credit_grants" }

// RelaySpendingCap is an explicit, acknowledged account-period setting. It
// limits managed-relay overage only; the schedule's included allowance remains
// available without consuming this cap.
type RelaySpendingCap struct {
	AccountID       string    `json:"account_id"`
	PeriodStart     time.Time `json:"period_start"`
	PeriodEnd       time.Time `json:"period_end"`
	ScheduleVersion string    `json:"schedule_version"`
	Currency        string    `json:"currency"`
	OverageMinor    int64     `json:"overage_minor"`
	Revision        uint64    `json:"revision"`
	Acknowledged    bool      `json:"acknowledged_interruption"`
	UpdatedBy       string    `json:"updated_by"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// RelayCreditGrant is an account-period budget reservation bound to one relay
// process generation and mapping version. The relay may use it only before
// PeriodEnd. Grant signing and transport authentication belong to the API edge.
type RelayCreditGrant struct {
	GrantID         string    `json:"grant_id"`
	AccountID       string    `json:"account_id"`
	PeriodStart     time.Time `json:"period_start"`
	PeriodEnd       time.Time `json:"period_end"`
	RelayID         string    `json:"relay_id"`
	Generation      string    `json:"generation"`
	MappingVersion  string    `json:"mapping_version"`
	ScheduleVersion string    `json:"schedule_version"`
	CapRevision     uint64    `json:"cap_revision"`
	RequestedBytes  string    `json:"requested_bytes"`
	GrantedBytes    string    `json:"granted_bytes"`
	CreatedAt       time.Time `json:"created_at"`
}

// SetRelaySpendingCap explicitly enables a managed-relay overage cap. Repeating
// the same request is idempotent. In-period increases create a durable revision.
// A decrease is accepted only after all grants have been surrendered and
// consumed bytes fit beneath the smaller cap; otherwise it is deferred to a
// later period. No default cap is created.
func (s *Store) SetRelaySpendingCap(ctx context.Context, start, end time.Time, overageMinor int64, acknowledged bool, actor string) (RelaySpendingCap, error) {
	accountID, err := billingAccountFromContext(ctx)
	if err != nil {
		return RelaySpendingCap{}, err
	}
	startUS, endUS, err := billingPeriodMicros(start, end)
	if err != nil || !isRelayCapMonth(startUS, endUS) || overageMinor < 0 || !acknowledged || !validToken(actor) {
		return RelaySpendingCap{}, ErrInvalidPeriod
	}
	assignment, err := s.Assignment(ctx, start, end)
	if err != nil {
		return RelaySpendingCap{}, err
	}
	schedule, err := s.Schedule(ctx, assignment.ScheduleVersion)
	if err != nil {
		return RelaySpendingCap{}, err
	}
	if schedule.Currency != "USD" || schedule.RelayMinorPerUnit <= 0 {
		return RelaySpendingCap{}, ErrInvalidRateSchedule
	}
	returnCap := RelaySpendingCap{}
	err = runBillingTransaction(ctx, s.db, func(tx *gorm.DB) error {
		if err := lockBillingAccount(tx, accountID); err != nil {
			return err
		}
		var row relayCapRow
		err := tx.Where("account_id = ? AND period_start_us = ?", accountID, startUS).Take(&row).Error
		now := time.Now().UTC()
		if errors.Is(err, gorm.ErrRecordNotFound) {
			row = relayCapRow{AccountID: accountID, PeriodStartUS: startUS, PeriodEndUS: endUS,
				ScheduleVersion: schedule.Version, OverageMinor: overageMinor, Revision: 1,
				Acknowledged: true, UpdatedBy: actor, UpdatedAt: now}
			if err := tx.Create(&row).Error; err != nil {
				return fmt.Errorf("billing: save relay spending cap: %w", err)
			}
			if err := addRelayCapRevision(tx, row, actor, now); err != nil {
				return err
			}
			returnCap = relayCapDTO(row)
			return nil
		}
		if err != nil {
			return fmt.Errorf("billing: load relay spending cap: %w", err)
		}
		if row.PeriodEndUS != endUS || row.ScheduleVersion != schedule.Version || !row.Acknowledged {
			return ErrRelayCapConflict
		}
		if overageMinor < row.OverageMinor {
			budget, err := maxRelayBytesForOverage(schedule, overageMinor)
			if err != nil {
				return err
			}
			var grants []relayCreditGrantRow
			if err := tx.Where("account_id = ? AND period_start_us = ?", accountID, startUS).Find(&grants).Error; err != nil {
				return fmt.Errorf("billing: verify relay cap decrease: %w", err)
			}
			committed := new(big.Int)
			for _, grant := range grants {
				if grant.State != "surrendered" {
					return ErrRelayCapDecrease
				}
				committed, err = addCanonicalBig(committed, grant.ConsumedBytes)
				if err != nil {
					return err
				}
			}
			if committed.Cmp(budget) > 0 {
				return ErrRelayCapDecrease
			}
		}
		if overageMinor == row.OverageMinor {
			returnCap = relayCapDTO(row)
			return nil
		}
		row.OverageMinor = overageMinor
		row.Revision++
		row.UpdatedBy = actor
		row.UpdatedAt = now
		if err := tx.Save(&row).Error; err != nil {
			return fmt.Errorf("billing: increase relay spending cap: %w", err)
		}
		if err := addRelayCapRevision(tx, row, actor, now); err != nil {
			return err
		}
		returnCap = relayCapDTO(row)
		return nil
	})
	return returnCap, err
}

// RelaySpendingCap reads only the explicit setting for the authenticated
// account and exact UTC calendar month.
func (s *Store) RelaySpendingCap(ctx context.Context, start, end time.Time) (RelaySpendingCap, error) {
	accountID, err := billingAccountFromContext(ctx)
	if err != nil {
		return RelaySpendingCap{}, err
	}
	startUS, endUS, err := billingPeriodMicros(start, end)
	if err != nil || !isRelayCapMonth(startUS, endUS) {
		return RelaySpendingCap{}, ErrInvalidPeriod
	}
	var row relayCapRow
	if err := s.db.WithContext(ctx).Where("account_id = ? AND period_start_us = ?", accountID, startUS).Take(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return RelaySpendingCap{}, ErrRelayCapNotConfigured
		}
		return RelaySpendingCap{}, fmt.Errorf("billing: read relay spending cap: %w", err)
	}
	if row.PeriodEndUS != endUS {
		return RelaySpendingCap{}, ErrRelayCapNotConfigured
	}
	return relayCapDTO(row), nil
}

// ReserveRelayCredits atomically reserves at most requestedBytes from the
// organization-period budget. A stable request ID makes retries idempotent
// across all relays in the account. Unreturned grants remain fully reserved.
func (s *Store) ReserveRelayCredits(ctx context.Context, start, end time.Time, relayID, generation, mappingVersion, requestID string, requestedBytes uint64) (RelayCreditGrant, error) {
	accountID, err := billingAccountFromContext(ctx)
	if err != nil {
		return RelayCreditGrant{}, err
	}
	startUS, endUS, err := billingPeriodMicros(start, end)
	if err != nil || !isRelayCapMonth(startUS, endUS) || !validToken(relayID) || !validToken(generation) || !validToken(mappingVersion) || !validToken(requestID) || requestedBytes == 0 {
		return RelayCreditGrant{}, ErrInvalidPeriod
	}
	returnGrant := RelayCreditGrant{}
	err = runBillingTransaction(ctx, s.db, func(tx *gorm.DB) error {
		if err := lockBillingAccount(tx, accountID); err != nil {
			return err
		}
		var cap relayCapRow
		if err := tx.Where("account_id = ? AND period_start_us = ?", accountID, startUS).Take(&cap).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrRelayCapNotConfigured
			}
			return fmt.Errorf("billing: load relay spending cap: %w", err)
		}
		if cap.PeriodEndUS != endUS || !cap.Acknowledged {
			return ErrRelayCapConflict
		}
		var existing relayCreditGrantRow
		err := tx.Where("account_id = ? AND period_start_us = ? AND relay_id = ? AND generation = ? AND request_id = ?", accountID, startUS, relayID, generation, requestID).Take(&existing).Error
		if err == nil {
			if existing.MappingVersion != mappingVersion || existing.RequestedBytes != new(big.Int).SetUint64(requestedBytes).String() || existing.ScheduleVersion != cap.ScheduleVersion {
				return ErrCreditRequestConflict
			}
			returnGrant = relayGrantDTO(existing, endUS)
			return nil
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("billing: check relay credit request: %w", err)
		}
		assignment, err := (&Store{db: tx}).Assignment(ctx, start, end)
		if err != nil || assignment.ScheduleVersion != cap.ScheduleVersion {
			return ErrScheduleUnassigned
		}
		schedule, err := (&Store{db: tx}).Schedule(ctx, cap.ScheduleVersion)
		if err != nil {
			return err
		}
		budget, err := maxRelayBytesForOverage(schedule, cap.OverageMinor)
		if err != nil {
			return err
		}
		var grants []relayCreditGrantRow
		if err := tx.Where("account_id = ? AND period_start_us = ?", accountID, startUS).Find(&grants).Error; err != nil {
			return fmt.Errorf("billing: sum relay credit reservations: %w", err)
		}
		committed := new(big.Int)
		for _, grant := range grants {
			if grant.State == "issued" {
				committed, err = addCanonicalBig(committed, grant.GrantedBytes)
			} else if grant.State == "surrendered" {
				committed, err = addCanonicalBig(committed, grant.ConsumedBytes)
			} else {
				return errors.New("billing: unknown relay credit grant state")
			}
			if err != nil {
				return err
			}
		}
		available := new(big.Int).Sub(budget, committed)
		if available.Sign() <= 0 {
			return ErrRelayCapExhausted
		}
		grantBytes := new(big.Int).SetUint64(requestedBytes)
		if grantBytes.Cmp(available) > 0 {
			grantBytes.Set(available)
		}
		idBytes := make([]byte, 16)
		if _, err := rand.Read(idBytes); err != nil {
			return fmt.Errorf("billing: generate relay grant ID: %w", err)
		}
		now := time.Now().UTC()
		row := relayCreditGrantRow{
			GrantID: hex.EncodeToString(idBytes), AccountID: accountID, PeriodStartUS: startUS,
			RelayID: relayID, Generation: generation, RequestID: requestID, MappingVersion: mappingVersion,
			ScheduleVersion: schedule.Version, CapRevision: cap.Revision,
			RequestedBytes: new(big.Int).SetUint64(requestedBytes).String(), GrantedBytes: grantBytes.String(), ConsumedBytes: "0",
			State: "issued", CreatedAt: now, UpdatedAt: now,
		}
		if err := tx.Create(&row).Error; err != nil {
			return fmt.Errorf("billing: reserve relay credits: %w", err)
		}
		returnGrant = relayGrantDTO(row, endUS)
		return nil
	})
	return returnGrant, err
}

// ReserveAuthorizedRelayCredits verifies the relay identity and its currently
// enabled operator mapping in the same outer transaction that reserves the
// account-wide credits. A mapping revocation cannot race between validation
// and issuance.
func (s *Store) ReserveAuthorizedRelayCredits(ctx context.Context, relayStore *relayusage.Store, start, end time.Time, request relayusage.CreditRequest) (RelayCreditGrant, error) {
	if relayStore == nil {
		return RelayCreditGrant{}, ErrCreditGrantConflict
	}
	requestedBytes, err := relayusage.DecodeRequestedCreditBytes(request)
	if err != nil {
		return RelayCreditGrant{}, err
	}
	var grant RelayCreditGrant
	err = runBillingTransaction(ctx, s.db, func(tx *gorm.DB) error {
		mapping, err := relayStore.WithDB(tx).AuthorizeCreditRequest(ctx, request)
		if err != nil {
			return err
		}
		accountCtx := WithAccount(ctx, mapping.AccountID)
		grant, err = (&Store{db: tx}).ReserveRelayCredits(accountCtx, start, end,
			request.RelayID, request.Generation, request.MappingVersion, request.RequestID, requestedBytes)
		return err
	})
	return grant, err
}

// SurrenderRelayCredits releases unused credits only after the API has
// authenticated the relay's durable surrender or generation fence. consumed
// bytes remain charged to the cap budget. Replays with the same report digest
// are idempotent; conflicting reports are rejected.
func (s *Store) SurrenderRelayCredits(ctx context.Context, grantID, relayID, generation, consumedBytes, surrenderDigest string) (RelayCreditGrant, error) {
	accountID, err := billingAccountFromContext(ctx)
	if err != nil {
		return RelayCreditGrant{}, err
	}
	if !validLowerHex(grantID, 16) || !validToken(relayID) || !validToken(generation) || !validLowerHex(surrenderDigest, 32) {
		return RelayCreditGrant{}, ErrCreditGrantConflict
	}
	consumed, ok := new(big.Int).SetString(consumedBytes, 10)
	if !ok || consumed.Sign() < 0 || consumed.String() != consumedBytes {
		return RelayCreditGrant{}, ErrCreditGrantConflict
	}
	var output RelayCreditGrant
	err = runBillingTransaction(ctx, s.db, func(tx *gorm.DB) error {
		if err := lockBillingAccount(tx, accountID); err != nil {
			return err
		}
		var row relayCreditGrantRow
		if err := tx.Where("grant_id = ? AND account_id = ?", grantID, accountID).Take(&row).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrCreditGrantNotFound
			}
			return fmt.Errorf("billing: load relay credit grant: %w", err)
		}
		if row.RelayID != relayID || row.Generation != generation {
			return ErrCreditGrantNotFound
		}
		granted, ok := new(big.Int).SetString(row.GrantedBytes, 10)
		if !ok || consumed.Cmp(granted) > 0 {
			return ErrCreditGrantConflict
		}
		if row.State == "surrendered" {
			if row.ConsumedBytes != consumedBytes || row.SurrenderDigest != surrenderDigest {
				return ErrCreditGrantConflict
			}
			var cap relayCapRow
			if err := tx.Where("account_id = ? AND period_start_us = ?", accountID, row.PeriodStartUS).Take(&cap).Error; err != nil {
				return err
			}
			output = relayGrantDTO(row, cap.PeriodEndUS)
			return nil
		}
		if row.State != "issued" {
			return ErrCreditGrantConflict
		}
		row.State = "surrendered"
		row.ConsumedBytes = consumedBytes
		row.SurrenderDigest = surrenderDigest
		row.UpdatedAt = time.Now().UTC()
		if err := tx.Save(&row).Error; err != nil {
			return fmt.Errorf("billing: surrender relay credit grant: %w", err)
		}
		var cap relayCapRow
		if err := tx.Where("account_id = ? AND period_start_us = ?", accountID, row.PeriodStartUS).Take(&cap).Error; err != nil {
			return err
		}
		output = relayGrantDTO(row, cap.PeriodEndUS)
		return nil
	})
	return output, err
}

func runBillingTransaction(ctx context.Context, db *gorm.DB, fn func(*gorm.DB) error) error {
	const maxRetries = 6
	for attempt := 0; ; attempt++ {
		err := db.WithContext(ctx).Transaction(fn, &sql.TxOptions{Isolation: sql.LevelSerializable})
		if err == nil || !retryableBillingTransaction(err) || attempt >= maxRetries {
			return err
		}
		delay := time.Duration(5*(1<<attempt)) * time.Millisecond
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func retryableBillingTransaction(err error) bool {
	message := strings.ToLower(err.Error())
	if strings.Contains(message, "database is locked") || strings.Contains(message, "database table is locked") ||
		strings.Contains(message, "serialization failure") || strings.Contains(message, "deadlock detected") {
		return true
	}
	type sqlStateError interface{ SQLState() string }
	var stateErr sqlStateError
	if errors.As(err, &stateErr) {
		return stateErr.SQLState() == "40001" || stateErr.SQLState() == "40P01"
	}
	return false
}

func validLowerHex(value string, bytes int) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == bytes && hex.EncodeToString(decoded) == value
}

func lockBillingAccount(tx *gorm.DB, accountID string) error {
	guard := billingAccountLock{AccountID: accountID}
	if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&guard).Error; err != nil {
		return fmt.Errorf("billing: lock account cap budget: %w", err)
	}
	var locked billingAccountLock
	if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("account_id = ?", accountID).Take(&locked).Error; err != nil {
		return fmt.Errorf("billing: lock account cap budget: %w", err)
	}
	return nil
}

func isRelayCapMonth(startUS, endUS int64) bool {
	start, end := time.UnixMicro(startUS).UTC(), time.UnixMicro(endUS).UTC()
	return start.Day() == 1 && start.Hour() == 0 && start.Minute() == 0 && start.Second() == 0 && start.Nanosecond() == 0 && end.Equal(start.AddDate(0, 1, 0))
}

func maxRelayBytesForOverage(schedule RateSchedule, overageMinor int64) (*big.Int, error) {
	if err := validateRateSchedule(schedule); err != nil || overageMinor < 0 || schedule.RelayMinorPerUnit == 0 {
		return nil, ErrInvalidRateSchedule
	}
	overageBytes := new(big.Int).Mul(big.NewInt(overageMinor), new(big.Int).SetUint64(schedule.RelayUnitBytes))
	overageBytes.Quo(overageBytes, big.NewInt(schedule.RelayMinorPerUnit))
	return new(big.Int).Add(new(big.Int).SetUint64(schedule.RelayIncludedBytes), overageBytes), nil
}

func addCanonicalBig(total *big.Int, decimal string) (*big.Int, error) {
	value, ok := new(big.Int).SetString(decimal, 10)
	if !ok || value.Sign() < 0 || value.String() != decimal {
		return nil, errors.New("billing: invalid persisted relay credit amount")
	}
	return new(big.Int).Add(total, value), nil
}

func relayCapDTO(row relayCapRow) RelaySpendingCap {
	return RelaySpendingCap{AccountID: row.AccountID, PeriodStart: time.UnixMicro(row.PeriodStartUS).UTC(), PeriodEnd: time.UnixMicro(row.PeriodEndUS).UTC(),
		ScheduleVersion: row.ScheduleVersion, Currency: "USD", OverageMinor: row.OverageMinor, Revision: row.Revision,
		Acknowledged: row.Acknowledged, UpdatedBy: row.UpdatedBy, UpdatedAt: row.UpdatedAt}
}

func relayGrantDTO(row relayCreditGrantRow, endUS int64) RelayCreditGrant {
	return RelayCreditGrant{GrantID: row.GrantID, AccountID: row.AccountID, PeriodStart: time.UnixMicro(row.PeriodStartUS).UTC(), PeriodEnd: time.UnixMicro(endUS).UTC(),
		RelayID: row.RelayID, Generation: row.Generation, MappingVersion: row.MappingVersion, ScheduleVersion: row.ScheduleVersion,
		CapRevision: row.CapRevision, RequestedBytes: row.RequestedBytes, GrantedBytes: row.GrantedBytes, CreatedAt: row.CreatedAt}
}

func addRelayCapRevision(tx *gorm.DB, row relayCapRow, actor string, now time.Time) error {
	revision := relayCapRevisionRow{AccountID: row.AccountID, PeriodStartUS: row.PeriodStartUS, Revision: row.Revision,
		PeriodEndUS: row.PeriodEndUS, ScheduleVersion: row.ScheduleVersion, OverageMinor: row.OverageMinor,
		Acknowledged: row.Acknowledged, Actor: actor, CreatedAt: now}
	if err := tx.Create(&revision).Error; err != nil {
		return fmt.Errorf("billing: record relay cap revision: %w", err)
	}
	return nil
}
