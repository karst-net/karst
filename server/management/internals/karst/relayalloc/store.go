// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// Package relayalloc stores an administrator's manual relay allocation
// request (ADR-0063, issue #455): name, infrastructure connection,
// location, requested capabilities, and permitted groups, plus a durable
// state machine (requested -> provisioning -> granting -> ready, or ->
// failed from any step; ready/failed -> revoking -> deprovisioning ->
// deprovisioned on teardown). Create persists the requested record in one
// local transaction with no provider call inside it -- the same discipline
// relayservice.UpdateAccess already follows, for the same reason: a
// provider call can take minutes and must never hold a DB transaction open.
// Driving a requested record forward (calling a karst-scaler Driver,
// minting an enroll token, calling relayservice to grant or revoke access)
// is the Rust reconciliation loop's job (ADR-0063), not this package's --
// this package only exposes the compare-and-set Transition/RequestDeprovision
// primitives that loop calls through, plus Create/List/Delete for the
// console.
package relayalloc

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/rs/xid"
	"gorm.io/gorm"

	"github.com/netbirdio/netbird/management/internals/karst/infraconnections"
	"github.com/netbirdio/netbird/management/server/types"
)

var (
	ErrNoAccount = errors.New("relay allocation: account scope missing")
	ErrInvalid   = errors.New("relay allocation: invalid allocation")
	ErrExists    = errors.New("relay allocation: allocation changed; reload before saving")
	ErrNotFound  = errors.New("relay allocation: allocation not found")
)

// State is the allocation's own lifecycle, independent of both the
// scaler's pool state and relayservice's access state (ADR-0063's
// "Alternatives rejected").
const (
	StateRequested      = "requested"
	StateProvisioning   = "provisioning"
	StateGranting       = "granting"
	StateReady          = "ready"
	StateRevoking       = "revoking"
	StateDeprovisioning = "deprovisioning"
	StateDeprovisioned  = "deprovisioned"
	StateFailed         = "failed"
)

type accountKey struct{}

func WithAccount(ctx context.Context, account string) context.Context {
	return context.WithValue(ctx, accountKey{}, account)
}

func accountFromContext(ctx context.Context) (string, error) {
	account, _ := ctx.Value(accountKey{}).(string)
	if strings.TrimSpace(account) == "" {
		return "", ErrNoAccount
	}
	return account, nil
}

// Allocation is the durable record ADR-0063 describes. FailedStep and
// FailureReason are only meaningful while State == StateFailed; every other
// transition clears both rather than leaving a stale reason behind.
type Allocation struct {
	AccountID         string    `gorm:"primaryKey;size:64" json:"-"`
	ID                string    `gorm:"primaryKey;size:64" json:"id"`
	Name              string    `gorm:"not null" json:"name"`
	InfraConnectionID string    `gorm:"not null" json:"infra_connection_id"`
	Location          string    `gorm:"not null" json:"location"`
	RelayTransport    bool      `json:"relay_transport,omitempty"`
	EgressV4          bool      `json:"egress_v4,omitempty"`
	EgressV6          bool      `json:"egress_v6,omitempty"`
	PermittedGroups   []string  `gorm:"serializer:json" json:"permitted_groups,omitempty"`
	State             string    `gorm:"not null;index" json:"state"`
	FailedStep        string    `json:"failed_step,omitempty"`
	FailureReason     string    `json:"failure_reason,omitempty"`
	InstanceID        string    `json:"instance_id,omitempty"`
	RelayID           string    `json:"relay_id,omitempty"`
	Revision          uint64    `gorm:"not null;default:0" json:"revision"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

func (Allocation) TableName() string { return "karst_relay_allocations" }

// AllocationHistory is the append-only transition audit trail -- mirrors
// billing's paymentHistoryRow, the closest existing precedent for a
// multi-step provider-backed state machine in this codebase.
type AllocationHistory struct {
	ID           uint   `gorm:"primaryKey"`
	AccountID    string `gorm:"index"`
	AllocationID string `gorm:"index"`
	FromState    string
	ToState      string
	Reason       string
	CreatedAt    time.Time `gorm:"index"`
}

func (AllocationHistory) TableName() string { return "karst_relay_allocation_history" }

type Store struct {
	db *gorm.DB
}

func NewStore(db *gorm.DB) (*Store, error) {
	if db == nil {
		return nil, fmt.Errorf("relay allocation: nil database")
	}
	if err := db.AutoMigrate(&Allocation{}, &AllocationHistory{}); err != nil {
		return nil, err
	}
	return &Store{db: db}, nil
}

// validAllocationTransition is the explicit transition-graph allow-list
// ADR-0063 specifies, mirroring billing's validPaymentTransition. Retrying
// a failed allocation forward is deliberately not offered here: the ADR
// only describes forward provisioning/granting and a revoke-then-destroy
// teardown, never a resume-in-place; an administrator retries by
// deprovisioning a failed allocation and allocating again.
func validAllocationTransition(from, to string) bool {
	switch from {
	case StateRequested:
		return to == StateProvisioning || to == StateFailed
	case StateProvisioning:
		return to == StateGranting || to == StateFailed
	case StateGranting:
		return to == StateReady || to == StateFailed
	case StateReady, StateFailed:
		return to == StateRevoking
	case StateRevoking:
		return to == StateDeprovisioning || to == StateFailed
	case StateDeprovisioning:
		return to == StateDeprovisioned || to == StateFailed
	default:
		return false
	}
}

func validateDraft(draft Allocation) error {
	if strings.TrimSpace(draft.Name) == "" {
		return fmt.Errorf("%w: name is required", ErrInvalid)
	}
	if strings.TrimSpace(draft.InfraConnectionID) == "" {
		return fmt.Errorf("%w: infra_connection_id is required", ErrInvalid)
	}
	if strings.TrimSpace(draft.Location) == "" {
		return fmt.Errorf("%w: location is required", ErrInvalid)
	}
	if !draft.RelayTransport {
		return fmt.Errorf("%w: relay transport capability is required", ErrInvalid)
	}
	// ADR-0063's own field list has no Gateway-identity picker, but
	// relayservice.configureAccess -- the exact function "granting" must
	// reuse -- hard-requires a GatewayHandle bound to an already-enrolled
	// Linux peer whenever egress is requested, with no path around that.
	// Rather than grant with no handle and let that validation fail the
	// allocation every time, egress stays rejected up front until a later
	// issue designs how a freshly-provisioned host's own Gateway identity
	// gets bound.
	if draft.EgressV4 || draft.EgressV6 {
		return fmt.Errorf("%w: egress is not yet supported by relay allocation", ErrInvalid)
	}
	if len(draft.PermittedGroups) == 0 {
		return fmt.Errorf("%w: choose at least one permitted group -- default is no access", ErrInvalid)
	}
	return nil
}

// Create validates references in the caller's account and persists the
// request as StateRequested in one transaction, with no provider call
// inside it. The caller's own ID/AccountID/State/Revision are never
// trusted; this always assigns a fresh server-generated ID.
func (s *Store) Create(ctx context.Context, draft Allocation) (*Allocation, error) {
	account, err := accountFromContext(ctx)
	if err != nil {
		return nil, err
	}
	if err := validateDraft(draft); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	allocation := Allocation{
		AccountID:         account,
		ID:                xid.New().String(),
		Name:              draft.Name,
		InfraConnectionID: draft.InfraConnectionID,
		Location:          draft.Location,
		RelayTransport:    draft.RelayTransport,
		EgressV4:          draft.EgressV4,
		EgressV6:          draft.EgressV6,
		PermittedGroups:   draft.PermittedGroups,
		State:             StateRequested,
		Revision:          1,
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var connections int64
		if err := tx.Model(&infraconnections.Account{}).Where("account_id = ? AND id = ?", account, allocation.InfraConnectionID).Count(&connections).Error; err != nil {
			return err
		}
		if connections != 1 {
			return fmt.Errorf("%w: infra_connection_id is not registered in this account", ErrInvalid)
		}
		for _, id := range allocation.PermittedGroups {
			var count int64
			if err := tx.Model(&types.Group{}).Where("account_id = ? AND id = ?", account, id).Count(&count).Error; err != nil {
				return err
			}
			if count != 1 {
				return fmt.Errorf("%w: selected group is unavailable in this account", ErrInvalid)
			}
		}
		if err := tx.Create(&allocation).Error; err != nil {
			return err
		}
		return tx.Create(&AllocationHistory{AccountID: account, AllocationID: allocation.ID, FromState: "", ToState: StateRequested, Reason: "allocation requested", CreatedAt: now}).Error
	})
	if err != nil {
		return nil, err
	}
	return &allocation, nil
}

// Get returns one allocation by id, scoped to the caller's account. The
// HTTP API a later PR adds uses this so a retried action (the
// reconciliation loop calling the same step twice after a crash or
// timeout between its own tick and the server's response) can tell
// whether it already landed before attempting another compare-and-set
// Transition against a state that has since moved on.
func (s *Store) Get(ctx context.Context, id string) (*Allocation, error) {
	account, err := accountFromContext(ctx)
	if err != nil {
		return nil, err
	}
	var current Allocation
	if err := s.db.WithContext(ctx).Where("account_id = ? AND id = ?", account, id).First(&current).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &current, nil
}

// List returns every allocation in the caller's account, regardless of
// state -- used both by the console and, via the HTTP API a later PR adds,
// by the Rust reconciliation loop's own polling.
func (s *Store) List(ctx context.Context) ([]Allocation, error) {
	account, err := accountFromContext(ctx)
	if err != nil {
		return nil, err
	}
	rows := make([]Allocation, 0)
	if err := s.db.WithContext(ctx).Where("account_id = ?", account).Order("created_at, id").Find(&rows).Error; err != nil {
		return nil, err
	}
	return rows, nil
}

// Transition applies one compare-and-set state change, modeled on
// billing.UpdatePaymentState: both expectedRevision and expectedState must
// match the row's current values, not just one, so a transition can never
// silently skip a step a concurrent writer (the console's deprovision
// request, or another tick of the same reconciliation loop after a
// timeout) already advanced past. instanceID/relayID are recorded when
// non-empty and otherwise left unchanged; transitioning to StateFailed
// records expectedState as FailedStep and reason as FailureReason, and any
// other transition clears both.
func (s *Store) Transition(ctx context.Context, id string, expectedRevision uint64, expectedState, to, reason, instanceID, relayID string) (*Allocation, error) {
	account, err := accountFromContext(ctx)
	if err != nil {
		return nil, err
	}
	if !validAllocationTransition(expectedState, to) {
		return nil, fmt.Errorf("%w: %s to %s is not a valid transition", ErrInvalid, expectedState, to)
	}
	now := time.Now().UTC()
	var current Allocation
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("account_id = ? AND id = ?", account, id).First(&current).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}
		if current.Revision != expectedRevision || current.State != expectedState {
			return ErrExists
		}
		updates := map[string]any{"state": to, "revision": current.Revision + 1, "updated_at": now}
		if to == StateFailed {
			updates["failed_step"] = expectedState
			updates["failure_reason"] = reason
		} else {
			updates["failed_step"] = ""
			updates["failure_reason"] = ""
		}
		if instanceID != "" {
			updates["instance_id"] = instanceID
		}
		if relayID != "" {
			updates["relay_id"] = relayID
		}
		result := tx.Model(&Allocation{}).Where("account_id = ? AND id = ? AND revision = ?", account, id, expectedRevision).Updates(updates)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return ErrExists
		}
		if err := tx.Create(&AllocationHistory{AccountID: account, AllocationID: id, FromState: expectedState, ToState: to, Reason: reason, CreatedAt: now}).Error; err != nil {
			return err
		}
		current.State = to
		current.Revision++
		current.UpdatedAt = now
		if to == StateFailed {
			current.FailedStep = expectedState
			current.FailureReason = reason
		} else {
			current.FailedStep = ""
			current.FailureReason = ""
		}
		if instanceID != "" {
			current.InstanceID = instanceID
		}
		if relayID != "" {
			current.RelayID = relayID
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &current, nil
}

// RequestDeprovision moves a ready or failed allocation into revoking --
// the first step of ADR-0063's reversed teardown order (withdraw the grant
// before touching compute). Refused from any in-flight state: an
// allocation the reconciliation loop is actively driving must finish (or
// fail) that step on its own before teardown can begin, so teardown never
// races a step already in progress.
func (s *Store) RequestDeprovision(ctx context.Context, id string, expectedRevision uint64) (*Allocation, error) {
	account, err := accountFromContext(ctx)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	var current Allocation
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("account_id = ? AND id = ?", account, id).First(&current).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}
		if current.Revision != expectedRevision {
			return ErrExists
		}
		if current.State != StateReady && current.State != StateFailed {
			return fmt.Errorf("%w: allocation is still in progress", ErrInvalid)
		}
		from := current.State
		result := tx.Model(&Allocation{}).Where("account_id = ? AND id = ? AND revision = ?", account, id, expectedRevision).
			Updates(map[string]any{"state": StateRevoking, "revision": current.Revision + 1, "updated_at": now, "failed_step": "", "failure_reason": ""})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return ErrExists
		}
		if err := tx.Create(&AllocationHistory{AccountID: account, AllocationID: id, FromState: from, ToState: StateRevoking, Reason: "deprovision requested", CreatedAt: now}).Error; err != nil {
			return err
		}
		current.State = StateRevoking
		current.Revision++
		current.UpdatedAt = now
		current.FailedStep = ""
		current.FailureReason = ""
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &current, nil
}

// Delete removes the row outright. Only legal once nothing was ever
// provisioned (StateRequested) or everything already was torn down
// (StateDeprovisioned) -- any other state must go through
// RequestDeprovision first, so a row referencing live compute or a live
// grant can never simply disappear from the account's view of it.
func (s *Store) Delete(ctx context.Context, id string, expectedRevision uint64) error {
	account, err := accountFromContext(ctx)
	if err != nil {
		return err
	}
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var current Allocation
		if err := tx.Where("account_id = ? AND id = ?", account, id).First(&current).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}
		if current.Revision != expectedRevision {
			return ErrExists
		}
		if current.State != StateRequested && current.State != StateDeprovisioned {
			return fmt.Errorf("%w: allocation must be deprovisioned before deletion", ErrInvalid)
		}
		result := tx.Where("account_id = ? AND id = ? AND revision = ?", account, id, expectedRevision).Delete(&Allocation{})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return ErrExists
		}
		return nil
	})
}
