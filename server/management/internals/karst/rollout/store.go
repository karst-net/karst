// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// Package rollout tracks an administrator's durable rollout plan for the
// single production Nomad job's control/console/relay task groups
// (ADR-0066, issue #484): a target digest and operator-attested
// cosign-verification reference per component, an enforced apply sequence,
// and a state machine (planned -> in_progress -> completed, or -> failed
// from any step; completed/failed -> rolled_back on teardown). Create
// persists the plan and its components as planned in one local transaction
// with no external call inside it -- the same discipline relayalloc.Create
// already follows, for the same reason: this package makes no external
// call at all (ADR-0066's trust-boundary decision), so there is nothing to
// keep out of the transaction, but the convention is kept for consistency.
// Driving a plan forward (recording that the operator actually ran
// `cosign verify`/`nomad job plan`/`run` by hand) is the console's/API
// caller's job via MarkComponentApplied/MarkComponentFailed, not an
// internal reconciliation loop -- ADR-0066 is explicit that v1 has none.
package rollout

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/rs/xid"
	"gorm.io/gorm"
)

var (
	ErrNoAccount = errors.New("rollout: account scope missing")
	ErrInvalid   = errors.New("rollout: invalid plan")
	ErrExists    = errors.New("rollout: plan changed; reload before saving")
	ErrNotFound  = errors.New("rollout: plan not found")
)

// State is the plan's own lifecycle.
const (
	StatePlanned    = "planned"
	StateInProgress = "in_progress"
	StateCompleted  = "completed"
	StateFailed     = "failed"
	StateRolledBack = "rolled_back"
)

// Component names this package accepts -- the single production Nomad job's
// three Karst-authored task groups (ADR-0066's v1 scope; Keycloak/Caddy are
// third-party infra and out of scope). RelayJob is this job's own relay
// task group specifically, not the broader scaler-managed/BYO relay fleet.
const (
	ComponentControl  = "control"
	ComponentConsole  = "console"
	ComponentRelayJob = "relay_job"
)

func validComponentName(name string) bool {
	switch name {
	case ComponentControl, ComponentConsole, ComponentRelayJob:
		return true
	default:
		return false
	}
}

// digestPattern matches an immutable OCI image digest shape, the same
// sha256:<64 lowercase hex chars> shape karst.nomad.hcl's own
// console_image_digest validation block already enforces. v1 validates
// shape only -- it never calls cosign itself (ADR-0066).
var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// Plan is the durable record ADR-0066 describes. FailedComponent and
// FailureReason are only meaningful while State == StateFailed; every other
// transition clears both rather than leaving a stale reason behind.
type Plan struct {
	AccountID             string     `gorm:"primaryKey;size:64" json:"-"`
	ID                    string     `gorm:"primaryKey;size:64" json:"id"`
	TargetRelease         string     `gorm:"not null" json:"target_release"`
	MaintenanceWindowNote string     `json:"maintenance_window_note,omitempty"`
	State                 string     `gorm:"not null;index" json:"state"`
	FailedComponent       string     `json:"failed_component,omitempty"`
	FailureReason         string     `json:"failure_reason,omitempty"`
	Revision              uint64     `gorm:"not null;default:0" json:"revision"`
	CreatedAt             time.Time  `json:"created_at"`
	UpdatedAt             time.Time  `json:"updated_at"`
	StartedAt             *time.Time `json:"started_at,omitempty"`
	CompletedAt           *time.Time `json:"completed_at,omitempty"`
}

func (Plan) TableName() string { return "karst_rollout_plans" }

// PlanComponent is one component's row within a Plan. Sequence is
// 0-based and must be contiguous across a plan's components (0, 1, 2, ...)
// -- MarkComponentApplied enforces apply order against it directly.
type PlanComponent struct {
	ID                           uint       `gorm:"primaryKey" json:"-"`
	PlanID                       string     `gorm:"not null;index;size:64" json:"-"`
	AccountID                    string     `gorm:"not null;size:64" json:"-"`
	Name                         string     `gorm:"not null" json:"name"`
	Sequence                     int        `gorm:"not null" json:"sequence"`
	CurrentDigest                string     `json:"current_digest,omitempty"`
	TargetDigest                 string     `gorm:"not null" json:"target_digest"`
	VerificationRef              string     `gorm:"not null" json:"verification_ref"`
	RequiresRelayLifecycleSchema *uint32    `json:"requires_relay_lifecycle_schema,omitempty"`
	RequiresGatewayIngressSchema *uint32    `json:"requires_gateway_ingress_schema,omitempty"`
	Status                       string     `gorm:"not null;default:'pending'" json:"status"`
	FailureReason                string     `json:"failure_reason,omitempty"`
	ObservedDigest               string     `json:"observed_digest,omitempty"`
	ObservedAt                   *time.Time `json:"observed_at,omitempty"`
}

func (PlanComponent) TableName() string { return "karst_rollout_plan_components" }

const (
	componentPending = "pending"
	componentApplied = "applied"
	componentFailed  = "failed"
)

// PlanHistory is the append-only transition audit trail -- mirrors
// relayalloc's AllocationHistory, itself modeled on billing's
// paymentHistoryRow, the established precedent for a multi-step state
// machine in this codebase.
type PlanHistory struct {
	ID        uint   `gorm:"primaryKey"`
	AccountID string `gorm:"index"`
	PlanID    string `gorm:"index"`
	FromState string
	ToState   string
	Reason    string
	CreatedAt time.Time `gorm:"index"`
}

func (PlanHistory) TableName() string { return "karst_rollout_plan_history" }

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

type Store struct {
	db *gorm.DB
}

func NewStore(db *gorm.DB) (*Store, error) {
	if db == nil {
		return nil, fmt.Errorf("rollout: nil database")
	}
	if err := db.AutoMigrate(&Plan{}, &PlanComponent{}, &PlanHistory{}); err != nil {
		return nil, err
	}
	return &Store{db: db}, nil
}

// validPlanTransition is the explicit transition-graph allow-list ADR-0066
// specifies, mirroring relayalloc's validAllocationTransition. Retrying a
// failed plan forward is deliberately not offered: an administrator retries
// by creating a new plan, not resuming this one in place.
func validPlanTransition(from, to string) bool {
	switch from {
	case StatePlanned:
		return to == StateInProgress
	case StateInProgress:
		return to == StateCompleted || to == StateFailed || to == StateRolledBack
	case StateCompleted, StateFailed:
		return to == StateRolledBack
	default:
		return false
	}
}

func validateDraft(draft Plan, components []PlanComponent) error {
	if strings.TrimSpace(draft.TargetRelease) == "" {
		return fmt.Errorf("%w: target_release is required", ErrInvalid)
	}
	if len(components) == 0 {
		return fmt.Errorf("%w: at least one component is required", ErrInvalid)
	}
	seenName := make(map[string]bool, len(components))
	seenSequence := make(map[int]bool, len(components))
	for _, component := range components {
		if !validComponentName(component.Name) {
			return fmt.Errorf("%w: %q is not a recognized component", ErrInvalid, component.Name)
		}
		if seenName[component.Name] {
			return fmt.Errorf("%w: component %q is listed more than once", ErrInvalid, component.Name)
		}
		seenName[component.Name] = true
		if seenSequence[component.Sequence] {
			return fmt.Errorf("%w: sequence %d is used more than once", ErrInvalid, component.Sequence)
		}
		seenSequence[component.Sequence] = true
		if !digestPattern.MatchString(component.TargetDigest) {
			return fmt.Errorf("%w: component %q has an invalid target digest shape", ErrInvalid, component.Name)
		}
		if strings.TrimSpace(component.VerificationRef) == "" {
			return fmt.Errorf("%w: component %q requires a verification reference", ErrInvalid, component.Name)
		}
	}
	for i := 0; i < len(components); i++ {
		if !seenSequence[i] {
			return fmt.Errorf("%w: sequence values must be contiguous starting at 0", ErrInvalid)
		}
	}
	return nil
}

// Create validates the draft plan and its components in the caller's
// account and persists them as StatePlanned/"pending" in one local
// transaction. The caller's own ID/AccountID/State/Revision and each
// component's Status/FailureReason/ObservedDigest/ObservedAt are never
// trusted; this always assigns fresh server-generated values.
func (s *Store) Create(ctx context.Context, draft Plan, components []PlanComponent) (*Plan, []PlanComponent, error) {
	account, err := accountFromContext(ctx)
	if err != nil {
		return nil, nil, err
	}
	if err := validateDraft(draft, components); err != nil {
		return nil, nil, err
	}
	now := time.Now().UTC()
	plan := Plan{
		AccountID:             account,
		ID:                    xid.New().String(),
		TargetRelease:         draft.TargetRelease,
		MaintenanceWindowNote: draft.MaintenanceWindowNote,
		State:                 StatePlanned,
		Revision:              1,
		CreatedAt:             now,
		UpdatedAt:             now,
	}
	rows := make([]PlanComponent, len(components))
	for i, component := range components {
		rows[i] = PlanComponent{
			PlanID:                       plan.ID,
			AccountID:                    account,
			Name:                         component.Name,
			Sequence:                     component.Sequence,
			CurrentDigest:                component.CurrentDigest,
			TargetDigest:                 component.TargetDigest,
			VerificationRef:              component.VerificationRef,
			RequiresRelayLifecycleSchema: component.RequiresRelayLifecycleSchema,
			RequiresGatewayIngressSchema: component.RequiresGatewayIngressSchema,
			Status:                       componentPending,
		}
	}
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&plan).Error; err != nil {
			return err
		}
		if err := tx.Create(&rows).Error; err != nil {
			return err
		}
		return tx.Create(&PlanHistory{AccountID: account, PlanID: plan.ID, FromState: "", ToState: StatePlanned, Reason: "plan created", CreatedAt: now}).Error
	})
	if err != nil {
		return nil, nil, err
	}
	return &plan, rows, nil
}

// Get returns one plan and its components by id, scoped to the caller's
// account.
func (s *Store) Get(ctx context.Context, id string) (*Plan, []PlanComponent, error) {
	account, err := accountFromContext(ctx)
	if err != nil {
		return nil, nil, err
	}
	var plan Plan
	if err := s.db.WithContext(ctx).Where("account_id = ? AND id = ?", account, id).First(&plan).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil, ErrNotFound
		}
		return nil, nil, err
	}
	components, err := s.components(ctx, account, id)
	if err != nil {
		return nil, nil, err
	}
	return &plan, components, nil
}

func (s *Store) components(ctx context.Context, account, planID string) ([]PlanComponent, error) {
	rows := make([]PlanComponent, 0)
	if err := s.db.WithContext(ctx).Where("account_id = ? AND plan_id = ?", account, planID).Order("sequence").Find(&rows).Error; err != nil {
		return nil, err
	}
	return rows, nil
}

// List returns every plan in the caller's account, regardless of state.
func (s *Store) List(ctx context.Context) ([]Plan, error) {
	account, err := accountFromContext(ctx)
	if err != nil {
		return nil, err
	}
	rows := make([]Plan, 0)
	if err := s.db.WithContext(ctx).Where("account_id = ?", account).Order("created_at, id").Find(&rows).Error; err != nil {
		return nil, err
	}
	return rows, nil
}

// Start applies the compare-and-set planned -> in_progress transition.
// acknowledge must be true -- the console's own double opt-in convention,
// matching relayalloc's deprovision request. overrideIncompatibility must
// also be true if the caller's own live compatibility preview (computed by
// the caller via Preview, not cached on the row -- fleet state drifts)
// still reports a blocking capability, so a stale UI state can never
// bypass the check: the caller must pass what it just computed.
func (s *Store) Start(ctx context.Context, id string, expectedRevision uint64, acknowledge, overrideIncompatibility bool, stillBlocking bool, maintenanceWindowNote string) (*Plan, error) {
	account, err := accountFromContext(ctx)
	if err != nil {
		return nil, err
	}
	if !acknowledge {
		return nil, fmt.Errorf("%w: review and acknowledge the rollout before starting it", ErrInvalid)
	}
	if stillBlocking && !overrideIncompatibility {
		return nil, fmt.Errorf("%w: fleet compatibility is still blocking; override explicitly to proceed", ErrInvalid)
	}
	now := time.Now().UTC()
	var current Plan
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("account_id = ? AND id = ?", account, id).First(&current).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}
		if current.Revision != expectedRevision || current.State != StatePlanned {
			return ErrExists
		}
		updates := map[string]any{"state": StateInProgress, "revision": current.Revision + 1, "updated_at": now, "started_at": now}
		if maintenanceWindowNote != "" {
			updates["maintenance_window_note"] = maintenanceWindowNote
		}
		result := tx.Model(&Plan{}).Where("account_id = ? AND id = ? AND revision = ?", account, id, expectedRevision).Updates(updates)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return ErrExists
		}
		if err := tx.Create(&PlanHistory{AccountID: account, PlanID: id, FromState: StatePlanned, ToState: StateInProgress, Reason: "rollout started", CreatedAt: now}).Error; err != nil {
			return err
		}
		current.State = StateInProgress
		current.Revision++
		current.UpdatedAt = now
		current.StartedAt = &now
		if maintenanceWindowNote != "" {
			current.MaintenanceWindowNote = maintenanceWindowNote
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &current, nil
}

// MarkComponentApplied is the sequencing enforcement: name must be the
// lowest not-yet-applied Sequence among the plan's components, so a
// component can never be recorded applied ahead of one that must precede
// it. Idempotent if name is already applied (the operator or console
// retrying after a timeout). Auto-transitions the Plan to StateCompleted,
// in the same transaction, once the last component applies.
func (s *Store) MarkComponentApplied(ctx context.Context, id string, expectedRevision uint64, name, observedDigest string) (*Plan, []PlanComponent, error) {
	account, err := accountFromContext(ctx)
	if err != nil {
		return nil, nil, err
	}
	if !validComponentName(name) {
		return nil, nil, fmt.Errorf("%w: %q is not a recognized component", ErrInvalid, name)
	}
	now := time.Now().UTC()
	var plan Plan
	var components []PlanComponent
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("account_id = ? AND id = ?", account, id).First(&plan).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}
		if plan.Revision != expectedRevision {
			return ErrExists
		}
		if plan.State != StateInProgress {
			return fmt.Errorf("%w: plan is not in progress", ErrInvalid)
		}
		rows, err := planComponentsTx(tx, account, id)
		if err != nil {
			return err
		}
		var target *PlanComponent
		lowestPending := -1
		for i := range rows {
			if rows[i].Name == name {
				target = &rows[i]
			}
			if rows[i].Status == componentPending && (lowestPending == -1 || rows[i].Sequence < rows[lowestPending].Sequence) {
				lowestPending = i
			}
		}
		if target == nil {
			return fmt.Errorf("%w: component %q is not part of this plan", ErrInvalid, name)
		}
		if target.Status == componentApplied {
			components = rows
			return nil // idempotent retry
		}
		if lowestPending == -1 || rows[lowestPending].Name != name {
			return fmt.Errorf("%w: component %q is not the next component in sequence", ErrInvalid, name)
		}
		if err := tx.Model(&PlanComponent{}).Where("account_id = ? AND plan_id = ? AND name = ?", account, id, name).
			Updates(map[string]any{"status": componentApplied, "failure_reason": "", "observed_digest": observedDigest, "observed_at": now}).Error; err != nil {
			return err
		}
		target.Status = componentApplied
		target.FailureReason = ""
		target.ObservedDigest = observedDigest
		target.ObservedAt = &now

		remainingPending := false
		for i := range rows {
			if rows[i].Name == name {
				continue
			}
			if rows[i].Status == componentPending {
				remainingPending = true
			}
		}
		if !remainingPending {
			result := tx.Model(&Plan{}).Where("account_id = ? AND id = ? AND revision = ?", account, id, expectedRevision).
				Updates(map[string]any{"state": StateCompleted, "revision": plan.Revision + 1, "updated_at": now, "completed_at": now})
			if result.Error != nil {
				return result.Error
			}
			if result.RowsAffected != 1 {
				return ErrExists
			}
			if err := tx.Create(&PlanHistory{AccountID: account, PlanID: id, FromState: StateInProgress, ToState: StateCompleted, Reason: "every component applied", CreatedAt: now}).Error; err != nil {
				return err
			}
			plan.State = StateCompleted
			plan.Revision++
			plan.UpdatedAt = now
			plan.CompletedAt = &now
		}
		components = rows
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return &plan, components, nil
}

// MarkComponentFailed transitions the Plan in_progress -> failed and sets
// FailedComponent/FailureReason, leaving every component row's own Status
// untouched except the one named (set to "failed").
func (s *Store) MarkComponentFailed(ctx context.Context, id string, expectedRevision uint64, name, reason string) (*Plan, []PlanComponent, error) {
	account, err := accountFromContext(ctx)
	if err != nil {
		return nil, nil, err
	}
	if !validComponentName(name) {
		return nil, nil, fmt.Errorf("%w: %q is not a recognized component", ErrInvalid, name)
	}
	if strings.TrimSpace(reason) == "" {
		return nil, nil, fmt.Errorf("%w: a failure reason is required", ErrInvalid)
	}
	now := time.Now().UTC()
	var plan Plan
	var components []PlanComponent
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("account_id = ? AND id = ?", account, id).First(&plan).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}
		if plan.Revision != expectedRevision || plan.State != StateInProgress {
			return ErrExists
		}
		result := tx.Model(&PlanComponent{}).Where("account_id = ? AND plan_id = ? AND name = ?", account, id, name).
			Updates(map[string]any{"status": componentFailed, "failure_reason": reason})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return fmt.Errorf("%w: component %q is not part of this plan", ErrInvalid, name)
		}
		planResult := tx.Model(&Plan{}).Where("account_id = ? AND id = ? AND revision = ?", account, id, expectedRevision).
			Updates(map[string]any{"state": StateFailed, "revision": plan.Revision + 1, "updated_at": now, "failed_component": name, "failure_reason": reason})
		if planResult.Error != nil {
			return planResult.Error
		}
		if planResult.RowsAffected != 1 {
			return ErrExists
		}
		if err := tx.Create(&PlanHistory{AccountID: account, PlanID: id, FromState: StateInProgress, ToState: StateFailed, Reason: reason, CreatedAt: now}).Error; err != nil {
			return err
		}
		plan.State = StateFailed
		plan.Revision++
		plan.UpdatedAt = now
		plan.FailedComponent = name
		plan.FailureReason = reason
		rows, err := planComponentsTx(tx, account, id)
		if err != nil {
			return err
		}
		components = rows
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return &plan, components, nil
}

// RollBack moves a plan from any of in_progress/completed/failed into
// rolled_back. PlanComponent rows are left untouched for audit -- a
// rollback is control's own record that the operator reverted the
// deployment by hand (ADR-0066's trust-boundary decision); it is not an
// automated teardown.
func (s *Store) RollBack(ctx context.Context, id string, expectedRevision uint64, reason string) (*Plan, error) {
	account, err := accountFromContext(ctx)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	var current Plan
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
		if !validPlanTransition(current.State, StateRolledBack) {
			return fmt.Errorf("%w: plan cannot be rolled back from %s", ErrInvalid, current.State)
		}
		from := current.State
		result := tx.Model(&Plan{}).Where("account_id = ? AND id = ? AND revision = ?", account, id, expectedRevision).
			Updates(map[string]any{"state": StateRolledBack, "revision": current.Revision + 1, "updated_at": now})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return ErrExists
		}
		if err := tx.Create(&PlanHistory{AccountID: account, PlanID: id, FromState: from, ToState: StateRolledBack, Reason: reason, CreatedAt: now}).Error; err != nil {
			return err
		}
		current.State = StateRolledBack
		current.Revision++
		current.UpdatedAt = now
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &current, nil
}

// Delete removes the plan and its components outright. Only legal while
// nothing has started (StatePlanned) -- any other state must go through
// RollBack first, so a row describing live operator activity can never
// simply disappear from the account's view of it.
func (s *Store) Delete(ctx context.Context, id string, expectedRevision uint64) error {
	account, err := accountFromContext(ctx)
	if err != nil {
		return err
	}
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var current Plan
		if err := tx.Where("account_id = ? AND id = ?", account, id).First(&current).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}
		if current.Revision != expectedRevision {
			return ErrExists
		}
		if current.State != StatePlanned {
			return fmt.Errorf("%w: plan must be rolled back before deletion", ErrInvalid)
		}
		if err := tx.Where("account_id = ? AND plan_id = ?", account, id).Delete(&PlanComponent{}).Error; err != nil {
			return err
		}
		result := tx.Where("account_id = ? AND id = ? AND revision = ?", account, id, expectedRevision).Delete(&Plan{})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return ErrExists
		}
		return nil
	})
}

func planComponentsTx(tx *gorm.DB, account, planID string) ([]PlanComponent, error) {
	rows := make([]PlanComponent, 0)
	if err := tx.Where("account_id = ? AND plan_id = ?", account, planID).Order("sequence").Find(&rows).Error; err != nil {
		return nil, err
	}
	return rows, nil
}
