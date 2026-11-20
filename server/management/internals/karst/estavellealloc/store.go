// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// Package estavellealloc stores an administrator's manual estavelle allocation
// request (ADR-0063, issue #455): name, infrastructure connection,
// location, requested capabilities, and permitted groups, plus a durable
// state machine (requested -> provisioning -> granting -> ready, or ->
// failed from any step; ready/failed -> revoking -> deprovisioning ->
// deprovisioned on teardown). Create persists the requested record in one
// local transaction with no provider call inside it -- the same discipline
// estavelleservice.UpdateAccess already follows, for the same reason: a
// provider call can take minutes and must never hold a DB transaction open.
// Driving a requested record forward (calling a karst-scaler Driver,
// minting an enroll token, calling estavelleservice to grant or revoke access)
// is the Rust reconciliation loop's job (ADR-0063), not this package's --
// this package only exposes the compare-and-set Transition/RequestDeprovision
// primitives that loop calls through, plus Create/List/Delete for the
// console.
package estavellealloc

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/rs/xid"
	"gorm.io/gorm"

	"github.com/netbirdio/netbird/management/internals/karst/cloudcatalog"
	"github.com/netbirdio/netbird/management/internals/karst/infraconnections"
	"github.com/netbirdio/netbird/management/internals/karst/locationreg"
	"github.com/netbirdio/netbird/management/server/migration"
	"github.com/netbirdio/netbird/management/server/types"
)

var (
	ErrNoAccount = errors.New("estavelle allocation: account scope missing")
	ErrInvalid   = errors.New("estavelle allocation: invalid allocation")
	ErrExists    = errors.New("estavelle allocation: allocation changed; reload before saving")
	ErrNotFound  = errors.New("estavelle allocation: allocation not found")
)

// State is the allocation's own lifecycle, independent of both the
// scaler's pool state and estavelleservice's access state (ADR-0063's
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

// ReplacementState is a side-channel on top of StateReady (issue #560): a
// zero-downtime version replacement never changes Allocation.State or
// touches the access grant, so "no estavelle-admission gap" is structural,
// not something the orchestration has to get right by timing. Empty means
// no replacement is in flight. Unlike the main state machine, a replacement
// can resume into itself after StateFailed -- every step is written to be
// idempotent/resumable (RetryReplacement), so there is no reason to force a
// restart from ReplacementStateProvisioning.
const (
	ReplacementStateProvisioning = "provisioning"
	ReplacementStateAdmitting    = "admitting"
	ReplacementStateDraining     = "draining"
	ReplacementStateDestroying   = "destroying"
	ReplacementStateFailed       = "failed"
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
	AccountID          string    `gorm:"primaryKey;size:64" json:"-"`
	ID                 string    `gorm:"primaryKey;size:64" json:"id"`
	Name               string    `gorm:"not null" json:"name"`
	InfraConnectionID  string    `gorm:"not null" json:"infra_connection_id"`
	Location           string    `gorm:"not null" json:"location"`
	EstavelleTransport bool      `json:"estavelle_transport,omitempty"`
	EgressV4           bool      `json:"egress_v4,omitempty"`
	EgressV6           bool      `json:"egress_v6,omitempty"`
	PermittedGroups    []string  `gorm:"serializer:json" json:"permitted_groups,omitempty"`
	State              string    `gorm:"not null;index" json:"state"`
	FailedStep         string    `json:"failed_step,omitempty"`
	FailureReason      string    `json:"failure_reason,omitempty"`
	InstanceID         string    `json:"instance_id,omitempty"`
	EstavelleID        string    `json:"estavelle_id,omitempty"`
	Revision           uint64    `gorm:"not null;default:0" json:"revision"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`

	// DesiredImage/RunningImage are issue #560's version tracking.
	// RunningImage is "" for an allocation whose current instance came from
	// the connection's own launch defaults and was never explicitly
	// versioned through this mechanism -- it becomes a real value either
	// once a replacement completes (CompleteReplacement) or, for the first
	// instance, straight out of Create below when the caller named an
	// Image to launch it with.
	DesiredImage string `json:"desired_image,omitempty"`
	RunningImage string `json:"running_image,omitempty"`
	// Image is accepted only on Create: the version/image to launch this
	// allocation's first instance with, instead of the infrastructure
	// connection's own launch default -- the console's "Allocate an
	// estavelle" dialog prompts for it, defaulting to the most recent
	// karst-net/karst release tag (see karst-releases.ts). Not itself a
	// persisted column (gorm:"-") and never echoed back: Create copies a
	// non-empty value straight into RunningImage above, since that
	// genuinely is what the first instance ends up running, and
	// provisionStep (drive_loop.go) reads RunningImage back out to pass
	// through to Driver.Create, the exact same CreateRequest.Image path
	// replaceProvisionStep already uses for DesiredImage.
	Image string `gorm:"-" json:"image,omitempty"`
	// ReplacementState/ReplacementInstanceID/ReplacementFailedStep/
	// ReplacementFailureReason/ReplacementUpdatedAt track one in-flight
	// zero-downtime replacement -- see the ReplacementState consts' own doc
	// comment for why this is a side-channel on State rather than a new
	// main lifecycle state. InstanceID/EstavelleID keep pointing at the
	// instance actually serving traffic until CompleteReplacement cuts
	// over; ReplacementInstanceID is the new instance in the meantime.
	ReplacementState         string    `json:"replacement_state,omitempty"`
	ReplacementInstanceID    string    `json:"replacement_instance_id,omitempty"`
	ReplacementFailedStep    string    `json:"replacement_failed_step,omitempty"`
	ReplacementFailureReason string    `json:"replacement_failure_reason,omitempty"`
	ReplacementUpdatedAt     time.Time `json:"-"`
}

func (Allocation) TableName() string { return "karst_estavelle_allocations" }

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

func (AllocationHistory) TableName() string { return "karst_estavelle_allocation_history" }

type Store struct {
	db *gorm.DB
	// maxConcurrentAllocations is ADR-0045 §6 bullet 4's "hard ceilings...
	// are mandatory configuration, with no 'unlimited' value," applied a
	// second time by that ADR's 2026-11-04 addendum now that this package
	// itself actuates infrastructure (drive_loop.go, via
	// infraprovision.Driver -- ADR-0067): zero (the default, before
	// SetMaxConcurrentAllocations is called) means Create refuses every
	// request rather than silently allowing an unbounded number of real,
	// billable instances per account.
	maxConcurrentAllocations int
}

func NewStore(db *gorm.DB) (*Store, error) {
	if db == nil {
		return nil, fmt.Errorf("estavelle allocation: nil database")
	}
	ctx := context.Background()
	// ADR-0069's clean-break Relay->Estavelle rename: idempotent, no-op once
	// the rename has happened.
	if err := migration.RenameTable[Allocation](ctx, db, "karst_relay_allocations"); err != nil {
		return nil, err
	}
	if err := migration.RenameTable[AllocationHistory](ctx, db, "karst_relay_allocation_history"); err != nil {
		return nil, err
	}
	// StoredLocation is locationreg's own table -- AutoMigrate is idempotent,
	// so migrating it here too (requireAuthorizedLocation reads it) is safe
	// regardless of whether bootstrap.go's own locationreg.NewStore has run
	// yet, and lets this package's tests construct a Store standalone.
	if err := db.AutoMigrate(&Allocation{}, &AllocationHistory{}, &locationreg.StoredLocation{}); err != nil {
		return nil, err
	}
	return &Store{db: db}, nil
}

// SetMaxConcurrentAllocations wires the per-account concurrency ceiling
// (KARST_RELAY_ALLOCATE_MAX_CONCURRENT, threaded down from
// cmd/karst-control/main.go through internals/karst/bootstrap) once, at
// boot. n must be positive; Create treats any non-positive value
// (including never calling this at all) as "not configured" and refuses
// every allocation request until it is set -- see maxConcurrentAllocations'
// own doc comment for why that is the deliberate default, not a bug.
func (s *Store) SetMaxConcurrentAllocations(n int) {
	s.maxConcurrentAllocations = n
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
	if !draft.EstavelleTransport {
		return fmt.Errorf("%w: estavelle transport capability is required", ErrInvalid)
	}
	// ADR-0063's own field list has no Gateway-identity picker, but
	// estavelleservice.configureAccess -- the exact function "granting" must
	// reuse -- hard-requires a AvenHandle bound to an already-enrolled
	// Linux peer whenever egress is requested, with no path around that.
	// Rather than grant with no handle and let that validation fail the
	// allocation every time, egress stays rejected up front until a later
	// issue designs how a freshly-provisioned host's own Gateway identity
	// gets bound.
	if draft.EgressV4 || draft.EgressV6 {
		return fmt.Errorf("%w: egress is not yet supported by estavelle allocation", ErrInvalid)
	}
	if len(draft.PermittedGroups) == 0 {
		return fmt.Errorf("%w: choose at least one permitted group -- default is no access", ErrInvalid)
	}
	return nil
}

// requireAuthorizedLocation rejects an allocation whose resolved coordinates
// are not already in the account's Authorized Locations registry
// (package locationreg) -- an allocation provisions a real host, so unlike
// a bare declared-location field (estavellereg, group-location, ...), it is
// deliberately coupled to that registry rather than following locationreg's
// own "not a foreign key" default (see its package doc): the operator's
// own request (issue #439, discussed alongside ADR-0063) was specifically
// to stop a host from being provisioned somewhere never authorized.
//
// Resolution stays entirely local, matching Create's own "no provider call
// inside this transaction" rule: a cloud location's coordinates come from
// the static cloudcatalog (the same source discover.go's enrich() uses),
// never a live Discover call, and a cluster connection's (Kubernetes/Nomad/
// LXD) own declared Lat/Lon is the only other source -- mirroring the
// console's own locations.tsx fallback (resource's own coordinates, else
// the connection's declared ones). A location this cannot resolve at all is
// rejected, not let through: an unresolvable location can never be
// confirmed authorized either.
func requireAuthorizedLocation(tx *gorm.DB, accountID string, connection infraconnections.Account, location string) error {
	var lat, lon float64
	switch connection.Type {
	case infraconnections.TypeAWS, infraconnections.TypeAzure, infraconnections.TypeGCP:
		entry, ok := cloudcatalog.Lookup(string(connection.Type), location)
		if !ok {
			return fmt.Errorf("%w: location %q has no known coordinates to check against the authorized locations registry -- add it to the cloud catalog", ErrInvalid, location)
		}
		lat, lon = entry.Lat, entry.Lon
	default:
		if connection.Lat == nil || connection.Lon == nil {
			return fmt.Errorf("%w: this connection has no declared location -- set one in Settings, or use a connection type with provider-supplied geography", ErrInvalid)
		}
		lat, lon = *connection.Lat, *connection.Lon
	}
	var authorized []locationreg.StoredLocation
	if err := tx.Where("account_id = ?", accountID).Find(&authorized).Error; err != nil {
		return err
	}
	for _, candidate := range authorized {
		if candidate.Lat == lat && candidate.Lon == lon {
			return nil
		}
	}
	return fmt.Errorf("%w: location %q is not in the authorized locations registry -- add it there first", ErrInvalid, location)
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
		AccountID:          account,
		ID:                 xid.New().String(),
		Name:               draft.Name,
		InfraConnectionID:  draft.InfraConnectionID,
		Location:           draft.Location,
		EstavelleTransport: draft.EstavelleTransport,
		EgressV4:           draft.EgressV4,
		EgressV6:           draft.EgressV6,
		PermittedGroups:    draft.PermittedGroups,
		State:              StateRequested,
		RunningImage:       strings.TrimSpace(draft.Image),
		Revision:           1,
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	if s.maxConcurrentAllocations <= 0 {
		return nil, fmt.Errorf("%w: KARST_ESTAVELLE_ALLOCATE_MAX_CONCURRENT is not configured -- set a per-account concurrency ceiling before allocating an estavelle (ADR-0045 §6)", ErrInvalid)
	}
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var connection infraconnections.Account
		if err := tx.Where("account_id = ? AND id = ?", account, allocation.InfraConnectionID).First(&connection).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return fmt.Errorf("%w: infra_connection_id is not registered in this account", ErrInvalid)
			}
			return err
		}
		// A static, credential-free type check -- not a provider call, so
		// it belongs inside this same transaction (ADR-0058) -- so an
		// admin picking a connection type with no infraprovision.Driver
		// implementation (ADR-0067) is rejected now, not left with a
		// `requested` allocation the worker can never move (see
		// docs/adr/0067-unified-relay-provisioning-workflow.md's Context).
		if !connection.Type.SupportsActuation() {
			return fmt.Errorf("%w: connection type %q does not support estavelle allocation yet", ErrInvalid, connection.Type)
		}
		if err := requireAuthorizedLocation(tx, account, connection, allocation.Location); err != nil {
			return err
		}
		// ADR-0045 §6 bullet 4, applied to this actuator by its
		// 2026-11-04 addendum: each non-terminal allocation is one real,
		// billable EC2 instance (or about to be one), so the ceiling is
		// checked inside this same transaction, not as a separate
		// read-then-write a concurrent Create could race.
		var nonTerminal int64
		if err := tx.Model(&Allocation{}).Where("account_id = ? AND state != ?", account, StateDeprovisioned).Count(&nonTerminal).Error; err != nil {
			return err
		}
		if nonTerminal >= int64(s.maxConcurrentAllocations) {
			return fmt.Errorf("%w: this account already has %d non-terminal estavelle allocation(s), at or above the configured ceiling of %d", ErrInvalid, nonTerminal, s.maxConcurrentAllocations)
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
// timeout) already advanced past. instanceID/estavelleID are recorded when
// non-empty and otherwise left unchanged; transitioning to StateFailed
// records expectedState as FailedStep and reason as FailureReason, and any
// other transition clears both.
func (s *Store) Transition(ctx context.Context, id string, expectedRevision uint64, expectedState, to, reason, instanceID, estavelleID string) (*Allocation, error) {
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
		if estavelleID != "" {
			updates["estavelle_id"] = estavelleID
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
		if estavelleID != "" {
			current.EstavelleID = estavelleID
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &current, nil
}

// validReplacementTransition is TransitionReplacement's own allow-list,
// mirroring validAllocationTransition's role for the main machine --
// "failed" is deliberately never a `to` here (FailReplacement is the only
// path into it, since it needs a reason and a fromStep, not a bare CAS).
func validReplacementTransition(from, to string) bool {
	switch from {
	case ReplacementStateProvisioning:
		return to == ReplacementStateAdmitting
	case ReplacementStateAdmitting:
		return to == ReplacementStateDraining
	case ReplacementStateDraining:
		return to == ReplacementStateDestroying
	default:
		return false
	}
}

// RequestReplace starts a zero-downtime version replacement (issue #560):
// an administrator names a desired image/version different from the one
// currently running, and the reconciliation loop takes it from there
// (drive_loop.go's replacementTick). Only ever starts a *fresh* replacement
// from idle (ReplacementState == "") -- resuming a failed one is
// RetryReplacement's job, not this method's, so a caller can never
// accidentally restart create-new-instance while a previous attempt's
// instance is still around (see TransitionReplacement's own doc comment on
// why the correlation ID this drives is distinct from the original
// instance's).
func (s *Store) RequestReplace(ctx context.Context, id string, expectedRevision uint64, desiredImage string) (*Allocation, error) {
	account, err := accountFromContext(ctx)
	if err != nil {
		return nil, err
	}
	desiredImage = strings.TrimSpace(desiredImage)
	if desiredImage == "" {
		return nil, fmt.Errorf("%w: desired image is required", ErrInvalid)
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
		if current.State != StateReady {
			return fmt.Errorf("%w: allocation must be ready before replacing its running version", ErrInvalid)
		}
		if current.ReplacementState != "" {
			return fmt.Errorf("%w: a version replacement is already in progress", ErrInvalid)
		}
		if desiredImage == current.RunningImage {
			return fmt.Errorf("%w: desired image already matches the running image", ErrInvalid)
		}
		updates := map[string]any{
			"desired_image":              desiredImage,
			"replacement_state":          ReplacementStateProvisioning,
			"replacement_instance_id":    "",
			"replacement_failed_step":    "",
			"replacement_failure_reason": "",
			"replacement_updated_at":     now,
			"revision":                   current.Revision + 1,
			"updated_at":                 now,
		}
		result := tx.Model(&Allocation{}).Where("account_id = ? AND id = ? AND revision = ?", account, id, expectedRevision).Updates(updates)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return ErrExists
		}
		if err := tx.Create(&AllocationHistory{AccountID: account, AllocationID: id, FromState: current.State, ToState: current.State, Reason: fmt.Sprintf("replacement requested: desired image %q", desiredImage), CreatedAt: now}).Error; err != nil {
			return err
		}
		current.DesiredImage = desiredImage
		current.ReplacementState = ReplacementStateProvisioning
		current.ReplacementInstanceID = ""
		current.ReplacementFailedStep = ""
		current.ReplacementFailureReason = ""
		current.ReplacementUpdatedAt = now
		current.Revision++
		current.UpdatedAt = now
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &current, nil
}

// RetryReplacement resumes a failed replacement from exactly the step it
// failed at -- never from ReplacementStateProvisioning again, since every
// step is written to be idempotent/resumable (mirroring how grantStep/
// deprovisionStep already resume the main machine after a crash): retrying
// after a failed drain/destroy must never call Create a second time.
func (s *Store) RetryReplacement(ctx context.Context, id string, expectedRevision uint64) (*Allocation, error) {
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
		if current.ReplacementState != ReplacementStateFailed {
			return fmt.Errorf("%w: no failed replacement to retry", ErrInvalid)
		}
		resumeAt := current.ReplacementFailedStep
		updates := map[string]any{
			"replacement_state":          resumeAt,
			"replacement_failed_step":    "",
			"replacement_failure_reason": "",
			"replacement_updated_at":     now,
			"revision":                   current.Revision + 1,
			"updated_at":                 now,
		}
		result := tx.Model(&Allocation{}).Where("account_id = ? AND id = ? AND revision = ?", account, id, expectedRevision).Updates(updates)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return ErrExists
		}
		if err := tx.Create(&AllocationHistory{AccountID: account, AllocationID: id, FromState: current.State, ToState: current.State, Reason: fmt.Sprintf("replacement retried from %s", resumeAt), CreatedAt: now}).Error; err != nil {
			return err
		}
		current.ReplacementState = resumeAt
		current.ReplacementFailedStep = ""
		current.ReplacementFailureReason = ""
		current.ReplacementUpdatedAt = now
		current.Revision++
		current.UpdatedAt = now
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &current, nil
}

// TransitionReplacement applies one compare-and-set step change to
// ReplacementState, the drive_loop.go replacement steps' own analog of
// Transition -- refused outright once State has moved off StateReady (a
// replacement must never still be running once teardown has started;
// RequestDeprovision's own guard is what's supposed to prevent that from
// ever being reached, this is defense in depth). replacementInstanceID is
// recorded when non-empty, exactly like Transition's own instanceID
// parameter.
func (s *Store) TransitionReplacement(ctx context.Context, id string, expectedRevision uint64, expectedState, to, replacementInstanceID string) (*Allocation, error) {
	account, err := accountFromContext(ctx)
	if err != nil {
		return nil, err
	}
	if !validReplacementTransition(expectedState, to) {
		return nil, fmt.Errorf("%w: replacement %s to %s is not a valid transition", ErrInvalid, expectedState, to)
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
		if current.Revision != expectedRevision || current.ReplacementState != expectedState {
			return ErrExists
		}
		if current.State != StateReady {
			return fmt.Errorf("%w: allocation is no longer ready", ErrInvalid)
		}
		updates := map[string]any{"replacement_state": to, "replacement_updated_at": now, "revision": current.Revision + 1, "updated_at": now}
		if replacementInstanceID != "" {
			updates["replacement_instance_id"] = replacementInstanceID
		}
		result := tx.Model(&Allocation{}).Where("account_id = ? AND id = ? AND revision = ?", account, id, expectedRevision).Updates(updates)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return ErrExists
		}
		if err := tx.Create(&AllocationHistory{AccountID: account, AllocationID: id, FromState: current.State, ToState: current.State, Reason: fmt.Sprintf("replacement: %s to %s", expectedState, to), CreatedAt: now}).Error; err != nil {
			return err
		}
		current.ReplacementState = to
		current.ReplacementUpdatedAt = now
		if replacementInstanceID != "" {
			current.ReplacementInstanceID = replacementInstanceID
		}
		current.Revision++
		current.UpdatedAt = now
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &current, nil
}

// FailReplacement records that the replacement stuck at fromStep -- the old
// instance (State/InstanceID/EstavelleID) is never touched by this call, by
// construction: a replacement failure must never put the allocation's
// existing, already-working grant at risk.
func (s *Store) FailReplacement(ctx context.Context, id string, expectedRevision uint64, fromStep, reason string) (*Allocation, error) {
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
		if current.Revision != expectedRevision || current.ReplacementState != fromStep {
			return ErrExists
		}
		updates := map[string]any{
			"replacement_state":          ReplacementStateFailed,
			"replacement_failed_step":    fromStep,
			"replacement_failure_reason": reason,
			"replacement_updated_at":     now,
			"revision":                   current.Revision + 1,
			"updated_at":                 now,
		}
		result := tx.Model(&Allocation{}).Where("account_id = ? AND id = ? AND revision = ?", account, id, expectedRevision).Updates(updates)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return ErrExists
		}
		if err := tx.Create(&AllocationHistory{AccountID: account, AllocationID: id, FromState: current.State, ToState: current.State, Reason: fmt.Sprintf("replacement failed at %s: %s", fromStep, reason), CreatedAt: now}).Error; err != nil {
			return err
		}
		current.ReplacementState = ReplacementStateFailed
		current.ReplacementFailedStep = fromStep
		current.ReplacementFailureReason = reason
		current.ReplacementUpdatedAt = now
		current.Revision++
		current.UpdatedAt = now
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &current, nil
}

// CompleteReplacement is the cutover: the new instance becomes the
// allocation's instance of record (InstanceID/EstavelleID/RunningImage),
// and every Replacement* field clears back to idle. Only valid from
// ReplacementStateDestroying -- the old instance must already be gone
// before the record stops pointing at it.
func (s *Store) CompleteReplacement(ctx context.Context, id string, expectedRevision uint64, newInstanceID, newEstavelleID, newRunningImage string) (*Allocation, error) {
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
		if current.Revision != expectedRevision || current.ReplacementState != ReplacementStateDestroying {
			return ErrExists
		}
		updates := map[string]any{
			"instance_id":                newInstanceID,
			"estavelle_id":               newEstavelleID,
			"running_image":              newRunningImage,
			"replacement_state":          "",
			"replacement_instance_id":    "",
			"replacement_failed_step":    "",
			"replacement_failure_reason": "",
			"replacement_updated_at":     now,
			"revision":                   current.Revision + 1,
			"updated_at":                 now,
		}
		result := tx.Model(&Allocation{}).Where("account_id = ? AND id = ? AND revision = ?", account, id, expectedRevision).Updates(updates)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return ErrExists
		}
		if err := tx.Create(&AllocationHistory{AccountID: account, AllocationID: id, FromState: current.State, ToState: current.State, Reason: fmt.Sprintf("replacement completed: running image now %q", newRunningImage), CreatedAt: now}).Error; err != nil {
			return err
		}
		current.InstanceID = newInstanceID
		current.EstavelleID = newEstavelleID
		current.RunningImage = newRunningImage
		current.ReplacementState = ""
		current.ReplacementInstanceID = ""
		current.ReplacementFailedStep = ""
		current.ReplacementFailureReason = ""
		current.ReplacementUpdatedAt = now
		current.Revision++
		current.UpdatedAt = now
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
// races a step already in progress. Also refused while a zero-downtime
// replacement (issue #560) is in flight, including a failed one: a replaced
// instance a failed replacement already created would otherwise never be
// destroyed, since deprovisioning only ever acts on InstanceID -- an
// administrator must resolve the replacement (RetryReplacement to
// completion) before tearing down the whole allocation.
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
		if current.ReplacementState != "" {
			return fmt.Errorf("%w: a version replacement is in progress -- resolve it before deprovisioning", ErrInvalid)
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

// PendingAcrossAccounts returns every allocation, across every account in
// the deployment, that still needs a reconciliation step -- the
// in-process allocate worker's own entry point (awsdrive_loop.go),
// replacing what used to be an external process's own
// POST /estavelle-allocations/pending poll (still served, deprecated, by
// api/estavelle_allocations.go, for any consumer that already built against
// it). Deliberately unscoped by account: driving an allocation forward is
// not a per-tenant-request operation the way every other method on this
// Store is.
func (s *Store) PendingAcrossAccounts(ctx context.Context) ([]Allocation, error) {
	rows := make([]Allocation, 0)
	err := s.db.WithContext(ctx).
		Where("state IN ?", []string{StateRequested, StateProvisioning, StateGranting, StateRevoking, StateDeprovisioning}).
		Order("created_at, id").
		Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("estavelle allocation: list pending across accounts: %w", err)
	}
	return rows, nil
}

// PendingReplacementsAcrossAccounts returns every allocation, across every
// account, with a zero-downtime replacement (issue #560) still in flight --
// drive_loop.go's replacementTick's own entry point, the replacement
// analog of PendingAcrossAccounts above. "failed" is deliberately excluded,
// matching the main machine's own no-auto-retry-from-failed convention: an
// administrator must call RetryReplacement explicitly.
func (s *Store) PendingReplacementsAcrossAccounts(ctx context.Context) ([]Allocation, error) {
	rows := make([]Allocation, 0)
	err := s.db.WithContext(ctx).
		Where("state = ? AND replacement_state IN ?", StateReady, []string{ReplacementStateProvisioning, ReplacementStateAdmitting, ReplacementStateDraining, ReplacementStateDestroying}).
		Order("created_at, id").
		Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("estavelle allocation: list pending replacements across accounts: %w", err)
	}
	return rows, nil
}

// HasNonTerminalAllocations implements
// infraconnections.AllocationReferenceChecker -- wired once at boot
// (internals/karst/bootstrap, via infraconnections.Store's own
// SetAllocationReferenceChecker) so infraconnections.Store.Delete can
// refuse to remove a connection a live allocation still depends on,
// without an import cycle: infraconnections cannot import this package,
// which already imports infraconnections the other way for Create's own
// reverse validation above. accountID is a plain parameter, not read from
// ctx -- WithAccount's context key here is this package's own and
// unexported, so a caller in infraconnections could not set it on ctx in
// the first place.
func (s *Store) HasNonTerminalAllocations(ctx context.Context, accountID, infraConnectionID string) (bool, error) {
	var count int64
	err := s.db.WithContext(ctx).Model(&Allocation{}).
		Where("account_id = ? AND infra_connection_id = ? AND state != ?", accountID, infraConnectionID, StateDeprovisioned).
		Count(&count).Error
	return count > 0, err
}
