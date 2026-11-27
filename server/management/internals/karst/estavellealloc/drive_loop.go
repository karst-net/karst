// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// The in-process reconciliation loop for ADR-0063's admin-triggered estavelle
// allocation -- replaces bins/karst-scaler/src/allocate_loop.rs's own
// poll loop (an external Rust binary, now removed) with a goroutine
// inside server/management itself. See ADR-0045's 2026-11-04 addendum and
// ADR-0063's own addendum for why: that external binary required manual,
// per-deployment setup (a locally built AWS-featured binary, a
// hand-written TOML config, an opt-in Nomad raw_exec task) nothing in the
// console flow ever told an administrator to do, so a requested
// allocation reached that state and simply stopped, with no signal why.
//
// ADR-0067 generalized the AWS-only half of this loop (previously
// awsdrive.go, calling the EC2 SDK by name) into infraprovision.Driver,
// so this file never names a cloud SDK call itself -- it drives whichever
// Driver infraconnections.Store.ActuationDriver returns for the
// allocation's own infrastructure connection, AWS or Nomad today.
package estavellealloc

import (
	"context"
	"errors"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/internals/karst/estavellereg"
	"github.com/netbirdio/netbird/management/internals/karst/estavelleservice"
	"github.com/netbirdio/netbird/management/internals/karst/infraconnections"
	"github.com/netbirdio/netbird/management/internals/karst/infraprovision"
	"github.com/netbirdio/netbird/management/internals/karst/roster"
)

// enrollMinter is MintEstavelleEnrollKey's own narrow shape -- the same
// method api/nodes.go's estavelle-enroll-tokens handler already calls
// through an identically narrow inline interface, satisfied by
// *server.DefaultAccountManager. Declared here, not imported from
// package server, so this package never depends on it and this loop
// never needs an HTTP/PAT round-trip to mint a token the Rust loop used
// to fetch over POST /estavelles/enroll-tokens.
type enrollMinter interface {
	MintEstavelleEnrollKey(ctx context.Context, accountID, poolID string, expiresIn time.Duration) (string, error)
}

// estavelleFinder is estavellereg.Store's own FindByTLSServerName -- the exact
// method api/estavelle_allocations.go's handleEstavelleAllocationGrant already
// calls through its own estavelleAllocationRegistry interface, narrowed
// identically here.
type estavelleFinder interface {
	FindByTLSServerName(ctx context.Context, tlsServerName string) (*estavellereg.StoredEstavelle, error)
}

// estavelleDeenroller is estavellereg.Store's own DeleteByTLSServerName -- issue
// #329's driver-teardown call, now made directly instead of through
// enroll::deenroll's HTTP round-trip.
type estavelleDeenroller interface {
	DeleteByTLSServerName(ctx context.Context, tlsServerName string) error
}

// estavelleTelemetryReader is estavellereg.Store's own LatestTelemetry --
// issue #560's "admitting" check needs more than TLSServerName resolving
// and a registry row existing (grantStep already shows that much is not
// proof the relay is actually up): a fresh self-report is proof the
// instance booted, enrolled, and ran at least one telemetry cycle, the
// same distinction api/nodes.go's healthFor already draws between
// "registered" and "confirmed."
type estavelleTelemetryReader interface {
	LatestTelemetry(ctx context.Context, id string) (*estavellereg.EstavelleTelemetryRecord, error)
}

// estavelleGrantStore is estavelleservice.Store's own Create/Delete -- the exact
// transactional path ADR-0063 requires granting/revoking go through, not
// a second one. Narrowed identically to api/estavelle_allocations.go's own
// estavelleAllocationGrantStore.
type estavelleGrantStore interface {
	Create(context.Context, estavelleservice.Service) (*estavelleservice.Service, error)
	Delete(context.Context, string) error
}

// infraConnections is infraconnections.Store's own ActuationDriver
// (ADR-0067) -- narrowed to exactly what this loop needs to actuate
// against a connection, so this package depends on infraconnections.Store's
// method set, not its storage internals.
type infraConnections interface {
	ActuationDriver(ctx context.Context, id string) (infraprovision.Driver, error)
}

// enrollTokenExpiry bounds how long the token minted for a newly created
// instance stays usable -- the boot window between Create returning and
// that instance's own `karst-estavelle enroll` redeeming it, not an
// operator-facing window. Mirrors server.defaultEstavelleEnrollKeyExpiry's own
// value; that constant is unexported, so this package keeps its own copy
// rather than reaching into package server for it.
const enrollTokenExpiry = 10 * time.Minute

// replacementTelemetryFreshWindow mirrors api/nodes.go's own
// relayTelemetryFreshWindow (unexported there, so duplicated here rather
// than imported -- the two packages have no reason to share a dependency
// for one constant): a telemetry report inside this window is this
// package's own proof an instance is genuinely admitting, not just
// registered.
const replacementTelemetryFreshWindow = 3 * time.Minute

// replaceAdmittingTimeout bounds the whole "wait for the replacement to be
// admitting" step (issue #560's own failure-handling requirement: never
// drain the old instance if the new one never comes up). Generous against
// a real cloud boot plus the replacement's own first telemetry report
// (bins/karst-relay's default report interval is 60s) and the roster
// producer's 25s rewrite cycle (roster.DefaultInterval) both docs/
// estavelle-services.md and roster.go already document -- long past either
// figure, not tuned to them closely, since a slow real boot should not be
// mistaken for a stuck one.
const replaceAdmittingTimeout = 10 * time.Minute

// AllocateDeps bundles everything RunAllocateWorker needs beyond the
// Store and the tick interval -- one struct instead of several
// positional parameters, since every field here is a long-lived
// dependency wired once at boot (internals/karst/bootstrap), not a
// per-call argument.
type AllocateDeps struct {
	InfraConnections infraConnections
	Enroll           enrollMinter
	Estavelles       estavelleFinder
	Deenroll         estavelleDeenroller
	Grants           estavelleGrantStore
	// Telemetry backs the "admitting" check a zero-downtime replacement's
	// own admitting step needs (issue #560) -- see estavelleTelemetryReader's
	// own doc comment for why TLSServerName/FindByTLSServerName alone are
	// not enough here, unlike the original provisioning path's grantStep.
	Telemetry estavelleTelemetryReader
	// ControlAPIBase is the management server's own externally-reachable
	// API base URL, embedded in every created instance's enroll bundle so
	// karst-estavelle enroll knows where to call back -- the Rust loop's own
	// AllocateConfig.control_api_base, now an operator-configured value
	// (KARST_RELAY_ALLOCATE_CONTROL_API_BASE) threaded down from
	// cmd/karst-control/main.go the same way KARST_SCALER_ADVISOR_URL
	// already is. Empty fails every requested allocation closed, with a
	// clear reason, rather than creating an instance that can never
	// enroll.
	ControlAPIBase string
	// ControlAPICACertPEM is an optional, additional trust anchor (PEM
	// text) for every created instance's own enroll call to
	// ControlAPIBase -- KARST_RELAY_ALLOCATE_CONTROL_API_CA_PEM, threaded
	// down the same way ControlAPIBase is. Empty (every deployment behind
	// a publicly-issued certificate) means unchanged behavior from before
	// this field existed.
	ControlAPICACertPEM string
}

// RunAllocateWorker drives every pending ADR-0063 estavelle allocation,
// across every account, forward by exactly one step per tick. Started
// once, unconditionally, at boot (internals/karst/bootstrap) -- no
// feature flag, the same always-on posture control/estavelle/console already
// have in the Nomad jobspec, replacing the opt-in `scaler_allocate_enabled`
// var this loop's external predecessor needed.
func RunAllocateWorker(ctx context.Context, store *Store, deps AllocateDeps, interval time.Duration, onError func(error)) {
	tick := func() {
		if err := allocateTick(ctx, store, deps); err != nil {
			onError(err)
		}
		// Replacements drive after the main pass, same ticker, same
		// synchronous-not-concurrent discipline -- a replacement only ever
		// touches a StateReady allocation's side-channel fields, so it
		// never contends with the main pass's own CAS writes on the same
		// row.
		if err := replacementTick(ctx, store, deps); err != nil {
			onError(err)
		}
	}
	tick()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Synchronous, deliberately: a Driver's Create/Drain/Destroy
			// are slow, side-effecting calls, so a tick that outlasts
			// interval must never run concurrently with the next one --
			// calling tick() inline, rather than `go tick()`, makes that
			// structural. time.Ticker drops a tick instead of queuing one
			// while the previous send on ticker.C is still unread, so a
			// slow tick simply delays the next one rather than
			// overlapping it.
			tick()
		}
	}
}

// scopedContexts carries one allocation's account scoped four different
// ways -- estavellealloc's own WithAccount plus infraconnections'/estavellereg'/
// estavelleservice's, each package's own unexported context key, the same
// fan-out api/estavelle_allocations.go's own `handle` func already builds
// per request (allocCtx/registryCtx/serviceCtx), just once per allocation
// per tick instead of once per HTTP call.
type scopedContexts struct {
	alloc     context.Context
	infra     context.Context
	estavelle context.Context
	grant     context.Context
}

func allocateTick(ctx context.Context, store *Store, deps AllocateDeps) error {
	pending, err := store.PendingAcrossAccounts(ctx)
	if err != nil {
		return err
	}
	for _, allocation := range pending {
		scoped := scopedContexts{
			alloc:     WithAccount(ctx, allocation.AccountID),
			infra:     infraconnections.WithAccount(ctx, allocation.AccountID),
			estavelle: estavellereg.WithAccount(ctx, allocation.AccountID),
			grant:     estavelleservice.WithAccount(estavelleservice.WithActor(ctx, "estavelle-allocation"), allocation.AccountID),
		}
		if err := driveOne(scoped, store, deps, allocation); err != nil {
			log.WithError(err).WithField("allocation_id", allocation.ID).Error("karst: estavelle allocation: drive step failed")
		}
	}
	return nil
}

func driveOne(ctx scopedContexts, store *Store, deps AllocateDeps, allocation Allocation) error {
	switch allocation.State {
	case StateRequested:
		return provisionStep(ctx, store, deps, allocation)
	case StateProvisioning, StateGranting:
		return grantStep(ctx, store, deps, allocation)
	case StateRevoking:
		return revokeStep(ctx, store, deps, allocation)
	case StateDeprovisioning:
		return deprovisionStep(ctx, store, deps, allocation)
	default:
		// ready/failed/deprovisioned never appear here: PendingAcrossAccounts
		// (store.go) already filters to the five in-flight states.
		return fmt.Errorf("allocation %s: unrecognized state %q", allocation.ID, allocation.State)
	}
}

// provisionStep calls the allocation's own Driver.Create, which looks for
// an already-live instance under this allocation's own correlation first
// (a retry after a crash between a previous successful Create and this
// function's own Transition call landing) before provisioning a new one.
// RunningImage is already populated at this point if the console's
// allocation request named one (Store.Create) -- empty just means "use
// the connection's own launch default," passed through unchanged.
func provisionStep(ctx scopedContexts, store *Store, deps AllocateDeps, allocation Allocation) error {
	driver, err := deps.InfraConnections.ActuationDriver(ctx.infra, allocation.InfraConnectionID)
	if err != nil {
		return failAllocation(ctx.alloc, store, allocation, StateRequested, err)
	}
	if deps.ControlAPIBase == "" {
		return failAllocation(ctx.alloc, store, allocation, StateRequested,
			errors.New("KARST_RELAY_ALLOCATE_CONTROL_API_BASE is not configured"))
	}
	token, err := deps.Enroll.MintEstavelleEnrollKey(ctx.alloc, allocation.AccountID, allocation.ID, enrollTokenExpiry)
	if err != nil {
		return failAllocation(ctx.alloc, store, allocation, StateRequested, err)
	}
	instance, err := driver.Create(ctx.infra, allocation.ID, infraprovision.CreateRequest{
		ControlAPIBase:      deps.ControlAPIBase,
		ControlAPICACertPEM: deps.ControlAPICACertPEM,
		Token:               token,
		Image:               allocation.RunningImage,
	})
	if err != nil {
		return failAllocation(ctx.alloc, store, allocation, StateRequested, err)
	}
	_, err = store.Transition(ctx.alloc, allocation.ID, allocation.Revision, StateRequested, StateProvisioning, "", instance.ID, "")
	return err
}

// grantStep is allocate_loop.rs::grant plus the server-side half
// handleEstavelleAllocationGrant already performed in-process, now one
// function instead of an HTTP round trip between them. Reached from both
// StateProvisioning (first attempt) and StateGranting (a resumed one
// after this loop itself restarted) -- the Driver's own TLSServerName is
// re-read every time, never cached in this process, for the same
// restart-survival reason.
func grantStep(ctx scopedContexts, store *Store, deps AllocateDeps, allocation Allocation) error {
	driver, err := deps.InfraConnections.ActuationDriver(ctx.infra, allocation.InfraConnectionID)
	if err != nil {
		return failAllocation(ctx.alloc, store, allocation, allocation.State, err)
	}
	name, err := driver.TLSServerName(ctx.infra, allocation.InstanceID)
	if err != nil {
		return failAllocation(ctx.alloc, store, allocation, allocation.State, err)
	}
	if name == "" {
		// The instance exists but has not finished announcing its own
		// correlation label yet (should be near-instantaneous after
		// Create, but a provider's own eventual-consistency window on a
		// just-created resource is real) -- not a failure, retry next
		// tick.
		return nil
	}
	estavelle, err := deps.Estavelles.FindByTLSServerName(ctx.estavelle, name)
	if err != nil {
		if errors.Is(err, estavellereg.ErrNotFound) {
			return nil // not registered yet -- not a failure, retry next tick
		}
		return failAllocation(ctx.alloc, store, allocation, allocation.State, err)
	}
	current := allocation
	if current.State == StateProvisioning {
		updated, err := store.Transition(ctx.alloc, current.ID, current.Revision, StateProvisioning, StateGranting, "", "", "")
		if err != nil {
			return err
		}
		current = *updated
	}
	service := estavelleservice.Service{
		ID:            current.ID,
		PonorID:       estavelle.ID,
		AccessManaged: true,
		AllowedGroups: current.PermittedGroups,
		ExitIPv4:      current.EgressV4,
		ExitIPv6:      current.EgressV6,
	}
	// ErrExists means a previous attempt's Create already landed and only
	// the Transition below crashed or timed out -- resuming forward is
	// correct, not a real failure, same as handleEstavelleAllocationGrant.
	if _, err := deps.Grants.Create(ctx.grant, service); err != nil && !errors.Is(err, estavelleservice.ErrExists) {
		return failAllocation(ctx.alloc, store, current, StateGranting, err)
	}
	_, err = store.Transition(ctx.alloc, current.ID, current.Revision, StateGranting, StateReady, "", "", estavelle.ID)
	return err
}

// revokeStep withdraws the grant estavelleservice.Store holds, then moves the
// allocation into deprovisioning -- ADR-0063's reversed teardown order's
// first half, the same call handleEstavelleAllocationRevoke already made
// in-process.
func revokeStep(ctx scopedContexts, store *Store, deps AllocateDeps, allocation Allocation) error {
	if err := deps.Grants.Delete(ctx.grant, allocation.ID); err != nil && !errors.Is(err, estavelleservice.ErrNotFound) {
		return failAllocation(ctx.alloc, store, allocation, StateRevoking, err)
	}
	_, err := store.Transition(ctx.alloc, allocation.ID, allocation.Revision, StateRevoking, StateDeprovisioning, "", "", "")
	return err
}

// deprovisionStep drains then destroys the instance, deenrolling its
// estavellereg row by the same correlation label grantStep already relied
// on -- the grant was already withdrawn by revokeStep above, before this
// ever runs, so nothing here can leave an access grant pointing at
// compute the system believes torn down. Idempotent once nothing is left
// to destroy (InstanceID already empty, or the Driver reports it already
// gone).
func deprovisionStep(ctx scopedContexts, store *Store, deps AllocateDeps, allocation Allocation) error {
	if allocation.InstanceID == "" {
		_, err := store.Transition(ctx.alloc, allocation.ID, allocation.Revision, StateDeprovisioning, StateDeprovisioned, "", "", "")
		return err
	}
	driver, err := deps.InfraConnections.ActuationDriver(ctx.infra, allocation.InfraConnectionID)
	if err != nil {
		return failAllocation(ctx.alloc, store, allocation, StateDeprovisioning, err)
	}
	if err := driver.Drain(ctx.infra, allocation.InstanceID); err != nil {
		return failAllocation(ctx.alloc, store, allocation, StateDeprovisioning, err)
	}
	tlsServerName, err := driver.Destroy(ctx.infra, allocation.InstanceID)
	if err != nil {
		return failAllocation(ctx.alloc, store, allocation, StateDeprovisioning, err)
	}
	if tlsServerName != "" {
		if err := deps.Deenroll.DeleteByTLSServerName(ctx.estavelle, tlsServerName); err != nil && !errors.Is(err, estavellereg.ErrNotFound) {
			return failAllocation(ctx.alloc, store, allocation, StateDeprovisioning, err)
		}
	}
	_, err = store.Transition(ctx.alloc, allocation.ID, allocation.Revision, StateDeprovisioning, StateDeprovisioned, "", "", "")
	return err
}

// failAllocation transitions allocation to StateFailed, recording cause's
// message as the reason, and returns cause itself -- not any secondary
// error recording the transition -- since that is what the tick loop
// logs and what matters to an operator reading it.
func failAllocation(ctx context.Context, store *Store, allocation Allocation, from string, cause error) error {
	if _, err := store.Transition(ctx, allocation.ID, allocation.Revision, from, StateFailed, cause.Error(), "", ""); err != nil {
		log.WithError(err).WithField("allocation_id", allocation.ID).
			Error("karst: estavelle allocation: failed, and recording that failure also failed")
	}
	return cause
}

// replacementCorrelationID is the Create correlation tag a replacement's
// new instance is provisioned under (issue #560) -- deliberately distinct
// from allocationID itself, so a Driver's own crash-safe "already live"
// lookup (awsdriver's describeLiveInstanceByPool, nomaddriver's
// describeLiveByAllocation) never finds the still-running *old* instance,
// still tagged under the bare allocation ID, and mistakes it for an
// already-created replacement. Purely a Go-side tag value this package
// controls, not a foreign key -- no driver code depends on its shape, only
// on it being stable across ticks for the same in-flight replacement.
func replacementCorrelationID(allocationID string) string {
	return allocationID + "/replace"
}

// replacementTick drives every StateReady allocation with a non-failed,
// non-empty ReplacementState forward by exactly one step -- the
// replacement analog of allocateTick, run from the same ticker
// (RunAllocateWorker) right after the main pass.
func replacementTick(ctx context.Context, store *Store, deps AllocateDeps) error {
	pending, err := store.PendingReplacementsAcrossAccounts(ctx)
	if err != nil {
		return err
	}
	for _, allocation := range pending {
		scoped := scopedContexts{
			alloc:     WithAccount(ctx, allocation.AccountID),
			infra:     infraconnections.WithAccount(ctx, allocation.AccountID),
			estavelle: estavellereg.WithAccount(ctx, allocation.AccountID),
			grant:     estavelleservice.WithAccount(estavelleservice.WithActor(ctx, "estavelle-allocation"), allocation.AccountID),
		}
		if err := driveReplacement(scoped, store, deps, allocation); err != nil {
			log.WithError(err).WithField("allocation_id", allocation.ID).Error("karst: estavelle allocation: replacement drive step failed")
		}
	}
	return nil
}

func driveReplacement(ctx scopedContexts, store *Store, deps AllocateDeps, allocation Allocation) error {
	switch allocation.ReplacementState {
	case ReplacementStateProvisioning:
		return replaceProvisionStep(ctx, store, deps, allocation)
	case ReplacementStateAdmitting:
		return replaceAdmitStep(ctx, store, deps, allocation)
	case ReplacementStateDraining:
		return replaceDrainStep(ctx, store, deps, allocation)
	case ReplacementStateDestroying:
		return replaceDestroyStep(ctx, store, deps, allocation)
	default:
		// "failed" never appears here: PendingReplacementsAcrossAccounts
		// already excludes it.
		return fmt.Errorf("allocation %s: unrecognized replacement state %q", allocation.ID, allocation.ReplacementState)
	}
}

// replaceProvisionStep creates the new instance at DesiredImage, under
// replacementCorrelationID rather than the allocation's own ID -- see that
// helper's own doc comment. The old instance (allocation.InstanceID) is
// never touched here.
func replaceProvisionStep(ctx scopedContexts, store *Store, deps AllocateDeps, allocation Allocation) error {
	driver, err := deps.InfraConnections.ActuationDriver(ctx.infra, allocation.InfraConnectionID)
	if err != nil {
		return failReplacement(ctx.alloc, store, allocation, ReplacementStateProvisioning, err)
	}
	if deps.ControlAPIBase == "" {
		return failReplacement(ctx.alloc, store, allocation, ReplacementStateProvisioning,
			errors.New("KARST_RELAY_ALLOCATE_CONTROL_API_BASE is not configured"))
	}
	correlationID := replacementCorrelationID(allocation.ID)
	token, err := deps.Enroll.MintEstavelleEnrollKey(ctx.alloc, allocation.AccountID, correlationID, enrollTokenExpiry)
	if err != nil {
		return failReplacement(ctx.alloc, store, allocation, ReplacementStateProvisioning, err)
	}
	instance, err := driver.Create(ctx.infra, correlationID, infraprovision.CreateRequest{
		ControlAPIBase:      deps.ControlAPIBase,
		ControlAPICACertPEM: deps.ControlAPICACertPEM,
		Token:               token,
		Image:               allocation.DesiredImage,
	})
	if err != nil {
		return failReplacement(ctx.alloc, store, allocation, ReplacementStateProvisioning, err)
	}
	_, err = store.TransitionReplacement(ctx.alloc, allocation.ID, allocation.Revision, ReplacementStateProvisioning, ReplacementStateAdmitting, instance.ID)
	return err
}

// replacementIsAdmitting is the "more than TLSServerName resolving" check
// estavelleTelemetryReader's own doc comment describes: registered, AND a
// fresh self-report (proof it actually booted and ran), AND at least one
// full roster.DefaultInterval since this replacement entered the admitting
// step -- an explicit, checked margin for the control-plane's roster
// producer to have picked up the new registration at least once, rather
// than relying on the fresh-telemetry window to imply it incidentally.
func replacementIsAdmitting(ctx scopedContexts, deps AllocateDeps, driver infraprovision.Driver, allocation Allocation) (bool, error) {
	name, err := driver.TLSServerName(ctx.infra, allocation.ReplacementInstanceID)
	if err != nil {
		return false, err
	}
	if name == "" {
		return false, nil // boot window hasn't finished -- retry later
	}
	estavelle, err := deps.Estavelles.FindByTLSServerName(ctx.estavelle, name)
	if err != nil {
		if errors.Is(err, estavellereg.ErrNotFound) {
			return false, nil // not registered yet -- retry later
		}
		return false, err
	}
	if deps.Telemetry == nil {
		return false, nil
	}
	record, err := deps.Telemetry.LatestTelemetry(ctx.estavelle, estavelle.ID)
	if err != nil {
		return false, err
	}
	if record == nil || time.Since(record.ReportedAt) > replacementTelemetryFreshWindow {
		return false, nil // registered, but never (or no longer) self-reporting
	}
	if time.Since(allocation.ReplacementUpdatedAt) < roster.DefaultInterval {
		return false, nil // give the roster producer's own cycle time to pick this up
	}
	return true, nil
}

// replaceAdmitStep waits for the new instance to be admitting (not just
// registered -- see replacementIsAdmitting), bounded by
// replaceAdmittingTimeout. A timeout cleans up the half-created
// replacement instance best-effort and fails the replacement without ever
// touching the old instance -- the issue's own explicit failure-handling
// requirement.
func replaceAdmitStep(ctx scopedContexts, store *Store, deps AllocateDeps, allocation Allocation) error {
	driver, err := deps.InfraConnections.ActuationDriver(ctx.infra, allocation.InfraConnectionID)
	if err != nil {
		return failReplacement(ctx.alloc, store, allocation, ReplacementStateAdmitting, err)
	}
	admitting, err := replacementIsAdmitting(ctx, deps, driver, allocation)
	if err != nil {
		return failReplacement(ctx.alloc, store, allocation, ReplacementStateAdmitting, err)
	}
	if admitting {
		_, err = store.TransitionReplacement(ctx.alloc, allocation.ID, allocation.Revision, ReplacementStateAdmitting, ReplacementStateDraining, "")
		return err
	}
	if time.Since(allocation.ReplacementUpdatedAt) <= replaceAdmittingTimeout {
		return nil // not admitting yet -- retry next tick
	}
	cause := fmt.Errorf("replacement instance never became admitting within %s", replaceAdmittingTimeout)
	if allocation.ReplacementInstanceID != "" {
		if err := driver.Drain(ctx.infra, allocation.ReplacementInstanceID); err != nil {
			log.WithError(err).WithField("allocation_id", allocation.ID).Warn("karst: estavelle allocation: replacement cleanup: drain failed")
		}
		if _, err := driver.Destroy(ctx.infra, allocation.ReplacementInstanceID); err != nil {
			log.WithError(err).WithField("allocation_id", allocation.ID).Warn("karst: estavelle allocation: replacement cleanup: destroy failed")
		}
	}
	return failReplacement(ctx.alloc, store, allocation, ReplacementStateAdmitting, cause)
}

// replaceDrainStep drains the *old* instance -- only reached once
// replaceAdmitStep has confirmed the new one is admitting, so this can
// never produce an estavelle-admission gap. driver.Drain's own bounded poll
// (both drivers' drainTimeout) is what gives in-flight clients on the old
// instance time to be told and migrate, exactly as deprovisionStep already
// relies on for ordinary teardown.
func replaceDrainStep(ctx scopedContexts, store *Store, deps AllocateDeps, allocation Allocation) error {
	driver, err := deps.InfraConnections.ActuationDriver(ctx.infra, allocation.InfraConnectionID)
	if err != nil {
		return failReplacement(ctx.alloc, store, allocation, ReplacementStateDraining, err)
	}
	if err := driver.Drain(ctx.infra, allocation.InstanceID); err != nil {
		return failReplacement(ctx.alloc, store, allocation, ReplacementStateDraining, err)
	}
	_, err = store.TransitionReplacement(ctx.alloc, allocation.ID, allocation.Revision, ReplacementStateDraining, ReplacementStateDestroying, "")
	return err
}

// replaceDestroyStep destroys the old instance, deenrolls its registry
// row, then cuts over: the new instance becomes the allocation's instance
// of record (CompleteReplacement). Resumable: a retry after a failure here
// re-destroys allocation.InstanceID (the drivers' own Destroy is
// idempotent once nothing is left, mirroring deprovisionStep's identical
// assumption) rather than creating anything new.
func replaceDestroyStep(ctx scopedContexts, store *Store, deps AllocateDeps, allocation Allocation) error {
	driver, err := deps.InfraConnections.ActuationDriver(ctx.infra, allocation.InfraConnectionID)
	if err != nil {
		return failReplacement(ctx.alloc, store, allocation, ReplacementStateDestroying, err)
	}
	tlsServerName, err := driver.Destroy(ctx.infra, allocation.InstanceID)
	if err != nil {
		return failReplacement(ctx.alloc, store, allocation, ReplacementStateDestroying, err)
	}
	if tlsServerName != "" {
		if err := deps.Deenroll.DeleteByTLSServerName(ctx.estavelle, tlsServerName); err != nil && !errors.Is(err, estavellereg.ErrNotFound) {
			return failReplacement(ctx.alloc, store, allocation, ReplacementStateDestroying, err)
		}
	}
	// Re-read the new instance's own registration rather than carrying
	// anything cached from replaceAdmitStep -- the same never-cache-across-
	// a-possible-restart discipline grantStep already follows.
	newTLSServerName, err := driver.TLSServerName(ctx.infra, allocation.ReplacementInstanceID)
	if err != nil {
		return failReplacement(ctx.alloc, store, allocation, ReplacementStateDestroying, err)
	}
	newEstavelle, err := deps.Estavelles.FindByTLSServerName(ctx.estavelle, newTLSServerName)
	if err != nil {
		return failReplacement(ctx.alloc, store, allocation, ReplacementStateDestroying, err)
	}
	_, err = store.CompleteReplacement(ctx.alloc, allocation.ID, allocation.Revision, allocation.ReplacementInstanceID, newEstavelle.ID, allocation.DesiredImage)
	return err
}

// failReplacement records that the replacement stuck at from, leaving the
// old instance and the allocation's main State entirely untouched -- the
// replacement analog of failAllocation.
func failReplacement(ctx context.Context, store *Store, allocation Allocation, from string, cause error) error {
	if _, err := store.FailReplacement(ctx, allocation.ID, allocation.Revision, from, cause.Error()); err != nil {
		log.WithError(err).WithField("allocation_id", allocation.ID).
			Error("karst: estavelle allocation: replacement failed, and recording that failure also failed")
	}
	return cause
}
