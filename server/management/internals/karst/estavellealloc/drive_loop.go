// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// The in-process reconciliation loop for ADR-0063's admin-triggered relay
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

	"github.com/netbirdio/netbird/management/internals/karst/infraconnections"
	"github.com/netbirdio/netbird/management/internals/karst/infraprovision"
	"github.com/netbirdio/netbird/management/internals/karst/estavellereg"
	"github.com/netbirdio/netbird/management/internals/karst/estavelleservice"
)

// enrollMinter is MintRelayEnrollKey's own narrow shape -- the same
// method api/nodes.go's relay-enroll-tokens handler already calls
// through an identically narrow inline interface, satisfied by
// *server.DefaultAccountManager. Declared here, not imported from
// package server, so this package never depends on it and this loop
// never needs an HTTP/PAT round-trip to mint a token the Rust loop used
// to fetch over POST /relays/enroll-tokens.
type enrollMinter interface {
	MintRelayEnrollKey(ctx context.Context, accountID, poolID string, expiresIn time.Duration) (string, error)
}

// relayFinder is estavellereg.Store's own FindByTLSServerName -- the exact
// method api/relay_allocations.go's handleRelayAllocationGrant already
// calls through its own relayAllocationRegistry interface, narrowed
// identically here.
type relayFinder interface {
	FindByTLSServerName(ctx context.Context, tlsServerName string) (*estavellereg.StoredEstavelle, error)
}

// relayDeenroller is estavellereg.Store's own DeleteByTLSServerName -- issue
// #329's driver-teardown call, now made directly instead of through
// enroll::deenroll's HTTP round-trip.
type relayDeenroller interface {
	DeleteByTLSServerName(ctx context.Context, tlsServerName string) error
}

// relayGrantStore is estavelleservice.Store's own Create/Delete -- the exact
// transactional path ADR-0063 requires granting/revoking go through, not
// a second one. Narrowed identically to api/relay_allocations.go's own
// relayAllocationGrantStore.
type relayGrantStore interface {
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
// that instance's own `karst-relay enroll` redeeming it, not an
// operator-facing window. Mirrors server.defaultRelayEnrollKeyExpiry's own
// value; that constant is unexported, so this package keeps its own copy
// rather than reaching into package server for it.
const enrollTokenExpiry = 10 * time.Minute

// AllocateDeps bundles everything RunAllocateWorker needs beyond the
// Store and the tick interval -- one struct instead of several
// positional parameters, since every field here is a long-lived
// dependency wired once at boot (internals/karst/bootstrap), not a
// per-call argument.
type AllocateDeps struct {
	InfraConnections infraConnections
	Enroll           enrollMinter
	Relays           relayFinder
	Deenroll         relayDeenroller
	Grants           relayGrantStore
	// ControlAPIBase is the management server's own externally-reachable
	// API base URL, embedded in every created instance's enroll bundle so
	// karst-relay enroll knows where to call back -- the Rust loop's own
	// AllocateConfig.control_api_base, now an operator-configured value
	// (KARST_RELAY_ALLOCATE_CONTROL_API_BASE) threaded down from
	// cmd/karst-control/main.go the same way KARST_SCALER_ADVISOR_URL
	// already is. Empty fails every requested allocation closed, with a
	// clear reason, rather than creating an instance that can never
	// enroll.
	ControlAPIBase string
}

// RunAllocateWorker drives every pending ADR-0063 relay allocation,
// across every account, forward by exactly one step per tick. Started
// once, unconditionally, at boot (internals/karst/bootstrap) -- no
// feature flag, the same always-on posture control/relay/console already
// have in the Nomad jobspec, replacing the opt-in `scaler_allocate_enabled`
// var this loop's external predecessor needed.
func RunAllocateWorker(ctx context.Context, store *Store, deps AllocateDeps, interval time.Duration, onError func(error)) {
	tick := func() {
		if err := allocateTick(ctx, store, deps); err != nil {
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
// fan-out api/relay_allocations.go's own `handle` func already builds
// per request (allocCtx/registryCtx/serviceCtx), just once per allocation
// per tick instead of once per HTTP call.
type scopedContexts struct {
	alloc context.Context
	infra context.Context
	relay context.Context
	grant context.Context
}

func allocateTick(ctx context.Context, store *Store, deps AllocateDeps) error {
	pending, err := store.PendingAcrossAccounts(ctx)
	if err != nil {
		return err
	}
	for _, allocation := range pending {
		scoped := scopedContexts{
			alloc: WithAccount(ctx, allocation.AccountID),
			infra: infraconnections.WithAccount(ctx, allocation.AccountID),
			relay: estavellereg.WithAccount(ctx, allocation.AccountID),
			grant: estavelleservice.WithAccount(estavelleservice.WithActor(ctx, "relay-allocation"), allocation.AccountID),
		}
		if err := driveOne(scoped, store, deps, allocation); err != nil {
			log.WithError(err).WithField("allocation_id", allocation.ID).Error("karst: relay allocation: drive step failed")
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
func provisionStep(ctx scopedContexts, store *Store, deps AllocateDeps, allocation Allocation) error {
	driver, err := deps.InfraConnections.ActuationDriver(ctx.infra, allocation.InfraConnectionID)
	if err != nil {
		return failAllocation(ctx.alloc, store, allocation, StateRequested, err)
	}
	if deps.ControlAPIBase == "" {
		return failAllocation(ctx.alloc, store, allocation, StateRequested,
			errors.New("KARST_RELAY_ALLOCATE_CONTROL_API_BASE is not configured"))
	}
	token, err := deps.Enroll.MintRelayEnrollKey(ctx.alloc, allocation.AccountID, allocation.ID, enrollTokenExpiry)
	if err != nil {
		return failAllocation(ctx.alloc, store, allocation, StateRequested, err)
	}
	instance, err := driver.Create(ctx.infra, allocation.ID, infraprovision.CreateRequest{
		ControlAPIBase: deps.ControlAPIBase,
		Token:          token,
	})
	if err != nil {
		return failAllocation(ctx.alloc, store, allocation, StateRequested, err)
	}
	_, err = store.Transition(ctx.alloc, allocation.ID, allocation.Revision, StateRequested, StateProvisioning, "", instance.ID, "")
	return err
}

// grantStep is allocate_loop.rs::grant plus the server-side half
// handleRelayAllocationGrant already performed in-process, now one
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
	relay, err := deps.Relays.FindByTLSServerName(ctx.relay, name)
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
		PonorID:       relay.ID,
		AccessManaged: true,
		AllowedGroups: current.PermittedGroups,
		ExitIPv4:      current.EgressV4,
		ExitIPv6:      current.EgressV6,
	}
	// ErrExists means a previous attempt's Create already landed and only
	// the Transition below crashed or timed out -- resuming forward is
	// correct, not a real failure, same as handleRelayAllocationGrant.
	if _, err := deps.Grants.Create(ctx.grant, service); err != nil && !errors.Is(err, estavelleservice.ErrExists) {
		return failAllocation(ctx.alloc, store, current, StateGranting, err)
	}
	_, err = store.Transition(ctx.alloc, current.ID, current.Revision, StateGranting, StateReady, "", "", relay.ID)
	return err
}

// revokeStep withdraws the grant estavelleservice.Store holds, then moves the
// allocation into deprovisioning -- ADR-0063's reversed teardown order's
// first half, the same call handleRelayAllocationRevoke already made
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
		if err := deps.Deenroll.DeleteByTLSServerName(ctx.relay, tlsServerName); err != nil && !errors.Is(err, estavellereg.ErrNotFound) {
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
			Error("karst: relay allocation: failed, and recording that failure also failed")
	}
	return cause
}
