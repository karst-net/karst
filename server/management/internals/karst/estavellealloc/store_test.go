// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package estavellealloc

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/netbirdio/netbird/management/internals/karst/infraconnections"
	"github.com/netbirdio/netbird/management/internals/karst/locationreg"
	"github.com/netbirdio/netbird/management/server/types"
)

// env is the fixture's own handle on everything a test needs: the store
// under test, plus one already-valid infra connection and group id in
// account "a" so draft() always starts from a Create-able allocation.
type env struct {
	store        *Store
	db           *gorm.DB
	connectionID string
	groupID      string
}

func fixture(t *testing.T) env {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:%s?mode=memory&cache=shared", t.Name())), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sqlDB.Close()) })
	require.NoError(t, db.AutoMigrate(&infraconnections.Account{}, &types.Group{}))
	store, err := NewStore(db)
	require.NoError(t, err)
	// Create refuses every request until this is set (ADR-0045 §6 bullet
	// 4's "mandatory configuration, no unlimited value," applied to this
	// actuator by that ADR's 2026-11-04 addendum) -- high enough that no
	// existing test's own handful of allocations trips it.
	store.SetMaxConcurrentAllocations(100)
	connection := infraconnections.Account{ID: "conn-1", AccountID: "a", Type: infraconnections.TypeAWS, Mode: infraconnections.ModeReadWrite, Label: "aws"}
	require.NoError(t, db.Create(&connection).Error)
	group := types.Group{ID: "engineering", AccountID: "a", Name: "Engineering"}
	require.NoError(t, db.Create(&group).Error)
	// draft()'s own "us-west-2" location must already be authorized --
	// requireAuthorizedLocation rejects a Create otherwise. Coordinates
	// match cloudcatalog's own entry for it exactly, the same source
	// requireAuthorizedLocation itself resolves a cloud location through.
	authorized := locationreg.StoredLocation{AccountID: "a", ID: "loc-1", Lat: 45.8696, Lon: -119.6880, Label: "US West (Oregon)"}
	require.NoError(t, db.Create(&authorized).Error)
	return env{store: store, db: db, connectionID: connection.ID, groupID: group.ID}
}

func (e env) draft() Allocation {
	return Allocation{
		Name:              "denver",
		InfraConnectionID: e.connectionID,
		Location:          "us-west-2",
		EstavelleTransport:    true,
		PermittedGroups:   []string{e.groupID},
	}
}

func TestCreateValidatesReferencesAndAssignsRequestedState(t *testing.T) {
	e := fixture(t)
	ctx := WithAccount(context.Background(), "a")
	created, err := e.store.Create(ctx, e.draft())
	require.NoError(t, err)
	require.NotEmpty(t, created.ID)
	require.Equal(t, "a", created.AccountID)
	require.Equal(t, StateRequested, created.State)
	require.EqualValues(t, 1, created.Revision)

	var historyCount int64
	require.NoError(t, e.db.Model(&AllocationHistory{}).Where("allocation_id = ?", created.ID).Count(&historyCount).Error)
	require.EqualValues(t, 1, historyCount)
}

func TestCreateRequiresAccountScope(t *testing.T) {
	e := fixture(t)
	_, err := e.store.Create(context.Background(), e.draft())
	require.ErrorIs(t, err, ErrNoAccount)
}

func TestCreateRejectsAnUnknownInfraConnectionAndWritesNothing(t *testing.T) {
	e := fixture(t)
	ctx := WithAccount(context.Background(), "a")
	draft := e.draft()
	draft.InfraConnectionID = "missing"
	_, err := e.store.Create(ctx, draft)
	require.ErrorIs(t, err, ErrInvalid)

	var count int64
	require.NoError(t, e.db.Model(&Allocation{}).Count(&count).Error)
	require.Zero(t, count)
	require.NoError(t, e.db.Model(&AllocationHistory{}).Count(&count).Error)
	require.Zero(t, count)
}

func TestCreateRejectsALocationNotInTheAuthorizedLocationsRegistry(t *testing.T) {
	e := fixture(t)
	ctx := WithAccount(context.Background(), "a")
	draft := e.draft()
	// A real AWS region, resolvable via cloudcatalog -- but never added to
	// account "a"'s Authorized Locations registry, unlike draft()'s own
	// "us-west-2" (see fixture()).
	draft.Location = "us-east-1"
	_, err := e.store.Create(ctx, draft)
	require.ErrorIs(t, err, ErrInvalid)
	require.ErrorContains(t, err, "not in the authorized locations registry")

	var count int64
	require.NoError(t, e.db.Model(&Allocation{}).Count(&count).Error)
	require.Zero(t, count)
}

func TestCreateRejectsALocationNotResolvableAtAll(t *testing.T) {
	e := fixture(t)
	ctx := WithAccount(context.Background(), "a")
	draft := e.draft()
	draft.Location = "aws-code-not-in-the-static-catalog"
	_, err := e.store.Create(ctx, draft)
	require.ErrorIs(t, err, ErrInvalid)
	require.ErrorContains(t, err, "no known coordinates")
}

func TestCreateAcceptsAClusterConnectionsDeclaredLocationWhenAuthorized(t *testing.T) {
	e := fixture(t)
	ctx := WithAccount(context.Background(), "a")
	lat, lon := 51.5072, -0.1276
	// TypeNomad, picked arbitrarily among the cluster types with a
	// registered infraprovision.Driver (ADR-0067: Nomad and Kubernetes
	// both do) -- any of them exercises requireAuthorizedLocation's same
	// "cluster connection, declared Lat/Lon" default branch identically.
	// A cluster type with no driver (Azure has none, and is not even a
	// "cluster connection" for this branch's purposes) is rejected before
	// ever reaching this logic -- see TestCreateRejectsAnUnsupportedConnectionType.
	cluster := infraconnections.Account{ID: "conn-nomad", AccountID: "a", Type: infraconnections.TypeNomad, Mode: infraconnections.ModeReadOnly, Label: "nomad", Lat: &lat, Lon: &lon}
	require.NoError(t, e.db.Create(&cluster).Error)
	require.NoError(t, e.db.Create(&locationreg.StoredLocation{AccountID: "a", ID: "loc-london", Lat: lat, Lon: lon, Label: "London cluster"}).Error)
	draft := e.draft()
	draft.InfraConnectionID = cluster.ID
	draft.Location = "default"
	_, err := e.store.Create(ctx, draft)
	require.NoError(t, err)
}

func TestCreateRejectsAClusterConnectionWithNoDeclaredLocation(t *testing.T) {
	e := fixture(t)
	ctx := WithAccount(context.Background(), "a")
	cluster := infraconnections.Account{ID: "conn-nomad", AccountID: "a", Type: infraconnections.TypeNomad, Mode: infraconnections.ModeReadOnly, Label: "nomad"}
	require.NoError(t, e.db.Create(&cluster).Error)
	draft := e.draft()
	draft.InfraConnectionID = cluster.ID
	draft.Location = "default"
	_, err := e.store.Create(ctx, draft)
	require.ErrorIs(t, err, ErrInvalid)
	require.ErrorContains(t, err, "no declared location")
}

func TestCreateRejectsAnUnsupportedConnectionType(t *testing.T) {
	e := fixture(t)
	ctx := WithAccount(context.Background(), "a")
	// Azure, not Kubernetes: ADR-0067 added a Kubernetes driver, so it no
	// longer belongs in this test -- Azure has no infraprovision.Driver
	// and (unlike a cluster type) needs no declared-location fixture at
	// all, since requireAuthorizedLocation's "cluster connection" branch
	// doesn't apply to it; this check must fail before reaching that
	// logic regardless.
	connection := infraconnections.Account{ID: "conn-azure", AccountID: "a", Type: infraconnections.TypeAzure, Mode: infraconnections.ModeReadOnly, Label: "azure"}
	require.NoError(t, e.db.Create(&connection).Error)
	draft := e.draft()
	draft.InfraConnectionID = connection.ID
	draft.Location = "default"

	_, err := e.store.Create(ctx, draft)

	require.ErrorIs(t, err, ErrInvalid)
	require.ErrorContains(t, err, `"azure"`)
	var count int64
	require.NoError(t, e.db.Model(&Allocation{}).Count(&count).Error)
	require.Zero(t, count, "a connection type with no driver must never reach StateRequested")
}

func TestCreateRejectsAnUnavailableGroupAndWritesNothing(t *testing.T) {
	e := fixture(t)
	ctx := WithAccount(context.Background(), "a")
	draft := e.draft()
	draft.PermittedGroups = []string{"not-a-group"}
	_, err := e.store.Create(ctx, draft)
	require.ErrorIs(t, err, ErrInvalid)

	var count int64
	require.NoError(t, e.db.Model(&Allocation{}).Count(&count).Error)
	require.Zero(t, count)
}

func TestCreateRejectsNoCapabilityAndNoGroup(t *testing.T) {
	e := fixture(t)
	ctx := WithAccount(context.Background(), "a")

	noCapability := e.draft()
	noCapability.EstavelleTransport = false
	_, err := e.store.Create(ctx, noCapability)
	require.ErrorIs(t, err, ErrInvalid)

	noGroup := e.draft()
	noGroup.PermittedGroups = nil
	_, err = e.store.Create(ctx, noGroup)
	require.ErrorIs(t, err, ErrInvalid)
}

func TestCreateRejectsEgressUntilGatewayBindingIsDesigned(t *testing.T) {
	e := fixture(t)
	ctx := WithAccount(context.Background(), "a")

	v4 := e.draft()
	v4.EgressV4 = true
	_, err := e.store.Create(ctx, v4)
	require.ErrorIs(t, err, ErrInvalid)

	v6 := e.draft()
	v6.EgressV6 = true
	_, err = e.store.Create(ctx, v6)
	require.ErrorIs(t, err, ErrInvalid)

	var count int64
	require.NoError(t, e.db.Model(&Allocation{}).Count(&count).Error)
	require.Zero(t, count)
}

func TestCreateIgnoresCallerSuppliedIdentityFields(t *testing.T) {
	e := fixture(t)
	ctx := WithAccount(context.Background(), "a")
	draft := e.draft()
	draft.ID = "spoofed"
	draft.AccountID = "spoofed-account"
	draft.State = StateReady
	draft.Revision = 99
	created, err := e.store.Create(ctx, draft)
	require.NoError(t, err)
	require.NotEqual(t, "spoofed", created.ID)
	require.Equal(t, "a", created.AccountID)
	require.Equal(t, StateRequested, created.State)
	require.EqualValues(t, 1, created.Revision)
}

func TestTransitionWalksTheHappyPathToReady(t *testing.T) {
	e := fixture(t)
	ctx := WithAccount(context.Background(), "a")
	created, err := e.store.Create(ctx, e.draft())
	require.NoError(t, err)

	provisioning, err := e.store.Transition(ctx, created.ID, created.Revision, StateRequested, StateProvisioning, "", "", "")
	require.NoError(t, err)
	require.Equal(t, StateProvisioning, provisioning.State)

	granting, err := e.store.Transition(ctx, created.ID, provisioning.Revision, StateProvisioning, StateGranting, "", "instance-1", "")
	require.NoError(t, err)
	require.Equal(t, StateGranting, granting.State)
	require.Equal(t, "instance-1", granting.InstanceID)

	ready, err := e.store.Transition(ctx, created.ID, granting.Revision, StateGranting, StateReady, "", "", "relay-1")
	require.NoError(t, err)
	require.Equal(t, StateReady, ready.State)
	require.Equal(t, "instance-1", ready.InstanceID)
	require.Equal(t, "relay-1", ready.EstavelleID)

	var historyCount int64
	require.NoError(t, e.db.Model(&AllocationHistory{}).Where("allocation_id = ?", created.ID).Count(&historyCount).Error)
	require.EqualValues(t, 4, historyCount) // requested, provisioning, granting, ready
}

func TestTransitionRejectsAnIllegalEdge(t *testing.T) {
	e := fixture(t)
	ctx := WithAccount(context.Background(), "a")
	created, err := e.store.Create(ctx, e.draft())
	require.NoError(t, err)

	_, err = e.store.Transition(ctx, created.ID, created.Revision, StateRequested, StateReady, "", "", "")
	require.ErrorIs(t, err, ErrInvalid)

	var current Allocation
	require.NoError(t, e.db.First(&current, "id = ?", created.ID).Error)
	require.Equal(t, StateRequested, current.State)
}

func TestTransitionToFailedRecordsStepAndReason(t *testing.T) {
	e := fixture(t)
	ctx := WithAccount(context.Background(), "a")
	created, err := e.store.Create(ctx, e.draft())
	require.NoError(t, err)
	provisioning, err := e.store.Transition(ctx, created.ID, created.Revision, StateRequested, StateProvisioning, "", "", "")
	require.NoError(t, err)

	failed, err := e.store.Transition(ctx, created.ID, provisioning.Revision, StateProvisioning, StateFailed, "quota exceeded", "", "")
	require.NoError(t, err)
	require.Equal(t, StateFailed, failed.State)
	require.Equal(t, StateProvisioning, failed.FailedStep)
	require.Equal(t, "quota exceeded", failed.FailureReason)
}

func TestTransitionIsCompareAndSetAgainstBothRevisionAndState(t *testing.T) {
	e := fixture(t)
	ctx := WithAccount(context.Background(), "a")
	created, err := e.store.Create(ctx, e.draft())
	require.NoError(t, err)

	_, err = e.store.Transition(ctx, created.ID, created.Revision+1, StateRequested, StateProvisioning, "", "", "")
	require.ErrorIs(t, err, ErrExists)

	first, err := e.store.Transition(ctx, created.ID, created.Revision, StateRequested, StateProvisioning, "", "", "")
	require.NoError(t, err)

	// Reusing the now-stale revision/state pair a second time must fail,
	// not double-apply -- the same race a concurrent admin edit or a
	// re-run reconciliation tick could otherwise hit.
	_, err = e.store.Transition(ctx, created.ID, created.Revision, StateRequested, StateProvisioning, "", "", "")
	require.ErrorIs(t, err, ErrExists)

	var historyCount int64
	require.NoError(t, e.db.Model(&AllocationHistory{}).Where("allocation_id = ?", created.ID).Count(&historyCount).Error)
	require.EqualValues(t, 2, historyCount) // requested, provisioning -- never 3

	require.Equal(t, StateProvisioning, first.State)
}

func TestTransitionRequiresAccountScopeAndRespectsAccountBoundary(t *testing.T) {
	e := fixture(t)
	ctx := WithAccount(context.Background(), "a")
	created, err := e.store.Create(ctx, e.draft())
	require.NoError(t, err)

	_, err = e.store.Transition(context.Background(), created.ID, created.Revision, StateRequested, StateProvisioning, "", "", "")
	require.ErrorIs(t, err, ErrNoAccount)

	_, err = e.store.Transition(WithAccount(context.Background(), "b"), created.ID, created.Revision, StateRequested, StateProvisioning, "", "", "")
	require.ErrorIs(t, err, ErrNotFound)
}

func TestRequestDeprovisionOnlyFromReadyOrFailed(t *testing.T) {
	e := fixture(t)
	ctx := WithAccount(context.Background(), "a")
	created, err := e.store.Create(ctx, e.draft())
	require.NoError(t, err)

	// Still requested -- nothing has been provisioned or granted yet.
	_, err = e.store.RequestDeprovision(ctx, created.ID, created.Revision)
	require.ErrorIs(t, err, ErrInvalid)

	provisioning, err := e.store.Transition(ctx, created.ID, created.Revision, StateRequested, StateProvisioning, "", "", "")
	require.NoError(t, err)

	// In flight -- must finish or fail its own step first.
	_, err = e.store.RequestDeprovision(ctx, created.ID, provisioning.Revision)
	require.ErrorIs(t, err, ErrInvalid)

	failed, err := e.store.Transition(ctx, created.ID, provisioning.Revision, StateProvisioning, StateFailed, "boom", "", "")
	require.NoError(t, err)

	revoking, err := e.store.RequestDeprovision(ctx, created.ID, failed.Revision)
	require.NoError(t, err)
	require.Equal(t, StateRevoking, revoking.State)
	require.Empty(t, revoking.FailedStep)
	require.Empty(t, revoking.FailureReason)
}

func TestDeprovisionTeardownPathToDeprovisioned(t *testing.T) {
	e := fixture(t)
	ctx := WithAccount(context.Background(), "a")
	created, err := e.store.Create(ctx, e.draft())
	require.NoError(t, err)
	provisioning, err := e.store.Transition(ctx, created.ID, created.Revision, StateRequested, StateProvisioning, "", "instance-1", "")
	require.NoError(t, err)
	granting, err := e.store.Transition(ctx, created.ID, provisioning.Revision, StateProvisioning, StateGranting, "", "", "")
	require.NoError(t, err)
	ready, err := e.store.Transition(ctx, created.ID, granting.Revision, StateGranting, StateReady, "", "", "relay-1")
	require.NoError(t, err)

	revoking, err := e.store.RequestDeprovision(ctx, created.ID, ready.Revision)
	require.NoError(t, err)

	deprovisioning, err := e.store.Transition(ctx, created.ID, revoking.Revision, StateRevoking, StateDeprovisioning, "", "", "")
	require.NoError(t, err)

	deprovisioned, err := e.store.Transition(ctx, created.ID, deprovisioning.Revision, StateDeprovisioning, StateDeprovisioned, "", "", "")
	require.NoError(t, err)
	require.Equal(t, StateDeprovisioned, deprovisioned.State)
	require.Equal(t, "instance-1", deprovisioned.InstanceID)
	require.Equal(t, "relay-1", deprovisioned.EstavelleID)

	require.NoError(t, e.store.Delete(ctx, created.ID, deprovisioned.Revision))

	var count int64
	require.NoError(t, e.db.Model(&Allocation{}).Count(&count).Error)
	require.Zero(t, count)
}

func TestDeleteOnlyFromRequestedOrDeprovisioned(t *testing.T) {
	e := fixture(t)
	ctx := WithAccount(context.Background(), "a")
	created, err := e.store.Create(ctx, e.draft())
	require.NoError(t, err)
	provisioning, err := e.store.Transition(ctx, created.ID, created.Revision, StateRequested, StateProvisioning, "", "", "")
	require.NoError(t, err)

	require.ErrorIs(t, e.store.Delete(ctx, created.ID, provisioning.Revision), ErrInvalid)

	other, err := e.store.Create(ctx, e.draft())
	require.NoError(t, err)
	require.NoError(t, e.store.Delete(ctx, other.ID, other.Revision))
}

func TestGetIsAccountScoped(t *testing.T) {
	e := fixture(t)
	ctx := WithAccount(context.Background(), "a")
	created, err := e.store.Create(ctx, e.draft())
	require.NoError(t, err)

	got, err := e.store.Get(ctx, created.ID)
	require.NoError(t, err)
	require.Equal(t, *created, *got)

	_, err = e.store.Get(WithAccount(context.Background(), "b"), created.ID)
	require.ErrorIs(t, err, ErrNotFound)

	_, err = e.store.Get(ctx, "missing")
	require.ErrorIs(t, err, ErrNotFound)

	_, err = e.store.Get(context.Background(), created.ID)
	require.ErrorIs(t, err, ErrNoAccount)
}

func TestListIsAccountScoped(t *testing.T) {
	e := fixture(t)
	ctx := WithAccount(context.Background(), "a")
	_, err := e.store.Create(ctx, e.draft())
	require.NoError(t, err)

	rows, err := e.store.List(ctx)
	require.NoError(t, err)
	require.Len(t, rows, 1)

	rows, err = e.store.List(WithAccount(context.Background(), "b"))
	require.NoError(t, err)
	require.Empty(t, rows)

	_, err = e.store.List(context.Background())
	require.ErrorIs(t, err, ErrNoAccount)
}

// TestCreateRefusesWhenConcurrencyCeilingNotConfigured is ADR-0045 §6
// bullet 4's "mandatory configuration, no unlimited value" -- a Store
// that never had SetMaxConcurrentAllocations called (not this test's own
// fixture, which does) must fail closed, not silently allow an unbounded
// number of real, billable instances per account.
func TestCreateRefusesWhenConcurrencyCeilingNotConfigured(t *testing.T) {
	e := fixture(t)
	e.store.SetMaxConcurrentAllocations(0)
	ctx := WithAccount(context.Background(), "a")

	_, err := e.store.Create(ctx, e.draft())
	require.ErrorIs(t, err, ErrInvalid)
	require.ErrorContains(t, err, "KARST_ESTAVELLE_ALLOCATE_MAX_CONCURRENT")
}

// TestCreateRefusesOverTheConfiguredConcurrencyCeiling checks the ceiling
// counts every non-deprovisioned allocation (requested through ready/
// failed), not only ones actively being driven, and that it is scoped per
// account -- a second account must never be blocked by the first's count.
func TestCreateRefusesOverTheConfiguredConcurrencyCeiling(t *testing.T) {
	e := fixture(t)
	e.store.SetMaxConcurrentAllocations(2)
	ctx := WithAccount(context.Background(), "a")

	_, err := e.store.Create(ctx, e.draft())
	require.NoError(t, err)
	_, err = e.store.Create(ctx, e.draft())
	require.NoError(t, err)

	_, err = e.store.Create(ctx, e.draft())
	require.ErrorIs(t, err, ErrInvalid)
	require.ErrorContains(t, err, "ceiling")

	// A different account's own ceiling is independent.
	otherAccount := infraconnections.Account{ID: "conn-2", AccountID: "b", Type: infraconnections.TypeAWS, Mode: infraconnections.ModeReadWrite, Label: "aws"}
	require.NoError(t, e.db.Create(&otherAccount).Error)
	otherGroup := types.Group{ID: "eng-b", AccountID: "b", Name: "Engineering"}
	require.NoError(t, e.db.Create(&otherGroup).Error)
	otherLocation := locationreg.StoredLocation{AccountID: "b", ID: "loc-b", Lat: 45.8696, Lon: -119.6880, Label: "US West (Oregon)"}
	require.NoError(t, e.db.Create(&otherLocation).Error)
	otherCtx := WithAccount(context.Background(), "b")
	_, err = e.store.Create(otherCtx, Allocation{Name: "denver", InfraConnectionID: otherAccount.ID, Location: "us-west-2", EstavelleTransport: true, PermittedGroups: []string{otherGroup.ID}})
	require.NoError(t, err)
}

// TestHasNonTerminalAllocations backs infraconnections.Store.Delete's own
// reference check (SetAllocationReferenceChecker) -- a deprovisioned
// allocation must never block deleting the connection it used to
// reference, and a different account's allocations must never be
// visible to this check.
func TestHasNonTerminalAllocations(t *testing.T) {
	e := fixture(t)
	ctx := WithAccount(context.Background(), "a")
	created, err := e.store.Create(ctx, e.draft())
	require.NoError(t, err)

	inUse, err := e.store.HasNonTerminalAllocations(context.Background(), "a", e.connectionID)
	require.NoError(t, err)
	require.True(t, inUse)

	inUse, err = e.store.HasNonTerminalAllocations(context.Background(), "b", e.connectionID)
	require.NoError(t, err)
	require.False(t, inUse, "a different account's connection id must never match")

	provisioning, err := e.store.Transition(ctx, created.ID, created.Revision, StateRequested, StateProvisioning, "", "inst-1", "")
	require.NoError(t, err)
	granting, err := e.store.Transition(ctx, created.ID, provisioning.Revision, StateProvisioning, StateGranting, "", "", "")
	require.NoError(t, err)
	ready, err := e.store.Transition(ctx, created.ID, granting.Revision, StateGranting, StateReady, "", "", "relay-1")
	require.NoError(t, err)
	revoking, err := e.store.RequestDeprovision(ctx, created.ID, ready.Revision)
	require.NoError(t, err)
	deprovisioning, err := e.store.Transition(ctx, created.ID, revoking.Revision, StateRevoking, StateDeprovisioning, "", "", "")
	require.NoError(t, err)
	_, err = e.store.Transition(ctx, created.ID, deprovisioning.Revision, StateDeprovisioning, StateDeprovisioned, "", "", "")
	require.NoError(t, err)

	inUse, err = e.store.HasNonTerminalAllocations(context.Background(), "a", e.connectionID)
	require.NoError(t, err)
	require.False(t, inUse, "a fully deprovisioned allocation must not block deleting its connection")
}
