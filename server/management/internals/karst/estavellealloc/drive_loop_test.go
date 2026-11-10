// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package estavellealloc

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/karst/estavellereg"
	"github.com/netbirdio/netbird/management/internals/karst/estavelleservice"
	"github.com/netbirdio/netbird/management/internals/karst/infraconnections"
	"github.com/netbirdio/netbird/management/internals/karst/infraprovision"
)

// fakeDriver is a trivial in-memory infraprovision.Driver -- the ADR-0067
// abstraction is what makes this loop fake-testable at all; before it,
// awsdrive_loop.go called the EC2 SDK by name and had zero direct tests.
type fakeDriver struct {
	instance      infraprovision.Instance
	createErr     error
	tlsServerName string
	drainErr      error
	destroyName   string
	destroyErr    error
	createCalls   int
	drained       bool
	destroyed     bool
}

func (f *fakeDriver) Create(context.Context, string, infraprovision.CreateRequest) (infraprovision.Instance, error) {
	f.createCalls++
	if f.createErr != nil {
		return infraprovision.Instance{}, f.createErr
	}
	return f.instance, nil
}

func (f *fakeDriver) TLSServerName(context.Context, string) (string, error) {
	return f.tlsServerName, nil
}

func (f *fakeDriver) Drain(context.Context, string) error { f.drained = true; return f.drainErr }

func (f *fakeDriver) Destroy(context.Context, string) (string, error) {
	f.destroyed = true
	if f.destroyErr != nil {
		return "", f.destroyErr
	}
	return f.destroyName, nil
}

type fakeInfraConnections struct {
	driver infraprovision.Driver
	err    error
}

func (f fakeInfraConnections) ActuationDriver(context.Context, string) (infraprovision.Driver, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.driver, nil
}

type fakeEnroll struct {
	token string
	err   error
}

func (f fakeEnroll) MintEstavelleEnrollKey(context.Context, string, string, time.Duration) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	return f.token, nil
}

type fakeRelays struct {
	relay *estavellereg.StoredEstavelle
	err   error
}

func (f fakeRelays) FindByTLSServerName(context.Context, string) (*estavellereg.StoredEstavelle, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.relay, nil
}

type fakeDeenroll struct {
	err     error
	deleted []string
}

func (f *fakeDeenroll) DeleteByTLSServerName(_ context.Context, name string) error {
	f.deleted = append(f.deleted, name)
	return f.err
}

type fakeGrants struct {
	createErr  error
	deleteErr  error
	created    []estavelleservice.Service
	deletedIDs []string
}

func (f *fakeGrants) Create(_ context.Context, s estavelleservice.Service) (*estavelleservice.Service, error) {
	if f.createErr != nil {
		return nil, f.createErr
	}
	f.created = append(f.created, s)
	return &s, nil
}

func (f *fakeGrants) Delete(_ context.Context, id string) error {
	f.deletedIDs = append(f.deletedIDs, id)
	return f.deleteErr
}

// driveEnv bundles a real Store (via fixture(t), store_test.go) with the
// scoped contexts and deps driveOne needs -- one real allocation per test,
// everything downstream of it faked.
type driveEnv struct {
	env
	ctx    scopedContexts
	deps   AllocateDeps
	driver *fakeDriver
	grants *fakeGrants
	deenr  *fakeDeenroll
}

func newDriveEnv(t *testing.T, driver *fakeDriver, relay *estavellereg.StoredEstavelle) driveEnv {
	t.Helper()
	e := fixture(t)
	grants := &fakeGrants{}
	deenr := &fakeDeenroll{}
	base := context.Background()
	ctx := scopedContexts{
		alloc: WithAccount(base, "a"),
		infra: infraconnections.WithAccount(base, "a"),
		relay: estavellereg.WithAccount(base, "a"),
		grant: estavelleservice.WithAccount(estavelleservice.WithActor(base, "test"), "a"),
	}
	deps := AllocateDeps{
		InfraConnections: fakeInfraConnections{driver: driver},
		Enroll:           fakeEnroll{token: "tok"},
		Relays:           fakeRelays{relay: relay},
		Deenroll:         deenr,
		Grants:           grants,
		ControlAPIBase:   "https://control.example",
	}
	return driveEnv{env: e, ctx: ctx, deps: deps, driver: driver, grants: grants, deenr: deenr}
}

func TestProvisionStepMovesRequestedToProvisioning(t *testing.T) {
	driver := &fakeDriver{instance: infraprovision.Instance{ID: "i-1", TLSServerName: "alloc-x-abc.aws.karst.internal"}}
	de := newDriveEnv(t, driver, nil)
	created, err := de.store.Create(de.ctx.alloc, de.draft())
	require.NoError(t, err)

	require.NoError(t, provisionStep(de.ctx, de.store, de.deps, *created))

	got, err := de.store.Get(de.ctx.alloc, created.ID)
	require.NoError(t, err)
	require.Equal(t, StateProvisioning, got.State)
	require.Equal(t, "i-1", got.InstanceID)
	require.Equal(t, 1, driver.createCalls)
}

func TestProvisionStepFailsWhenControlAPIBaseMissing(t *testing.T) {
	driver := &fakeDriver{instance: infraprovision.Instance{ID: "i-1", TLSServerName: "name"}}
	de := newDriveEnv(t, driver, nil)
	de.deps.ControlAPIBase = ""
	created, err := de.store.Create(de.ctx.alloc, de.draft())
	require.NoError(t, err)

	err = provisionStep(de.ctx, de.store, de.deps, *created)
	require.Error(t, err)

	got, getErr := de.store.Get(de.ctx.alloc, created.ID)
	require.NoError(t, getErr)
	require.Equal(t, StateFailed, got.State)
	require.Equal(t, 0, driver.createCalls, "must not mint a token or call Create when control-api-base is unset")
}

func TestGrantStepMovesProvisioningToReadyAndCreatesGrant(t *testing.T) {
	driver := &fakeDriver{instance: infraprovision.Instance{ID: "i-1", TLSServerName: "alloc-x.aws.karst.internal"}, tlsServerName: "alloc-x.aws.karst.internal"}
	relay := &estavellereg.StoredEstavelle{AccountID: "a", ID: "relay-1", TLSServerName: "alloc-x.aws.karst.internal"}
	de := newDriveEnv(t, driver, relay)
	created, err := de.store.Create(de.ctx.alloc, de.draft())
	require.NoError(t, err)
	require.NoError(t, provisionStep(de.ctx, de.store, de.deps, *created))
	provisioning, err := de.store.Get(de.ctx.alloc, created.ID)
	require.NoError(t, err)

	require.NoError(t, grantStep(de.ctx, de.store, de.deps, *provisioning))

	got, err := de.store.Get(de.ctx.alloc, created.ID)
	require.NoError(t, err)
	require.Equal(t, StateReady, got.State)
	require.Equal(t, "relay-1", got.RelayID)
	require.Len(t, de.grants.created, 1)
	require.Equal(t, "relay-1", de.grants.created[0].PonorID)
}

func TestGrantStepRetriesWhenTLSServerNameNotYetDiscoverable(t *testing.T) {
	driver := &fakeDriver{instance: infraprovision.Instance{ID: "i-1"}, tlsServerName: ""}
	de := newDriveEnv(t, driver, nil)
	created, err := de.store.Create(de.ctx.alloc, de.draft())
	require.NoError(t, err)
	require.NoError(t, provisionStep(de.ctx, de.store, de.deps, *created))
	provisioning, err := de.store.Get(de.ctx.alloc, created.ID)
	require.NoError(t, err)

	require.NoError(t, grantStep(de.ctx, de.store, de.deps, *provisioning))

	got, err := de.store.Get(de.ctx.alloc, created.ID)
	require.NoError(t, err)
	require.Equal(t, StateProvisioning, got.State, "must stay in provisioning, not fail, while the correlation label isn't discoverable yet")
	require.Empty(t, de.grants.created)
}

func TestRevokeThenDeprovisionTearsDownInReverseOrder(t *testing.T) {
	driver := &fakeDriver{instance: infraprovision.Instance{ID: "i-1", TLSServerName: "alloc-x.aws.karst.internal"}, tlsServerName: "alloc-x.aws.karst.internal", destroyName: "alloc-x.aws.karst.internal"}
	relay := &estavellereg.StoredEstavelle{AccountID: "a", ID: "relay-1", TLSServerName: "alloc-x.aws.karst.internal"}
	de := newDriveEnv(t, driver, relay)
	created, err := de.store.Create(de.ctx.alloc, de.draft())
	require.NoError(t, err)
	require.NoError(t, provisionStep(de.ctx, de.store, de.deps, *created))
	provisioning, err := de.store.Get(de.ctx.alloc, created.ID)
	require.NoError(t, err)
	require.NoError(t, grantStep(de.ctx, de.store, de.deps, *provisioning))
	ready, err := de.store.Get(de.ctx.alloc, created.ID)
	require.NoError(t, err)

	revoking, err := de.store.RequestDeprovision(de.ctx.alloc, ready.ID, ready.Revision)
	require.NoError(t, err)
	require.NoError(t, revokeStep(de.ctx, de.store, de.deps, *revoking))
	require.Len(t, de.grants.deletedIDs, 1, "grant must be revoked before compute is touched")
	require.False(t, driver.drained, "compute must not be touched by revokeStep itself")
	require.False(t, driver.destroyed, "compute must not be touched by revokeStep itself")

	deprovisioning, err := de.store.Get(de.ctx.alloc, created.ID)
	require.NoError(t, err)
	require.NoError(t, deprovisionStep(de.ctx, de.store, de.deps, *deprovisioning))

	final, err := de.store.Get(de.ctx.alloc, created.ID)
	require.NoError(t, err)
	require.Equal(t, StateDeprovisioned, final.State)
	require.True(t, driver.drained)
	require.True(t, driver.destroyed)
	require.Equal(t, []string{"alloc-x.aws.karst.internal"}, de.deenr.deleted)
}

func TestDriveOneFailsClosedOnAnUnrecognizedState(t *testing.T) {
	de := newDriveEnv(t, &fakeDriver{}, nil)
	created, err := de.store.Create(de.ctx.alloc, de.draft())
	require.NoError(t, err)
	bogus := *created
	bogus.State = "not-a-real-state"

	require.Error(t, driveOne(de.ctx, de.store, de.deps, bogus))
}
