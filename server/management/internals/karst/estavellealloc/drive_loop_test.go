// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package estavellealloc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/karst/estavellereg"
	"github.com/netbirdio/netbird/management/internals/karst/estavelleservice"
	"github.com/netbirdio/netbird/management/internals/karst/infraconnections"
	"github.com/netbirdio/netbird/management/internals/karst/infraprovision"
	"github.com/netbirdio/netbird/management/internals/karst/roster"
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

	// replacementInstance/replacementTLSServerName let a test give the
	// *second* Create call (the replacement's) a different instance
	// ID/TLS-server-name than the original, since a real replacement
	// always produces a genuinely different instance.
	replacementInstance      infraprovision.Instance
	replacementTLSServerName string
	// createAllocationIDs/createImages record every Create call's own
	// correlation-ID and CreateRequest.Image arguments, in order --
	// issue #560's tests assert the replacement call never reuses the
	// original allocation ID (replacementCorrelationID's own guarantee)
	// and does pass the desired image through.
	createAllocationIDs []string
	createImages        []string
	// drainedInstanceIDs/destroyedInstanceIDs record every instance ID
	// Drain/Destroy was called with, in order -- tests assert *which*
	// instance (old vs. replacement) was touched, not just whether Drain/
	// Destroy was called at all.
	drainedInstanceIDs   []string
	destroyedInstanceIDs []string
}

func (f *fakeDriver) Create(_ context.Context, allocationID string, req infraprovision.CreateRequest) (infraprovision.Instance, error) {
	f.createAllocationIDs = append(f.createAllocationIDs, allocationID)
	f.createImages = append(f.createImages, req.Image)
	f.createCalls++
	if f.createErr != nil {
		return infraprovision.Instance{}, f.createErr
	}
	if f.createCalls > 1 && f.replacementInstance.ID != "" {
		return f.replacementInstance, nil
	}
	return f.instance, nil
}

func (f *fakeDriver) TLSServerName(_ context.Context, instanceID string) (string, error) {
	if f.replacementInstance.ID != "" && instanceID == f.replacementInstance.ID {
		return f.replacementTLSServerName, nil
	}
	return f.tlsServerName, nil
}

func (f *fakeDriver) Drain(_ context.Context, instanceID string) error {
	f.drained = true
	f.drainedInstanceIDs = append(f.drainedInstanceIDs, instanceID)
	return f.drainErr
}

func (f *fakeDriver) Destroy(_ context.Context, instanceID string) (string, error) {
	f.destroyed = true
	f.destroyedInstanceIDs = append(f.destroyedInstanceIDs, instanceID)
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

type fakeEstavelles struct {
	relay *estavellereg.StoredEstavelle
	err   error
	// byName, when non-nil, resolves by the queried TLS server name instead
	// of always returning relay -- issue #560's replacement tests need two
	// distinct estavelles (the old instance's and the replacement's) found
	// by two distinct names in the same test.
	byName map[string]*estavellereg.StoredEstavelle
}

func (f fakeEstavelles) FindByTLSServerName(_ context.Context, name string) (*estavellereg.StoredEstavelle, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.byName != nil {
		if relay, ok := f.byName[name]; ok {
			return relay, nil
		}
		return nil, estavellereg.ErrNotFound
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
		alloc:     WithAccount(base, "a"),
		infra:     infraconnections.WithAccount(base, "a"),
		estavelle: estavellereg.WithAccount(base, "a"),
		grant:     estavelleservice.WithAccount(estavelleservice.WithActor(base, "test"), "a"),
	}
	deps := AllocateDeps{
		InfraConnections: fakeInfraConnections{driver: driver},
		Enroll:           fakeEnroll{token: "tok"},
		Estavelles:       fakeEstavelles{relay: relay},
		Deenroll:         deenr,
		Grants:           grants,
		ControlAPIBase:   "https://control.example",
	}
	return driveEnv{env: e, ctx: ctx, deps: deps, driver: driver, grants: grants, deenr: deenr}
}

// fakeTelemetry is estavelleTelemetryReader's own fake -- issue #560's
// replacement admitting-check tests control exactly what "the new instance
// has/hasn't self-reported yet" looks like.
type fakeTelemetry struct {
	record *estavellereg.EstavelleTelemetryRecord
	err    error
}

func (f fakeTelemetry) LatestTelemetry(context.Context, string) (*estavellereg.EstavelleTelemetryRecord, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.record, nil
}

// newReplacementDriveEnv is newDriveEnv's own replacement-test sibling:
// callers need control over Estavelles (two names, old and new) and
// Telemetry that newDriveEnv's narrower signature does not expose.
func newReplacementDriveEnv(t *testing.T, driver *fakeDriver, estavelles fakeEstavelles, telemetry fakeTelemetry) driveEnv {
	t.Helper()
	e := fixture(t)
	grants := &fakeGrants{}
	deenr := &fakeDeenroll{}
	base := context.Background()
	ctx := scopedContexts{
		alloc:     WithAccount(base, "a"),
		infra:     infraconnections.WithAccount(base, "a"),
		estavelle: estavellereg.WithAccount(base, "a"),
		grant:     estavelleservice.WithAccount(estavelleservice.WithActor(base, "test"), "a"),
	}
	deps := AllocateDeps{
		InfraConnections: fakeInfraConnections{driver: driver},
		Enroll:           fakeEnroll{token: "tok"},
		Estavelles:       estavelles,
		Deenroll:         deenr,
		Grants:           grants,
		Telemetry:        telemetry,
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
	require.Equal(t, "relay-1", got.EstavelleID)
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

// bringToReadyWithReplacementFixtures drives a freshly created allocation
// to StateReady through the real provisionStep/grantStep (not a shortcut
// Transition call) -- the replacement correlation-ID guarantee below only
// means something if the *original* instance was actually created the
// normal way first.
func bringToReadyWithReplacementFixtures(t *testing.T, de driveEnv) *Allocation {
	t.Helper()
	created, err := de.store.Create(de.ctx.alloc, de.draft())
	require.NoError(t, err)
	require.NoError(t, provisionStep(de.ctx, de.store, de.deps, *created))
	provisioning, err := de.store.Get(de.ctx.alloc, created.ID)
	require.NoError(t, err)
	require.NoError(t, grantStep(de.ctx, de.store, de.deps, *provisioning))
	ready, err := de.store.Get(de.ctx.alloc, created.ID)
	require.NoError(t, err)
	require.Equal(t, StateReady, ready.State)
	return ready
}

func replacementFixtureDriver() *fakeDriver {
	return &fakeDriver{
		instance:                 infraprovision.Instance{ID: "i-1", TLSServerName: "old.aws.karst.internal"},
		tlsServerName:            "old.aws.karst.internal",
		replacementInstance:      infraprovision.Instance{ID: "i-2", TLSServerName: "new.aws.karst.internal"},
		replacementTLSServerName: "new.aws.karst.internal",
		destroyName:              "old.aws.karst.internal",
	}
}

func replacementFixtureEstavelles() fakeEstavelles {
	return fakeEstavelles{byName: map[string]*estavellereg.StoredEstavelle{
		"old.aws.karst.internal": {AccountID: "a", ID: "relay-1", TLSServerName: "old.aws.karst.internal"},
		"new.aws.karst.internal": {AccountID: "a", ID: "relay-2", TLSServerName: "new.aws.karst.internal"},
	}}
}

func TestReplaceProvisionStepUsesACorrelationIDDistinctFromTheOriginal(t *testing.T) {
	driver := replacementFixtureDriver()
	de := newReplacementDriveEnv(t, driver, replacementFixtureEstavelles(), fakeTelemetry{})
	ready := bringToReadyWithReplacementFixtures(t, de)

	replacing, err := de.store.RequestReplace(de.ctx.alloc, ready.ID, ready.Revision, "v2")
	require.NoError(t, err)

	require.NoError(t, replaceProvisionStep(de.ctx, de.store, de.deps, *replacing))

	got, err := de.store.Get(de.ctx.alloc, ready.ID)
	require.NoError(t, err)
	require.Equal(t, ReplacementStateAdmitting, got.ReplacementState)
	require.Equal(t, "i-2", got.ReplacementInstanceID)
	require.Equal(t, "i-1", got.InstanceID, "the old instance stays of record until cutover")
	require.Equal(t,
		[]string{ready.ID, replacementCorrelationID(ready.ID)},
		driver.createAllocationIDs,
		"the replacement Create must never reuse the original allocation ID -- that would collide with the still-running old instance's own crash-safe dedup lookup",
	)
	require.Equal(t, []string{"", "v2"}, driver.createImages)
}

func TestReplaceAdmitStepNeverAdvancesWithoutFreshTelemetryAndARosterCycle(t *testing.T) {
	driver := replacementFixtureDriver()
	de := newReplacementDriveEnv(t, driver, replacementFixtureEstavelles(), fakeTelemetry{})
	ready := bringToReadyWithReplacementFixtures(t, de)
	replacing, err := de.store.RequestReplace(de.ctx.alloc, ready.ID, ready.Revision, "v2")
	require.NoError(t, err)
	require.NoError(t, replaceProvisionStep(de.ctx, de.store, de.deps, *replacing))
	afterProvision, err := de.store.Get(de.ctx.alloc, ready.ID)
	require.NoError(t, err)

	// No telemetry at all yet -- registered is not admitting.
	require.NoError(t, replaceAdmitStep(de.ctx, de.store, de.deps, *afterProvision))
	stillWaiting, err := de.store.Get(de.ctx.alloc, ready.ID)
	require.NoError(t, err)
	require.Equal(t, ReplacementStateAdmitting, stillWaiting.ReplacementState)
	require.False(t, driver.drained, "the old instance must never be touched before the replacement is admitting")

	// Telemetry arrives, but not even one roster.DefaultInterval has
	// elapsed since entering "admitting" -- must still wait.
	de.deps.Telemetry = fakeTelemetry{record: &estavellereg.EstavelleTelemetryRecord{AccountID: "a", ID: "relay-2", ReportedAt: time.Now().UTC()}}
	require.NoError(t, replaceAdmitStep(de.ctx, de.store, de.deps, *stillWaiting))
	stillWaiting2, err := de.store.Get(de.ctx.alloc, ready.ID)
	require.NoError(t, err)
	require.Equal(t, ReplacementStateAdmitting, stillWaiting2.ReplacementState, "must wait at least one roster.DefaultInterval after entering admitting")
	require.False(t, driver.drained)

	// Back-date past roster.DefaultInterval: now it may advance.
	require.NoError(t, de.db.Model(&Allocation{}).Where("id = ?", ready.ID).
		Update("replacement_updated_at", time.Now().UTC().Add(-roster.DefaultInterval-time.Second)).Error)
	backdated, err := de.store.Get(de.ctx.alloc, ready.ID)
	require.NoError(t, err)
	require.NoError(t, replaceAdmitStep(de.ctx, de.store, de.deps, *backdated))

	nowDraining, err := de.store.Get(de.ctx.alloc, ready.ID)
	require.NoError(t, err)
	require.Equal(t, ReplacementStateDraining, nowDraining.ReplacementState)
	require.False(t, driver.drained, "entering draining must not itself call Drain -- that is replaceDrainStep's own job")
}

func TestReplaceAdmitStepTimesOutCleansUpReplacementAndNeverTouchesOldInstance(t *testing.T) {
	driver := replacementFixtureDriver()
	// The replacement instance never registers at all in estavellereg --
	// simulates a boot that never enrolls.
	estavelles := fakeEstavelles{byName: map[string]*estavellereg.StoredEstavelle{
		"old.aws.karst.internal": {AccountID: "a", ID: "relay-1", TLSServerName: "old.aws.karst.internal"},
	}}
	de := newReplacementDriveEnv(t, driver, estavelles, fakeTelemetry{})
	ready := bringToReadyWithReplacementFixtures(t, de)
	replacing, err := de.store.RequestReplace(de.ctx.alloc, ready.ID, ready.Revision, "v2")
	require.NoError(t, err)
	require.NoError(t, replaceProvisionStep(de.ctx, de.store, de.deps, *replacing))

	require.NoError(t, de.db.Model(&Allocation{}).Where("id = ?", ready.ID).
		Update("replacement_updated_at", time.Now().UTC().Add(-replaceAdmittingTimeout-time.Second)).Error)
	stuck, err := de.store.Get(de.ctx.alloc, ready.ID)
	require.NoError(t, err)

	require.Error(t, replaceAdmitStep(de.ctx, de.store, de.deps, *stuck), "a timed-out replacement must report its own failure, mirroring failAllocation's own convention")

	failed, err := de.store.Get(de.ctx.alloc, ready.ID)
	require.NoError(t, err)
	require.Equal(t, ReplacementStateFailed, failed.ReplacementState)
	require.Equal(t, ReplacementStateAdmitting, failed.ReplacementFailedStep)
	require.Equal(t, StateReady, failed.State, "the allocation's own grant must stay untouched")
	require.Equal(t, "i-1", failed.InstanceID, "the old instance is still of record")
	require.Equal(t, []string{"i-2"}, driver.drainedInstanceIDs, "only the half-created replacement is cleaned up")
	require.Equal(t, []string{"i-2"}, driver.destroyedInstanceIDs, "the old instance must never be destroyed by a stuck replacement")
}

func TestReplacementFullSequenceCutsOverOnlyAfterTheOldInstanceIsGone(t *testing.T) {
	driver := replacementFixtureDriver()
	de := newReplacementDriveEnv(t, driver, replacementFixtureEstavelles(), fakeTelemetry{})
	ready := bringToReadyWithReplacementFixtures(t, de)

	replacing, err := de.store.RequestReplace(de.ctx.alloc, ready.ID, ready.Revision, "v2")
	require.NoError(t, err)
	require.NoError(t, replaceProvisionStep(de.ctx, de.store, de.deps, *replacing))
	afterProvision, err := de.store.Get(de.ctx.alloc, ready.ID)
	require.NoError(t, err)

	de.deps.Telemetry = fakeTelemetry{record: &estavellereg.EstavelleTelemetryRecord{AccountID: "a", ID: "relay-2", ReportedAt: time.Now().UTC()}}
	require.NoError(t, de.db.Model(&Allocation{}).Where("id = ?", ready.ID).
		Update("replacement_updated_at", time.Now().UTC().Add(-roster.DefaultInterval-time.Second)).Error)
	backdated, err := de.store.Get(de.ctx.alloc, ready.ID)
	require.NoError(t, err)
	require.NoError(t, replaceAdmitStep(de.ctx, de.store, de.deps, *backdated))
	_ = afterProvision
	draining, err := de.store.Get(de.ctx.alloc, ready.ID)
	require.NoError(t, err)
	require.Equal(t, ReplacementStateDraining, draining.ReplacementState)

	require.NoError(t, replaceDrainStep(de.ctx, de.store, de.deps, *draining))
	require.Equal(t, []string{"i-1"}, driver.drainedInstanceIDs, "only the old instance is drained")
	destroying, err := de.store.Get(de.ctx.alloc, ready.ID)
	require.NoError(t, err)
	require.Equal(t, ReplacementStateDestroying, destroying.ReplacementState)

	require.NoError(t, replaceDestroyStep(de.ctx, de.store, de.deps, *destroying))
	require.Equal(t, []string{"i-1"}, driver.destroyedInstanceIDs, "only the old instance is destroyed")
	require.Equal(t, []string{"old.aws.karst.internal"}, de.deenr.deleted)

	final, err := de.store.Get(de.ctx.alloc, ready.ID)
	require.NoError(t, err)
	require.Empty(t, final.ReplacementState)
	require.Equal(t, "i-2", final.InstanceID, "cutover: the new instance is now of record")
	require.Equal(t, "relay-2", final.EstavelleID)
	require.Equal(t, "v2", final.RunningImage)
}

func TestRetryReplacementAfterFailedDrainResumesWithoutRecreating(t *testing.T) {
	driver := replacementFixtureDriver()
	driver.drainErr = errors.New("stop instances: throttled")
	de := newReplacementDriveEnv(t, driver, replacementFixtureEstavelles(), fakeTelemetry{})
	ready := bringToReadyWithReplacementFixtures(t, de)

	replacing, err := de.store.RequestReplace(de.ctx.alloc, ready.ID, ready.Revision, "v2")
	require.NoError(t, err)
	require.NoError(t, replaceProvisionStep(de.ctx, de.store, de.deps, *replacing))
	de.deps.Telemetry = fakeTelemetry{record: &estavellereg.EstavelleTelemetryRecord{AccountID: "a", ID: "relay-2", ReportedAt: time.Now().UTC()}}
	require.NoError(t, de.db.Model(&Allocation{}).Where("id = ?", ready.ID).
		Update("replacement_updated_at", time.Now().UTC().Add(-roster.DefaultInterval-time.Second)).Error)
	backdated, err := de.store.Get(de.ctx.alloc, ready.ID)
	require.NoError(t, err)
	require.NoError(t, replaceAdmitStep(de.ctx, de.store, de.deps, *backdated))
	draining, err := de.store.Get(de.ctx.alloc, ready.ID)
	require.NoError(t, err)
	require.Equal(t, ReplacementStateDraining, draining.ReplacementState)
	require.Equal(t, 2, driver.createCalls, "exactly the original create plus the one replacement create so far")

	err = replaceDrainStep(de.ctx, de.store, de.deps, *draining)
	require.Error(t, err)
	failed, err2 := de.store.Get(de.ctx.alloc, ready.ID)
	require.NoError(t, err2)
	require.Equal(t, ReplacementStateFailed, failed.ReplacementState)
	require.Equal(t, ReplacementStateDraining, failed.ReplacementFailedStep)
	require.Equal(t, StateReady, failed.State)

	retried, err := de.store.RetryReplacement(de.ctx.alloc, ready.ID, failed.Revision)
	require.NoError(t, err)
	require.Equal(t, ReplacementStateDraining, retried.ReplacementState)

	driver.drainErr = nil
	require.NoError(t, replaceDrainStep(de.ctx, de.store, de.deps, *retried))
	require.Equal(t, 2, driver.createCalls, "retrying a failed drain must never call Create again")
	destroying, err := de.store.Get(de.ctx.alloc, ready.ID)
	require.NoError(t, err)
	require.Equal(t, ReplacementStateDestroying, destroying.ReplacementState)
}

func TestDriveReplacementFailsClosedOnAnUnrecognizedReplacementState(t *testing.T) {
	driver := replacementFixtureDriver()
	de := newReplacementDriveEnv(t, driver, replacementFixtureEstavelles(), fakeTelemetry{})
	ready := bringToReadyWithReplacementFixtures(t, de)
	replacing, err := de.store.RequestReplace(de.ctx.alloc, ready.ID, ready.Revision, "v2")
	require.NoError(t, err)
	bogus := *replacing
	bogus.ReplacementState = "not-a-real-step"

	require.Error(t, driveReplacement(de.ctx, de.store, de.deps, bogus))
}
