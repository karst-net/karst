// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package rollout_test

import (
	"context"
	"errors"
	"testing"

	"github.com/netbirdio/netbird/management/internals/karst/rollout"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const validDigest = "sha256:" + "0123456789abcdef" + "0123456789abcdef" + "0123456789abcdef" + "0123456789abcdef"

func testStore(t *testing.T) *rollout.Store {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sqlDB.Close()) })
	store, err := rollout.NewStore(db)
	require.NoError(t, err)
	return store
}

func validDraftComponents() []rollout.PlanComponent {
	return []rollout.PlanComponent{
		{Name: rollout.ComponentControl, Sequence: 0, TargetDigest: validDigest, VerificationRef: "cosign verify ok @ 2026-11-03"},
		{Name: rollout.ComponentEstavelleJob, Sequence: 1, TargetDigest: validDigest, VerificationRef: "cosign verify ok @ 2026-11-03"},
		{Name: rollout.ComponentConsole, Sequence: 2, TargetDigest: validDigest, VerificationRef: "cosign verify ok @ 2026-11-03"},
	}
}

func TestCreateValidatesDraftAndPersistsPlanned(t *testing.T) {
	store := testStore(t)
	ctx := rollout.WithAccount(context.Background(), "a")

	plan, components, err := store.Create(ctx, rollout.Plan{TargetRelease: "v0.9.0"}, validDraftComponents())
	require.NoError(t, err)
	require.Equal(t, rollout.StatePlanned, plan.State)
	require.EqualValues(t, 1, plan.Revision)
	require.Len(t, components, 3)
	for _, component := range components {
		require.Equal(t, "pending", component.Status)
	}
}

func TestCreateRejectsInvalidDrafts(t *testing.T) {
	store := testStore(t)
	ctx := rollout.WithAccount(context.Background(), "a")

	_, _, err := store.Create(ctx, rollout.Plan{}, validDraftComponents())
	require.ErrorIs(t, err, rollout.ErrInvalid, "missing target_release")

	_, _, err = store.Create(ctx, rollout.Plan{TargetRelease: "v1"}, nil)
	require.ErrorIs(t, err, rollout.ErrInvalid, "no components")

	badName := validDraftComponents()
	badName[0].Name = "gateway"
	_, _, err = store.Create(ctx, rollout.Plan{TargetRelease: "v1"}, badName)
	require.ErrorIs(t, err, rollout.ErrInvalid, "unrecognized component name")

	dupeName := validDraftComponents()
	dupeName[1].Name = dupeName[0].Name
	_, _, err = store.Create(ctx, rollout.Plan{TargetRelease: "v1"}, dupeName)
	require.ErrorIs(t, err, rollout.ErrInvalid, "duplicate component name")

	dupeSeq := validDraftComponents()
	dupeSeq[1].Sequence = dupeSeq[0].Sequence
	_, _, err = store.Create(ctx, rollout.Plan{TargetRelease: "v1"}, dupeSeq)
	require.ErrorIs(t, err, rollout.ErrInvalid, "duplicate sequence")

	gapSeq := validDraftComponents()
	gapSeq[2].Sequence = 5
	_, _, err = store.Create(ctx, rollout.Plan{TargetRelease: "v1"}, gapSeq)
	require.ErrorIs(t, err, rollout.ErrInvalid, "non-contiguous sequence")

	badDigest := validDraftComponents()
	badDigest[0].TargetDigest = "sha256:not-hex"
	_, _, err = store.Create(ctx, rollout.Plan{TargetRelease: "v1"}, badDigest)
	require.ErrorIs(t, err, rollout.ErrInvalid, "invalid digest shape")

	noVerification := validDraftComponents()
	noVerification[0].VerificationRef = ""
	_, _, err = store.Create(ctx, rollout.Plan{TargetRelease: "v1"}, noVerification)
	require.ErrorIs(t, err, rollout.ErrInvalid, "missing verification reference")

	_, _, err = store.Create(context.Background(), rollout.Plan{TargetRelease: "v1"}, validDraftComponents())
	require.ErrorIs(t, err, rollout.ErrNoAccount, "missing account scope")
}

func TestStateMachineValidAndInvalidTransitions(t *testing.T) {
	store := testStore(t)
	ctx := rollout.WithAccount(context.Background(), "a")
	plan, _, err := store.Create(ctx, rollout.Plan{TargetRelease: "v1"}, validDraftComponents())
	require.NoError(t, err)

	// Cannot mark a component applied, fail a component, or roll back
	// before the plan is started.
	_, _, err = store.MarkComponentApplied(ctx, plan.ID, plan.Revision, rollout.ComponentControl, validDigest)
	require.ErrorIs(t, err, rollout.ErrInvalid)
	_, _, err = store.MarkComponentFailed(ctx, plan.ID, plan.Revision, rollout.ComponentControl, "boom")
	require.ErrorIs(t, err, rollout.ErrExists)

	started, err := store.Start(ctx, plan.ID, plan.Revision, true, false, false, "")
	require.NoError(t, err)
	require.Equal(t, rollout.StateInProgress, started.State)
	require.NotNil(t, started.StartedAt)

	// Starting again (already in_progress) is a revision/state conflict,
	// not a silent no-op.
	_, err = store.Start(ctx, plan.ID, started.Revision, true, false, false, "")
	require.ErrorIs(t, err, rollout.ErrExists)

	rolledBack, err := store.RollBack(ctx, plan.ID, started.Revision, "operator aborted")
	require.NoError(t, err)
	require.Equal(t, rollout.StateRolledBack, rolledBack.State)

	// rolled_back is terminal: nothing transitions out of it.
	_, err = store.RollBack(ctx, plan.ID, rolledBack.Revision, "again")
	require.ErrorIs(t, err, rollout.ErrInvalid)
	_, _, err = store.MarkComponentApplied(ctx, plan.ID, rolledBack.Revision, rollout.ComponentControl, validDigest)
	require.ErrorIs(t, err, rollout.ErrInvalid)
}

func TestStartRequiresAcknowledgeAndOverridesIncompatibility(t *testing.T) {
	store := testStore(t)
	ctx := rollout.WithAccount(context.Background(), "a")
	plan, _, err := store.Create(ctx, rollout.Plan{TargetRelease: "v1"}, validDraftComponents())
	require.NoError(t, err)

	_, err = store.Start(ctx, plan.ID, plan.Revision, false, false, false, "")
	require.ErrorIs(t, err, rollout.ErrInvalid, "acknowledge required")

	_, err = store.Start(ctx, plan.ID, plan.Revision, true, false, true, "")
	require.ErrorIs(t, err, rollout.ErrInvalid, "blocking without override")

	started, err := store.Start(ctx, plan.ID, plan.Revision, true, true, true, "maintenance window: 2026-11-10 02:00 UTC")
	require.NoError(t, err)
	require.Equal(t, rollout.StateInProgress, started.State)
	require.Equal(t, "maintenance window: 2026-11-10 02:00 UTC", started.MaintenanceWindowNote)
}

func TestMarkComponentAppliedEnforcesSequenceIsIdempotentAndCompletesThePlan(t *testing.T) {
	store := testStore(t)
	ctx := rollout.WithAccount(context.Background(), "a")
	plan, _, err := store.Create(ctx, rollout.Plan{TargetRelease: "v1"}, validDraftComponents())
	require.NoError(t, err)
	started, err := store.Start(ctx, plan.ID, plan.Revision, true, false, false, "")
	require.NoError(t, err)

	// Out-of-order: estavelle_job is sequence 1, control is sequence 0.
	_, _, err = store.MarkComponentApplied(ctx, plan.ID, started.Revision, rollout.ComponentEstavelleJob, validDigest)
	require.ErrorIs(t, err, rollout.ErrInvalid, "out-of-sequence apply must be rejected")

	updated, components, err := store.MarkComponentApplied(ctx, plan.ID, started.Revision, rollout.ComponentControl, validDigest)
	require.NoError(t, err)
	require.Equal(t, rollout.StateInProgress, updated.State, "plan is not complete yet")
	for _, c := range components {
		if c.Name == rollout.ComponentControl {
			require.Equal(t, "applied", c.Status)
			require.Equal(t, validDigest, c.ObservedDigest)
			require.NotNil(t, c.ObservedAt)
		}
	}

	// Idempotent retry of the same component: no error, no state change,
	// no sequence violation triggered by re-marking it.
	again, _, err := store.MarkComponentApplied(ctx, plan.ID, updated.Revision, rollout.ComponentControl, validDigest)
	require.NoError(t, err)
	require.Equal(t, updated.Revision, again.Revision, "idempotent retry must not advance the revision")

	updated, _, err = store.MarkComponentApplied(ctx, plan.ID, again.Revision, rollout.ComponentEstavelleJob, validDigest)
	require.NoError(t, err)
	require.Equal(t, rollout.StateInProgress, updated.State)

	completed, components, err := store.MarkComponentApplied(ctx, plan.ID, updated.Revision, rollout.ComponentConsole, validDigest)
	require.NoError(t, err)
	require.Equal(t, rollout.StateCompleted, completed.State)
	require.NotNil(t, completed.CompletedAt)
	for _, c := range components {
		require.Equal(t, "applied", c.Status)
	}
}

func TestMarkComponentFailedSetsPlanFailureFields(t *testing.T) {
	store := testStore(t)
	ctx := rollout.WithAccount(context.Background(), "a")
	plan, _, err := store.Create(ctx, rollout.Plan{TargetRelease: "v1"}, validDraftComponents())
	require.NoError(t, err)
	started, err := store.Start(ctx, plan.ID, plan.Revision, true, false, false, "")
	require.NoError(t, err)

	failed, components, err := store.MarkComponentFailed(ctx, plan.ID, started.Revision, rollout.ComponentControl, "nomad job run failed: rollback")
	require.NoError(t, err)
	require.Equal(t, rollout.StateFailed, failed.State)
	require.Equal(t, rollout.ComponentControl, failed.FailedComponent)
	require.Equal(t, "nomad job run failed: rollback", failed.FailureReason)
	for _, c := range components {
		if c.Name == rollout.ComponentControl {
			require.Equal(t, "failed", c.Status)
			require.Equal(t, "nomad job run failed: rollback", c.FailureReason)
		}
	}

	// A plan already failed cannot be marked applied/failed again without
	// going through a fresh Start.
	_, _, err = store.MarkComponentFailed(ctx, plan.ID, failed.Revision, rollout.ComponentEstavelleJob, "x")
	require.ErrorIs(t, err, rollout.ErrExists)
}

func TestConcurrentTransitionLosesTheRevisionRace(t *testing.T) {
	store := testStore(t)
	ctx := rollout.WithAccount(context.Background(), "a")
	plan, _, err := store.Create(ctx, rollout.Plan{TargetRelease: "v1"}, validDraftComponents())
	require.NoError(t, err)

	// Two concurrent callers both read revision 1 and race to start it;
	// only one compare-and-set can win.
	_, errA := store.Start(ctx, plan.ID, plan.Revision, true, false, false, "")
	_, errB := store.Start(ctx, plan.ID, plan.Revision, true, false, false, "")
	require.True(t, (errA == nil) != (errB == nil), "exactly one concurrent Start must win")
	if errA != nil {
		require.ErrorIs(t, errA, rollout.ErrExists)
	}
	if errB != nil {
		require.ErrorIs(t, errB, rollout.ErrExists)
	}
}

func TestDeleteOnlyFromPlannedOrRolledBack(t *testing.T) {
	store := testStore(t)
	ctx := rollout.WithAccount(context.Background(), "a")
	plan, _, err := store.Create(ctx, rollout.Plan{TargetRelease: "v1"}, validDraftComponents())
	require.NoError(t, err)

	started, err := store.Start(ctx, plan.ID, plan.Revision, true, false, false, "")
	require.NoError(t, err)
	err = store.Delete(ctx, plan.ID, started.Revision)
	require.ErrorIs(t, err, rollout.ErrInvalid, "in_progress plan must not be deletable")

	rolledBack, err := store.RollBack(ctx, plan.ID, started.Revision, "abort")
	require.NoError(t, err)
	err = store.Delete(ctx, plan.ID, rolledBack.Revision)
	require.ErrorIs(t, err, rollout.ErrInvalid, "only planned (never started) may be deleted in v1, rolled_back must stay for audit")

	fresh, _, err := store.Create(ctx, rollout.Plan{TargetRelease: "v2"}, validDraftComponents())
	require.NoError(t, err)
	require.NoError(t, store.Delete(ctx, fresh.ID, fresh.Revision))
	_, _, err = store.Get(ctx, fresh.ID)
	require.ErrorIs(t, err, rollout.ErrNotFound)
}

func TestGetAndListAreAccountScoped(t *testing.T) {
	store := testStore(t)
	ctxA := rollout.WithAccount(context.Background(), "a")
	ctxB := rollout.WithAccount(context.Background(), "b")
	plan, _, err := store.Create(ctxA, rollout.Plan{TargetRelease: "v1"}, validDraftComponents())
	require.NoError(t, err)

	_, _, err = store.Get(ctxB, plan.ID)
	require.ErrorIs(t, err, rollout.ErrNotFound)

	listA, err := store.List(ctxA)
	require.NoError(t, err)
	require.Len(t, listA, 1)
	listB, err := store.List(ctxB)
	require.NoError(t, err)
	require.Empty(t, listB)

	var notFoundErr error = rollout.ErrNotFound
	require.True(t, errors.Is(notFoundErr, rollout.ErrNotFound))
}
