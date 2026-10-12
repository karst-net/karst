// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package billing

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func testBillingStore(t *testing.T) *Store {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:billing-store-%s?mode=memory&cache=shared", t.Name())), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	store, err := NewStore(db)
	if err != nil {
		t.Fatalf("new billing store: %v", err)
	}
	return store
}

func testSchedule() RateSchedule {
	return RateSchedule{
		Version: "pilot-2026-01", Currency: "USD",
		DeviceTiers:        []DeviceTier{{UpToDevices: 10, MinorPerPeriod: 250}, {UpToDevices: 50, MinorPerPeriod: 150}, {MinorPerPeriod: 75}},
		RelayIncludedBytes: 10_000_000_000, RelayUnitBytes: 1_000_000_000, RelayMinorPerUnit: 20,
	}
}

func TestStoreRequiresExplicitAccountAndAssignment(t *testing.T) {
	store := testBillingStore(t)
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	end := start.AddDate(0, 1, 0)
	if err := store.AssignSchedule(context.Background(), start, end, "pilot-2026-01"); !errors.Is(err, ErrNoBillingAccount) {
		t.Fatalf("AssignSchedule without account = %v, want ErrNoBillingAccount", err)
	}
	if _, err := store.Assignment(context.Background(), start, end); !errors.Is(err, ErrNoBillingAccount) {
		t.Fatalf("Assignment without account = %v, want ErrNoBillingAccount", err)
	}
	ctx := WithAccount(context.Background(), "org-1")
	if _, err := store.Assignment(ctx, start, end); !errors.Is(err, ErrScheduleUnassigned) {
		t.Fatalf("unconfigured account assignment = %v, want ErrScheduleUnassigned", err)
	}
}

func TestStorePersistsImmutableSchedulesAndExplicitAssignments(t *testing.T) {
	store := testBillingStore(t)
	ctx := WithAccount(context.Background(), "org-1")
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	end := start.AddDate(0, 1, 0)
	schedule := testSchedule()
	if err := store.PutSchedule(ctx, schedule); err != nil {
		t.Fatalf("put schedule: %v", err)
	}
	if err := store.PutSchedule(ctx, schedule); err != nil {
		t.Fatalf("repeat identical schedule: %v", err)
	}
	loaded, err := store.Schedule(ctx, schedule.Version)
	if err != nil {
		t.Fatalf("load schedule: %v", err)
	}
	if len(loaded.DeviceTiers) != len(schedule.DeviceTiers) || loaded.DeviceTiers[1] != schedule.DeviceTiers[1] || loaded.RelayIncludedBytes != schedule.RelayIncludedBytes {
		t.Fatalf("loaded schedule differs: got %+v, want %+v", loaded, schedule)
	}

	conflict := schedule
	conflict.DeviceTiers = append([]DeviceTier(nil), schedule.DeviceTiers...)
	conflict.DeviceTiers[0].MinorPerPeriod++
	if err := store.PutSchedule(ctx, conflict); !errors.Is(err, ErrScheduleConflict) {
		t.Fatalf("put changed schedule under same version = %v, want ErrScheduleConflict", err)
	}

	if err := store.AssignSchedule(ctx, start, end, schedule.Version); err != nil {
		t.Fatalf("assign schedule: %v", err)
	}
	if err := store.AssignSchedule(ctx, start, end, schedule.Version); err != nil {
		t.Fatalf("repeat identical assignment: %v", err)
	}
	assignment, err := store.Assignment(ctx, start, end)
	if err != nil {
		t.Fatalf("load assignment: %v", err)
	}
	if assignment.AccountID != "org-1" || !assignment.PeriodStart.Equal(start) || !assignment.PeriodEnd.Equal(end) || assignment.ScheduleVersion != schedule.Version {
		t.Fatalf("unexpected assignment: %+v", assignment)
	}
	assigned, err := store.AssignedSchedule(ctx, start, end)
	if err != nil || assigned.Version != schedule.Version {
		t.Fatalf("load assigned schedule: schedule=%+v err=%v", assigned, err)
	}
	if _, err := store.Assignment(WithAccount(context.Background(), "org-2"), start, end); !errors.Is(err, ErrScheduleUnassigned) {
		t.Fatalf("other account inherited assignment: %v", err)
	}
}

func TestStorePersistsAcrossInstances(t *testing.T) {
	path := filepath.Join(t.TempDir(), "billing.db")
	open := func() *gorm.DB {
		db, err := gorm.Open(sqlite.Open(path), &gorm.Config{Logger: logger.Discard})
		if err != nil {
			t.Fatalf("open sqlite: %v", err)
		}
		return db
	}
	first, err := NewStore(open())
	if err != nil {
		t.Fatalf("create first store: %v", err)
	}
	schedule := testSchedule()
	if err := first.PutSchedule(context.Background(), schedule); err != nil {
		t.Fatalf("put schedule: %v", err)
	}
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	end := start.AddDate(0, 1, 0)
	ctx := WithAccount(context.Background(), "org-persistent")
	if err := first.AssignSchedule(ctx, start, end, schedule.Version); err != nil {
		t.Fatalf("assign schedule: %v", err)
	}
	second, err := NewStore(open())
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	got, err := second.AssignedSchedule(ctx, start, end)
	if err != nil || got.Version != schedule.Version {
		t.Fatalf("reopened assigned schedule = %+v, %v; want %q", got, err, schedule.Version)
	}
}

func TestStoreRejectsUnknownScheduleInvalidPeriodsAndOverlaps(t *testing.T) {
	store := testBillingStore(t)
	ctx := WithAccount(context.Background(), "org-1")
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	end := start.AddDate(0, 1, 0)
	if err := store.AssignSchedule(ctx, start, end, "missing"); !errors.Is(err, ErrScheduleNotFound) {
		t.Fatalf("assign unknown schedule = %v, want ErrScheduleNotFound", err)
	}
	if err := store.AssignSchedule(ctx, end, start, "missing"); !errors.Is(err, ErrInvalidPeriod) {
		t.Fatalf("assign invalid period = %v, want ErrInvalidPeriod", err)
	}
	if err := store.PutSchedule(ctx, testSchedule()); err != nil {
		t.Fatalf("put schedule: %v", err)
	}
	if err := store.AssignSchedule(ctx, start, end, testSchedule().Version); err != nil {
		t.Fatalf("assign schedule: %v", err)
	}
	if err := store.AssignSchedule(ctx, start, end.Add(time.Hour), testSchedule().Version); !errors.Is(err, ErrAssignmentConflict) {
		t.Fatalf("reassign period with changed boundary = %v, want ErrAssignmentConflict", err)
	}
	if err := store.AssignSchedule(ctx, end.Add(-time.Hour), end.AddDate(0, 1, 0), testSchedule().Version); !errors.Is(err, ErrAssignmentConflict) {
		t.Fatalf("assign overlapping period = %v, want ErrAssignmentConflict", err)
	}
}
