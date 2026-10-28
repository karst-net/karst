// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package relayreg

import (
	"context"
	"testing"
	"time"
)

func TestRecordDemandSampleSnapshotsCurrentDemandByRegion(t *testing.T) {
	s := newTestStore(t)
	a := mustCreateInRegion(t, s, "acct-a", "us-east-1", 0x10)
	if err := s.RecordTelemetry(context.Background(), "acct-a", a.ID, Telemetry{RTTUnder20ms: 5, RTTOver100ms: 1}); err != nil {
		t.Fatalf("record telemetry: %v", err)
	}

	before := time.Now().UTC()
	if err := s.RecordDemandSample(context.Background()); err != nil {
		t.Fatalf("record demand sample: %v", err)
	}
	after := time.Now().UTC()

	got, err := s.DemandHistory(context.Background(), before.Add(-time.Second), after.Add(time.Second))
	if err != nil {
		t.Fatalf("demand history: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d samples, want 1: %+v", len(got), got)
	}
	if got[0].Region != "us-east-1" || got[0].AccountID != "acct-a" || got[0].RTTUnder20ms != 5 || got[0].RTTOver100ms != 1 {
		t.Fatalf("got %+v, want region=us-east-1 account=acct-a RTTUnder20ms=5 RTTOver100ms=1", got[0])
	}
	if got[0].SampledAt.Before(before) || got[0].SampledAt.After(after) {
		t.Fatalf("SampledAt %v not within [%v, %v]", got[0].SampledAt, before, after)
	}
}

func TestRecordDemandSampleWritesNothingWhenThereIsNoDemand(t *testing.T) {
	s := newTestStore(t)
	mustCreateInRegion(t, s, "acct-a", "us-east-1", 0x11) // registered, never reported

	if err := s.RecordDemandSample(context.Background()); err != nil {
		t.Fatalf("record demand sample: %v", err)
	}
	got, err := s.DemandHistory(context.Background(), time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("demand history: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %d samples, want 0 — no demand means nothing to sample", len(got))
	}
}

func TestDemandHistoryOnlyReturnsSamplesInRange(t *testing.T) {
	s := newTestStore(t)
	now := time.Now().UTC()
	samples := []RegionDemandSample{
		{Region: "us-east-1", AccountID: "acct-a", SampledAt: now.Add(-48 * time.Hour), RTTUnder20ms: 1},
		{Region: "us-east-1", AccountID: "acct-a", SampledAt: now.Add(-1 * time.Hour), RTTUnder20ms: 2},
		{Region: "us-east-1", AccountID: "acct-a", SampledAt: now, RTTUnder20ms: 3},
	}
	if err := s.db.Create(&samples).Error; err != nil {
		t.Fatalf("seed samples: %v", err)
	}

	got, err := s.DemandHistory(context.Background(), now.Add(-2*time.Hour), now.Add(time.Second))
	if err != nil {
		t.Fatalf("demand history: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d samples, want 2 (the -1h and now samples, not the -48h one): %+v", len(got), got)
	}
	if got[0].RTTUnder20ms != 2 || got[1].RTTUnder20ms != 3 {
		t.Fatalf("got RTTUnder20ms %d, %d in that order, want 2 then 3 (ordered by SampledAt)", got[0].RTTUnder20ms, got[1].RTTUnder20ms)
	}
}

func TestPruneDemandHistoryRemovesOnlySamplesOlderThanCutoff(t *testing.T) {
	s := newTestStore(t)
	now := time.Now().UTC()
	samples := []RegionDemandSample{
		{Region: "us-east-1", AccountID: "acct-a", SampledAt: now.Add(-400 * 24 * time.Hour), RTTUnder20ms: 1},
		{Region: "us-east-1", AccountID: "acct-a", SampledAt: now, RTTUnder20ms: 2},
	}
	if err := s.db.Create(&samples).Error; err != nil {
		t.Fatalf("seed samples: %v", err)
	}

	if err := s.PruneDemandHistory(context.Background(), now.Add(-200*24*time.Hour)); err != nil {
		t.Fatalf("prune demand history: %v", err)
	}

	got, err := s.DemandHistory(context.Background(), now.Add(-500*24*time.Hour), now.Add(time.Second))
	if err != nil {
		t.Fatalf("demand history: %v", err)
	}
	if len(got) != 1 || got[0].RTTUnder20ms != 2 {
		t.Fatalf("got %+v, want exactly the recent sample (RTTUnder20ms=2) surviving", got)
	}
}

func TestStartDemandHistoryWorkerSamplesImmediatelyOnStartup(t *testing.T) {
	s := newTestStore(t)
	a := mustCreateInRegion(t, s, "acct-a", "us-east-1", 0x12)
	if err := s.RecordTelemetry(context.Background(), "acct-a", a.ID, Telemetry{RTTUnder20ms: 7}); err != nil {
		t.Fatalf("record telemetry: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// A long interval: this test only checks the immediate first pass, not
	// the ticker — a restart should not wait a full interval for a sample.
	s.StartDemandHistoryWorker(ctx, time.Hour, 400*24*time.Hour)

	deadline := time.Now().Add(2 * time.Second)
	for {
		got, err := s.DemandHistory(context.Background(), time.Now().Add(-time.Minute), time.Now().Add(time.Second))
		if err == nil && len(got) == 1 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no sample recorded within 2s of starting the worker (last query error: %v)", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
