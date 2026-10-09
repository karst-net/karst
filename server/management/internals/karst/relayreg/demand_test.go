// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package relayreg

import (
	"context"
	"testing"
)

func mustCreateInRegion(t *testing.T, s *Store, accountID, region string, seed byte) *StoredRelay {
	t.Helper()
	relay, err := s.Create(WithAccount(context.Background(), accountID), Entry{
		Address:       "203.0.113.7:443",
		TLSServerName: "relay.example.com",
		IdentityKey:   testKey(seed),
		Region:        region,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	return relay
}

func TestDemandByRegionSumsAcrossRelaysInTheSameRegionAndAccount(t *testing.T) {
	s := newTestStore(t)
	a := mustCreateInRegion(t, s, "acct-a", "us-east-1", 0x01)
	b := mustCreateInRegion(t, s, "acct-a", "us-east-1", 0x02)

	if err := s.RecordTelemetry(context.Background(), "acct-a", a.ID, Telemetry{RTTUnder20ms: 5, RTT20To50ms: 1}); err != nil {
		t.Fatalf("record telemetry: %v", err)
	}
	if err := s.RecordTelemetry(context.Background(), "acct-a", b.ID, Telemetry{RTTUnder20ms: 3, RTTOver100ms: 2}); err != nil {
		t.Fatalf("record telemetry: %v", err)
	}

	got, err := s.DemandByRegion(context.Background())
	if err != nil {
		t.Fatalf("demand by region: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d rows, want 1: %+v", len(got), got)
	}
	want := RegionDemand{Region: "us-east-1", AccountID: "acct-a", RTTUnder20ms: 8, RTT20To50ms: 1, RTTOver100ms: 2}
	if got[0] != want {
		t.Fatalf("got %+v, want %+v", got[0], want)
	}
}

func TestDemandByRegionKeepsDifferentAccountsInTheSameRegionSeparate(t *testing.T) {
	s := newTestStore(t)
	a := mustCreateInRegion(t, s, "acct-a", "us-east-1", 0x03)
	b := mustCreateInRegion(t, s, "acct-b", "us-east-1", 0x04)
	if err := s.RecordTelemetry(context.Background(), "acct-a", a.ID, Telemetry{RTTUnder20ms: 10}); err != nil {
		t.Fatalf("record telemetry: %v", err)
	}
	if err := s.RecordTelemetry(context.Background(), "acct-b", b.ID, Telemetry{RTTUnder20ms: 20}); err != nil {
		t.Fatalf("record telemetry: %v", err)
	}

	got, err := s.DemandByRegion(context.Background())
	if err != nil {
		t.Fatalf("demand by region: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d rows, want 2 (one per account): %+v", len(got), got)
	}
	if got[0].AccountID != "acct-a" || got[0].RTTUnder20ms != 10 {
		t.Fatalf("row 0 = %+v, want acct-a/10", got[0])
	}
	if got[1].AccountID != "acct-b" || got[1].RTTUnder20ms != 20 {
		t.Fatalf("row 1 = %+v, want acct-b/20", got[1])
	}
}

func TestDemandByRegionKeepsDifferentRegionsSeparate(t *testing.T) {
	s := newTestStore(t)
	a := mustCreateInRegion(t, s, "acct-a", "us-east-1", 0x05)
	b := mustCreateInRegion(t, s, "acct-a", "eu-west-1", 0x06)
	if err := s.RecordTelemetry(context.Background(), "acct-a", a.ID, Telemetry{RTTUnder20ms: 1}); err != nil {
		t.Fatalf("record telemetry: %v", err)
	}
	if err := s.RecordTelemetry(context.Background(), "acct-a", b.ID, Telemetry{RTTUnder20ms: 2}); err != nil {
		t.Fatalf("record telemetry: %v", err)
	}

	got, err := s.DemandByRegion(context.Background())
	if err != nil {
		t.Fatalf("demand by region: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d rows, want 2 (one per region): %+v", len(got), got)
	}
	// Sorted by region, then account — "eu-west-1" < "us-east-1".
	if got[0].Region != "eu-west-1" || got[1].Region != "us-east-1" {
		t.Fatalf("got regions %q, %q, want eu-west-1 then us-east-1", got[0].Region, got[1].Region)
	}
}

func TestDemandByRegionIsEmptyWithNoTelemetryAtAll(t *testing.T) {
	s := newTestStore(t)
	mustCreateInRegion(t, s, "acct-a", "us-east-1", 0x07) // registered, never reported

	got, err := s.DemandByRegion(context.Background())
	if err != nil {
		t.Fatalf("demand by region: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %d rows, want 0 — a relay that never reported contributes nothing, not a zero-filled row", len(got))
	}
}

func TestDemandByRegionSkipsTelemetryForADeletedRelay(t *testing.T) {
	s := newTestStore(t)
	a := mustCreateInRegion(t, s, "acct-a", "us-east-1", 0x08)
	if err := s.RecordTelemetry(context.Background(), "acct-a", a.ID, Telemetry{RTTUnder20ms: 99}); err != nil {
		t.Fatalf("record telemetry: %v", err)
	}
	if err := s.Delete(WithAccount(context.Background(), "acct-a"), a.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}

	got, err := s.DemandByRegion(context.Background())
	if err != nil {
		t.Fatalf("demand by region: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %d rows, want 0 — an orphaned telemetry row for a deleted relay names no region", len(got))
	}
}
