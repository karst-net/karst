// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package relayreg

import (
	"bytes"
	"context"
	"encoding/base64"
	"testing"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// newTestStore gives each test its own in-memory database, named after the
// test so a failure names which one leaked state rather than every test
// sharing one and depending on run order.
func newTestStore(t *testing.T) *Store {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("db: %v", err)
	}
	store, err := NewStore(db)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	return store
}

func testKey(seed byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{seed}, IdentityKeySize))
}

func mustCreate(t *testing.T, s *Store, accountID string, seed byte) *StoredRelay {
	t.Helper()
	relay, err := s.Create(WithAccount(context.Background(), accountID), Entry{
		Address:       "203.0.113.7:443",
		TLSServerName: "relay.example.com",
		IdentityKey:   testKey(seed),
		Region:        "eu",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	return relay
}

func TestFindByIDIsNotAccountScoped(t *testing.T) {
	s := newTestStore(t)
	relay := mustCreate(t, s, "acct-a", 0x11)

	// No WithAccount in this context at all — the point of FindByID.
	found, err := s.FindByID(context.Background(), relay.ID)
	if err != nil {
		t.Fatalf("find by id: %v", err)
	}
	if len(found) != 1 || found[0].AccountID != "acct-a" {
		t.Fatalf("got %+v, want exactly the one row under acct-a", found)
	}
}

func TestFindByIDFindsTheSameKeyUnderEveryAccountThatRegisteredIt(t *testing.T) {
	s := newTestStore(t)
	a := mustCreate(t, s, "acct-a", 0x22)
	mustCreate(t, s, "acct-b", 0x22) // same key, different account

	found, err := s.FindByID(context.Background(), a.ID)
	if err != nil {
		t.Fatalf("find by id: %v", err)
	}
	if len(found) != 2 {
		t.Fatalf("got %d rows, want 2 (one per account that registered this key)", len(found))
	}
}

func TestFindByIDIsEmptyForAnUnregisteredID(t *testing.T) {
	s := newTestStore(t)
	found, err := s.FindByID(context.Background(), "not-a-registered-id")
	if err != nil {
		t.Fatalf("find by id: %v", err)
	}
	if len(found) != 0 {
		t.Fatalf("got %d rows, want 0", len(found))
	}
}

func TestLatestTelemetryIsNilBeforeAnyReport(t *testing.T) {
	s := newTestStore(t)
	relay := mustCreate(t, s, "acct-a", 0x33)

	record, err := s.LatestTelemetry(WithAccount(context.Background(), "acct-a"), relay.ID)
	if err != nil {
		t.Fatalf("latest telemetry: %v", err)
	}
	if record != nil {
		t.Fatalf("got %+v, want nil — nothing has reported yet", record)
	}
}

func TestRecordTelemetryThenLatestTelemetryRoundTrips(t *testing.T) {
	s := newTestStore(t)
	relay := mustCreate(t, s, "acct-a", 0x44)
	ctx := WithAccount(context.Background(), "acct-a")

	report := Telemetry{LocalClients: 5, MeshPeers: 1, RemoteClients: 9, BytesTotal: 123456, UptimeSecs: 3600}
	if err := s.RecordTelemetry(ctx, "acct-a", relay.ID, report); err != nil {
		t.Fatalf("record telemetry: %v", err)
	}

	got, err := s.LatestTelemetry(ctx, relay.ID)
	if err != nil {
		t.Fatalf("latest telemetry: %v", err)
	}
	if got == nil {
		t.Fatalf("got nil, want a record")
	}
	if got.LocalClients != 5 || got.MeshPeers != 1 || got.RemoteClients != 9 || got.BytesTotal != 123456 || got.UptimeSecs != 3600 {
		t.Fatalf("got %+v, want the report unchanged", got)
	}
	if time.Since(got.ReportedAt) > time.Minute {
		t.Fatalf("ReportedAt = %v, want close to now", got.ReportedAt)
	}
}

func TestRecordTelemetryReplacesThePreviousReport(t *testing.T) {
	s := newTestStore(t)
	relay := mustCreate(t, s, "acct-a", 0x55)
	ctx := WithAccount(context.Background(), "acct-a")

	if err := s.RecordTelemetry(ctx, "acct-a", relay.ID, Telemetry{LocalClients: 1}); err != nil {
		t.Fatalf("first report: %v", err)
	}
	if err := s.RecordTelemetry(ctx, "acct-a", relay.ID, Telemetry{LocalClients: 2}); err != nil {
		t.Fatalf("second report: %v", err)
	}

	got, err := s.LatestTelemetry(ctx, relay.ID)
	if err != nil {
		t.Fatalf("latest telemetry: %v", err)
	}
	if got == nil || got.LocalClients != 2 {
		t.Fatalf("got %+v, want the second report to have replaced the first", got)
	}
}

func TestLatestTelemetryIsScopedToTheAskingAccount(t *testing.T) {
	s := newTestStore(t)
	a := mustCreate(t, s, "acct-a", 0x66)
	b := mustCreate(t, s, "acct-b", 0x77)
	if err := s.RecordTelemetry(context.Background(), "acct-a", a.ID, Telemetry{LocalClients: 1}); err != nil {
		t.Fatalf("record for acct-a: %v", err)
	}

	// acct-b asking about its own (different) relay must not see acct-a's report.
	got, err := s.LatestTelemetry(WithAccount(context.Background(), "acct-b"), b.ID)
	if err != nil {
		t.Fatalf("latest telemetry: %v", err)
	}
	if got != nil {
		t.Fatalf("got %+v, want nil — acct-b's relay has never reported", got)
	}
}
