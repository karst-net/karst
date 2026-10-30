// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package relayreg

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
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

// TestRecordTelemetryDetectedLocationRoundTrips covers ADR-0048: a
// relay-detected location (via cloud metadata) round-trips through the
// same upsert as the rest of the report.
func TestRecordTelemetryDetectedLocationRoundTrips(t *testing.T) {
	s := newTestStore(t)
	relay := mustCreate(t, s, "acct-a", 0x66)
	ctx := WithAccount(context.Background(), "acct-a")

	lat, lon := 47.6062, -122.3321
	if err := s.RecordTelemetry(ctx, "acct-a", relay.ID, Telemetry{LocalClients: 1, DetectedLat: &lat, DetectedLon: &lon}); err != nil {
		t.Fatalf("record telemetry: %v", err)
	}

	got, err := s.LatestTelemetry(ctx, relay.ID)
	if err != nil {
		t.Fatalf("latest telemetry: %v", err)
	}
	if got == nil || got.DetectedLat == nil || got.DetectedLon == nil || *got.DetectedLat != lat || *got.DetectedLon != lon {
		t.Fatalf("got %+v, want detected location (%v, %v)", got, lat, lon)
	}
}

// TestRecordTelemetryClearsAStaleDetectedLocation is the companion case: a
// relay that stops reporting a location (has_location=false on a later
// tick) must have that clear the stored value, not leave a stale one
// behind from a previous report.
func TestRecordTelemetryClearsAStaleDetectedLocation(t *testing.T) {
	s := newTestStore(t)
	relay := mustCreate(t, s, "acct-a", 0x77)
	ctx := WithAccount(context.Background(), "acct-a")

	lat, lon := 47.6062, -122.3321
	if err := s.RecordTelemetry(ctx, "acct-a", relay.ID, Telemetry{LocalClients: 1, DetectedLat: &lat, DetectedLon: &lon}); err != nil {
		t.Fatalf("first report: %v", err)
	}
	if err := s.RecordTelemetry(ctx, "acct-a", relay.ID, Telemetry{LocalClients: 2}); err != nil {
		t.Fatalf("second report: %v", err)
	}

	got, err := s.LatestTelemetry(ctx, relay.ID)
	if err != nil {
		t.Fatalf("latest telemetry: %v", err)
	}
	if got == nil || got.DetectedLat != nil || got.DetectedLon != nil {
		t.Fatalf("got %+v, want the stale location cleared by the second report", got)
	}
}

// TestADeclaredLocationSurvivesCreateAndList covers the NOC-map data path
// end to end: Entry.Location -> StoredRelay's flat columns -> back out
// through List, and through ToProto -> compiledRelay's cache/clone path.
func TestADeclaredLocationSurvivesCreateAndList(t *testing.T) {
	s := newTestStore(t)
	ctx := WithAccount(context.Background(), "acct-a")
	_, err := s.Create(ctx, Entry{
		Address:       "203.0.113.7:443",
		TLSServerName: "relay.example.com",
		IdentityKey:   testKey(0x88),
		Region:        "eu",
		Location:      &Location{Lat: 51.5072, Lon: -0.1276, Label: "London"},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	records, err := s.List(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(records) != 1 || records[0].LocationLat == nil {
		t.Fatalf("got %+v, want one record with a location", records)
	}
	if *records[0].LocationLat != 51.5072 || *records[0].LocationLon != -0.1276 || records[0].LocationLabel != "London" {
		t.Fatalf("location = (%v, %v, %q), want (51.5072, -0.1276, \"London\")",
			*records[0].LocationLat, *records[0].LocationLon, records[0].LocationLabel)
	}

	relay, err := records[0].ToProto()
	if err != nil {
		t.Fatalf("to proto: %v", err)
	}
	if relay.GetLocation() == nil || relay.GetLocation().GetLabel() != "London" {
		t.Fatalf("ToProto location = %+v, want London", relay.GetLocation())
	}
}

// TestNoDeclaredLocationStaysNilThroughTheStore is the companion case: a
// relay created with no Location must never pick one up on the way through
// storage — ADR-0046 §1's "never a guessed pin."
func TestNoDeclaredLocationStaysNilThroughTheStore(t *testing.T) {
	s := newTestStore(t)
	relay := mustCreate(t, s, "acct-a", 0x99)
	if relay.LocationLat != nil {
		t.Fatalf("a relay created with no location got one: %+v", relay)
	}

	proto, err := relay.ToProto()
	if err != nil {
		t.Fatalf("to proto: %v", err)
	}
	if proto.GetLocation() != nil {
		t.Fatalf("ToProto location = %+v, want nil", proto.GetLocation())
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

// mustCreateWithAddress is mustCreate but for DeleteByAddress's own tests,
// which need addresses that actually differ between rows — mustCreate's
// fixed "203.0.113.7:443" is fine for every other test here, which never
// looks up by address.
func mustCreateWithAddress(t *testing.T, s *Store, accountID string, seed byte, address string) *StoredRelay {
	t.Helper()
	relay, err := s.Create(WithAccount(context.Background(), accountID), Entry{
		Address:       address,
		TLSServerName: "relay.example.com",
		IdentityKey:   testKey(seed),
		Region:        "eu",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	return relay
}

// mustCreateWithTLSServerName is mustCreateWithAddress's own counterpart
// for DeleteByTLSServerName's tests (#329) -- which need TLSServerName
// values that actually differ between rows, unlike mustCreate's fixed
// "relay.example.com".
func mustCreateWithTLSServerName(t *testing.T, s *Store, accountID string, seed byte, tlsServerName string) *StoredRelay {
	t.Helper()
	relay, err := s.Create(WithAccount(context.Background(), accountID), Entry{
		Address:       "203.0.113.50:443",
		TLSServerName: tlsServerName,
		IdentityKey:   testKey(seed),
		Region:        "eu",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	return relay
}

func TestDeleteByTLSServerNameRemovesTheMatchingEntry(t *testing.T) {
	s := newTestStore(t)
	ctx := WithAccount(context.Background(), "acct-a")
	kept := mustCreateWithTLSServerName(t, s, "acct-a", 0xee, "pool-aaaaaa.aws.karst.internal")
	mustCreateWithTLSServerName(t, s, "acct-a", 0xff, "pool-bbbbbb.aws.karst.internal")

	if err := s.DeleteByTLSServerName(ctx, "pool-bbbbbb.aws.karst.internal"); err != nil {
		t.Fatalf("delete by tls_server_name: %v", err)
	}

	remaining, err := s.List(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(remaining) != 1 || remaining[0].ID != kept.ID {
		t.Fatalf("got %+v, want only the untouched relay at pool-aaaaaa...", remaining)
	}
}

func TestDeleteByTLSServerNameOfAnUnknownNameIsErrNotFound(t *testing.T) {
	s := newTestStore(t)
	ctx := WithAccount(context.Background(), "acct-a")
	mustCreateWithTLSServerName(t, s, "acct-a", 0x12, "pool-cccccc.aws.karst.internal")

	err := s.DeleteByTLSServerName(ctx, "pool-never-registered.aws.karst.internal")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete by tls_server_name: got %v, want ErrNotFound", err)
	}
}

func TestDeleteByTLSServerNameIsScopedToTheAskingAccount(t *testing.T) {
	s := newTestStore(t)
	mustCreateWithTLSServerName(t, s, "acct-a", 0x34, "pool-dddddd.aws.karst.internal")

	// acct-b asking to remove acct-a's relay by its tls_server_name must
	// not find it.
	err := s.DeleteByTLSServerName(WithAccount(context.Background(), "acct-b"), "pool-dddddd.aws.karst.internal")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete by tls_server_name across accounts: got %v, want ErrNotFound", err)
	}

	remaining, err := s.List(WithAccount(context.Background(), "acct-a"))
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(remaining) != 1 {
		t.Fatalf("got %+v, want acct-a's relay untouched", remaining)
	}
}

func TestFindByTLSServerNameReturnsTheMatchingEntry(t *testing.T) {
	s := newTestStore(t)
	ctx := WithAccount(context.Background(), "acct-a")
	kept := mustCreateWithTLSServerName(t, s, "acct-a", 0xaa, "pool-eeeeee.aws.karst.internal")
	mustCreateWithTLSServerName(t, s, "acct-a", 0xbb, "pool-ffffff.aws.karst.internal")

	found, err := s.FindByTLSServerName(ctx, "pool-eeeeee.aws.karst.internal")
	if err != nil {
		t.Fatalf("find by tls_server_name: %v", err)
	}
	if found.ID != kept.ID {
		t.Fatalf("got %+v, want the relay at pool-eeeeee...", found)
	}
}

func TestFindByTLSServerNameOfAnUnknownNameIsErrNotFound(t *testing.T) {
	s := newTestStore(t)
	ctx := WithAccount(context.Background(), "acct-a")
	mustCreateWithTLSServerName(t, s, "acct-a", 0xcc, "pool-gggggg.aws.karst.internal")

	_, err := s.FindByTLSServerName(ctx, "pool-never-registered.aws.karst.internal")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("find by tls_server_name: got %v, want ErrNotFound", err)
	}
}

func TestFindByTLSServerNameIsScopedToTheAskingAccount(t *testing.T) {
	s := newTestStore(t)
	mustCreateWithTLSServerName(t, s, "acct-a", 0xdd, "pool-hhhhhh.aws.karst.internal")

	_, err := s.FindByTLSServerName(WithAccount(context.Background(), "acct-b"), "pool-hhhhhh.aws.karst.internal")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("find by tls_server_name across accounts: got %v, want ErrNotFound", err)
	}
}

func TestDeleteByAddressRemovesTheMatchingEntry(t *testing.T) {
	s := newTestStore(t)
	ctx := WithAccount(context.Background(), "acct-a")
	kept := mustCreateWithAddress(t, s, "acct-a", 0xaa, "203.0.113.1:443")
	mustCreateWithAddress(t, s, "acct-a", 0xbb, "203.0.113.2:443")

	if err := s.DeleteByAddress(ctx, "203.0.113.2:443"); err != nil {
		t.Fatalf("delete by address: %v", err)
	}

	remaining, err := s.List(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(remaining) != 1 || remaining[0].ID != kept.ID {
		t.Fatalf("got %+v, want only the untouched relay at 203.0.113.1:443", remaining)
	}
}

func TestDeleteByAddressOfAnUnknownAddressIsErrNotFound(t *testing.T) {
	s := newTestStore(t)
	ctx := WithAccount(context.Background(), "acct-a")
	mustCreateWithAddress(t, s, "acct-a", 0xcc, "203.0.113.3:443")

	err := s.DeleteByAddress(ctx, "203.0.113.99:443")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete by address: got %v, want ErrNotFound", err)
	}
}

func TestDeleteByAddressIsScopedToTheAskingAccount(t *testing.T) {
	s := newTestStore(t)
	mustCreateWithAddress(t, s, "acct-a", 0xdd, "203.0.113.4:443")

	// acct-b asking to remove acct-a's relay by its address must not find it.
	err := s.DeleteByAddress(WithAccount(context.Background(), "acct-b"), "203.0.113.4:443")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete by address across accounts: got %v, want ErrNotFound", err)
	}

	// Confirmed still there under its real account.
	remaining, err := s.List(WithAccount(context.Background(), "acct-a"))
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(remaining) != 1 {
		t.Fatalf("got %+v, want acct-a's relay untouched", remaining)
	}
}
