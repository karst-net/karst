// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package routetelemetry

import (
	"context"
	"testing"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

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

func TestRecordThenRead(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	report := RouteReport{Bytes: 1000, Packets: 10, IngressBytes: 400, IngressPackets: 4}
	if err := s.RecordRouteBytes(ctx, "acct-a", "route-1", report); err != nil {
		t.Fatalf("record: %v", err)
	}
	byRoute, err := s.LatestByRoute(ctx, "acct-a")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	got, ok := byRoute["route-1"]
	if !ok {
		t.Fatalf("route-1 not found in %+v", byRoute)
	}
	if got.Bytes != 1000 || got.Packets != 10 || got.IngressBytes != 400 || got.IngressPackets != 4 {
		t.Fatalf("got %+v, want bytes=1000 packets=10 ingress_bytes=400 ingress_packets=4", got)
	}
}

func TestRecordTwiceReplacesRatherThanAccumulates(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	first := RouteReport{Bytes: 1000, Packets: 10, IngressBytes: 400, IngressPackets: 4}
	if err := s.RecordRouteBytes(ctx, "acct-a", "route-1", first); err != nil {
		t.Fatalf("first record: %v", err)
	}
	// A real gateway reports a running total every tick, never a delta —
	// a later report's own count already includes everything the first one
	// did. The store must replace, not add, or every tick would double the
	// true figure.
	second := RouteReport{Bytes: 1500, Packets: 15, IngressBytes: 600, IngressPackets: 6}
	if err := s.RecordRouteBytes(ctx, "acct-a", "route-1", second); err != nil {
		t.Fatalf("second record: %v", err)
	}
	byRoute, err := s.LatestByRoute(ctx, "acct-a")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	got := byRoute["route-1"]
	if got.Bytes != 1500 || got.Packets != 15 || got.IngressBytes != 600 || got.IngressPackets != 6 {
		t.Fatalf("got %+v, want the replaced second report, not an accumulation", got)
	}
}

func TestForwardingActiveReplacesOnEachReportIncludingToFalse(t *testing.T) {
	// Issue #404: the gateway reports this every tick for as long as it
	// holds the offer, including a transition from active to inactive
	// (e.g. an nftables apply failure after a previously-healthy report).
	// The replace-not-accumulate contract above must hold for this bool
	// field too -- a stale "true" surviving a later "false" report would
	// show an operator a route as ready when it no longer is.
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.RecordRouteBytes(ctx, "acct-a", "route-1", RouteReport{ForwardingActive: true}); err != nil {
		t.Fatalf("record active: %v", err)
	}
	byRoute, err := s.LatestByRoute(ctx, "acct-a")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !byRoute["route-1"].ForwardingActive {
		t.Fatalf("got %+v, want ForwardingActive=true", byRoute["route-1"])
	}
	if err := s.RecordRouteBytes(ctx, "acct-a", "route-1", RouteReport{ForwardingActive: false}); err != nil {
		t.Fatalf("record inactive: %v", err)
	}
	byRoute, err = s.LatestByRoute(ctx, "acct-a")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if byRoute["route-1"].ForwardingActive {
		t.Fatalf("got %+v, want the later false report to replace the earlier true one", byRoute["route-1"])
	}
}

func TestLatestByRouteIsScopedToOneAccount(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.RecordRouteBytes(ctx, "acct-a", "route-1", RouteReport{Bytes: 1000, Packets: 10}); err != nil {
		t.Fatalf("record acct-a: %v", err)
	}
	if err := s.RecordRouteBytes(ctx, "acct-b", "route-1", RouteReport{Bytes: 2000, Packets: 20}); err != nil {
		t.Fatalf("record acct-b: %v", err)
	}
	byRoute, err := s.LatestByRoute(ctx, "acct-a")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(byRoute) != 1 || byRoute["route-1"].Bytes != 1000 {
		t.Fatalf("got %+v, want only acct-a's own 1000 bytes for route-1", byRoute)
	}
}

func TestRecordRejectsEmptyFields(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	report := RouteReport{Bytes: 1000, Packets: 10}
	if err := s.RecordRouteBytes(ctx, "", "route-1", report); err == nil {
		t.Fatal("empty account id: want an error, got nil")
	}
	if err := s.RecordRouteBytes(ctx, "acct-a", "", report); err == nil {
		t.Fatal("empty route id: want an error, got nil")
	}
}

func TestGatewayHealthKeepsCandidatesAndAccountsIndependent(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	for _, r := range []struct {
		account, node string
		active        bool
	}{
		{"a", "primary", true}, {"a", "standby", false}, {"b", "primary", false},
	} {
		if err := s.RecordRouteBytes(ctx, r.account, "shared-route", RouteReport{GatewayID: r.node, ForwardingActive: r.active}); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := s.LatestByGateway(ctx, "a")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || !rows["primary"]["shared-route"].ForwardingActive || rows["standby"]["shared-route"].ForwardingActive {
		t.Fatalf("candidate/account health mixed: %+v", rows)
	}
	if rows["primary"]["shared-route"].ReportedAt.IsZero() {
		t.Fatal("missing report time")
	}
	if err := s.RecordRouteBytes(ctx, "a", "legacy-route", RouteReport{ForwardingActive: true}); err != nil {
		t.Fatal(err)
	}
	rows, err = s.LatestByGateway(ctx, "a")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows["primary"]) != 1 || len(rows["standby"]) != 1 {
		t.Fatalf("unattributed legacy report became gateway health: %+v", rows)
	}
}
