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
	if err := s.RecordRouteBytes(ctx, "acct-a", "route-1", 1000, 10); err != nil {
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
	if got.Bytes != 1000 || got.Packets != 10 {
		t.Fatalf("got %+v, want bytes=1000 packets=10", got)
	}
}

func TestRecordTwiceReplacesRatherThanAccumulates(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.RecordRouteBytes(ctx, "acct-a", "route-1", 1000, 10); err != nil {
		t.Fatalf("first record: %v", err)
	}
	// A real gateway reports a running total every tick, never a delta —
	// a later report's own count already includes everything the first one
	// did. The store must replace, not add, or every tick would double the
	// true figure.
	if err := s.RecordRouteBytes(ctx, "acct-a", "route-1", 1500, 15); err != nil {
		t.Fatalf("second record: %v", err)
	}
	byRoute, err := s.LatestByRoute(ctx, "acct-a")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got := byRoute["route-1"]; got.Bytes != 1500 || got.Packets != 15 {
		t.Fatalf("got %+v, want the replaced bytes=1500 packets=15, not an accumulation", got)
	}
}

func TestLatestByRouteIsScopedToOneAccount(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.RecordRouteBytes(ctx, "acct-a", "route-1", 1000, 10); err != nil {
		t.Fatalf("record acct-a: %v", err)
	}
	if err := s.RecordRouteBytes(ctx, "acct-b", "route-1", 2000, 20); err != nil {
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
	if err := s.RecordRouteBytes(ctx, "", "route-1", 1000, 10); err == nil {
		t.Fatal("empty account id: want an error, got nil")
	}
	if err := s.RecordRouteBytes(ctx, "acct-a", "", 1000, 10); err == nil {
		t.Fatal("empty route id: want an error, got nil")
	}
}
