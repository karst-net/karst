// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package grouplocation

import (
	"context"
	"errors"
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

func TestSetThenGet(t *testing.T) {
	s := newTestStore(t)
	ctx := WithAccount(context.Background(), "acct-a")
	if _, err := s.Set(ctx, Entry{GroupID: "grp-1", Lat: 1, Lon: 2, Label: "edge"}); err != nil {
		t.Fatalf("set: %v", err)
	}
	got, err := s.Get(ctx, "grp-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Lat != 1 || got.Lon != 2 || got.Label != "edge" {
		t.Fatalf("got %+v, want lat=1 lon=2 label=edge", got)
	}
}

func TestSetTwiceReplaces(t *testing.T) {
	s := newTestStore(t)
	ctx := WithAccount(context.Background(), "acct-a")
	if _, err := s.Set(ctx, Entry{GroupID: "grp-1", Lat: 1, Lon: 1}); err != nil {
		t.Fatalf("first set: %v", err)
	}
	if _, err := s.Set(ctx, Entry{GroupID: "grp-1", Lat: 2, Lon: 2}); err != nil {
		t.Fatalf("second set: %v", err)
	}
	rows, err := s.List(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 1 || rows[0].Lat != 2 {
		t.Fatalf("got %+v, want exactly one row updated to lat=2", rows)
	}
}

func TestGetMissingIsNotFound(t *testing.T) {
	s := newTestStore(t)
	_, err := s.Get(WithAccount(context.Background(), "acct-a"), "nope")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}

func TestSetRejectsEmptyGroupID(t *testing.T) {
	s := newTestStore(t)
	_, err := s.Set(WithAccount(context.Background(), "acct-a"), Entry{Lat: 1, Lon: 1})
	if err == nil {
		t.Fatal("want an error for an empty group_id")
	}
}
