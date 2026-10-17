// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package cplocation

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

func TestGetBeforeSetIsNotFound(t *testing.T) {
	s := newTestStore(t)
	_, err := s.Get(WithAccount(context.Background(), "acct-a"))
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}

func TestSetThenGet(t *testing.T) {
	s := newTestStore(t)
	ctx := WithAccount(context.Background(), "acct-a")
	if _, err := s.Set(ctx, 10, 20, "control room"); err != nil {
		t.Fatalf("set: %v", err)
	}
	got, err := s.Get(ctx)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Lat != 10 || got.Lon != 20 || got.Label != "control room" {
		t.Fatalf("got %+v, want lat=10 lon=20 label=control room", got)
	}
}

func TestSetRejectsOutOfRangeCoordinates(t *testing.T) {
	s := newTestStore(t)
	_, err := s.Set(WithAccount(context.Background(), "acct-a"), 1000, 0, "")
	if err == nil {
		t.Fatal("want an error for an out-of-range latitude")
	}
}

func TestSetIsAccountScoped(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.Set(WithAccount(context.Background(), "acct-a"), 1, 1, ""); err != nil {
		t.Fatalf("set under acct-a: %v", err)
	}
	_, err := s.Get(WithAccount(context.Background(), "acct-b"))
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("acct-b got %v, want ErrNotFound (acct-a's location must not leak)", err)
	}
}
