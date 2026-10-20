// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package tutorialmode

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

func TestDefaultsToEnabled(t *testing.T) {
	s := newTestStore(t)
	got, err := s.Get(WithAccount(context.Background(), "acct-a"))
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !got {
		t.Fatal("want guidance text enabled by default")
	}
}

func TestSetDisabledThenGet(t *testing.T) {
	s := newTestStore(t)
	ctx := WithAccount(context.Background(), "acct-a")
	if err := s.Set(ctx, false); err != nil {
		t.Fatalf("set: %v", err)
	}
	got, err := s.Get(ctx)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got {
		t.Fatal("want guidance text disabled after Set(false)")
	}
}

func TestSetIsAccountScoped(t *testing.T) {
	s := newTestStore(t)
	if err := s.Set(WithAccount(context.Background(), "acct-a"), false); err != nil {
		t.Fatalf("set: %v", err)
	}
	got, err := s.Get(WithAccount(context.Background(), "acct-b"))
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !got {
		t.Fatal("disabling one account must not disable another")
	}
}

func TestSetCanBeFlippedBackToDefault(t *testing.T) {
	s := newTestStore(t)
	ctx := WithAccount(context.Background(), "acct-a")
	if err := s.Set(ctx, false); err != nil {
		t.Fatalf("set false: %v", err)
	}
	if err := s.Set(ctx, true); err != nil {
		t.Fatalf("set true: %v", err)
	}
	got, err := s.Get(ctx)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !got {
		t.Fatal("want enabled after explicitly setting true again")
	}
}
