// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package locationreg

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

func TestCreateRejectsOutOfRangeCoordinates(t *testing.T) {
	s := newTestStore(t)
	_, err := s.Create(WithAccount(context.Background(), "acct-a"), Entry{Lat: 91, Lon: 0})
	if err == nil {
		t.Fatal("want an error for an out-of-range latitude")
	}
}

func TestCreateListDelete(t *testing.T) {
	s := newTestStore(t)
	ctx := WithAccount(context.Background(), "acct-a")

	created, err := s.Create(ctx, Entry{Lat: 51.5072, Lon: -0.1276, Label: "London", Kind: "datacenter"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	rows, err := s.List(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 1 || rows[0].ID != created.ID {
		t.Fatalf("got %+v, want exactly the created row", rows)
	}

	if err := s.Delete(ctx, created.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	rows, err = s.List(ctx)
	if err != nil {
		t.Fatalf("list after delete: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("got %d rows after delete, want 0", len(rows))
	}
}

func TestCreateIsAccountScoped(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.Create(WithAccount(context.Background(), "acct-a"), Entry{Lat: 1, Lon: 1}); err != nil {
		t.Fatalf("create under acct-a: %v", err)
	}
	rows, err := s.List(WithAccount(context.Background(), "acct-b"))
	if err != nil {
		t.Fatalf("list under acct-b: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("acct-b sees %d rows from acct-a, want 0", len(rows))
	}
}

func TestDeleteOfIdenticalEntryUnderTwoAccountsIsIndependent(t *testing.T) {
	s := newTestStore(t)
	entry := Entry{Lat: 1, Lon: 1, Label: "same everywhere"}
	if _, err := s.Create(WithAccount(context.Background(), "acct-a"), entry); err != nil {
		t.Fatalf("create under acct-a: %v", err)
	}
	created, err := s.Create(WithAccount(context.Background(), "acct-b"), entry)
	if err != nil {
		t.Fatalf("create under acct-b: %v", err)
	}
	if err := s.Delete(WithAccount(context.Background(), "acct-b"), created.ID); err != nil {
		t.Fatalf("delete under acct-b: %v", err)
	}
	rows, err := s.List(WithAccount(context.Background(), "acct-a"))
	if err != nil {
		t.Fatalf("list under acct-a: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("acct-a's row was affected by acct-b's delete: got %d rows, want 1", len(rows))
	}
}

func TestDeleteOfMissingIDIsNotFound(t *testing.T) {
	s := newTestStore(t)
	err := s.Delete(WithAccount(context.Background(), "acct-a"), "does-not-exist")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}

func TestCreateOfIdenticalEntryTwiceIsExists(t *testing.T) {
	s := newTestStore(t)
	ctx := WithAccount(context.Background(), "acct-a")
	entry := Entry{Lat: 1, Lon: 1, Label: "dup"}
	if _, err := s.Create(ctx, entry); err != nil {
		t.Fatalf("first create: %v", err)
	}
	_, err := s.Create(ctx, entry)
	if !errors.Is(err, ErrExists) {
		t.Fatalf("got %v, want ErrExists", err)
	}
}
