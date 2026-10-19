// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package firstrun

import (
	"context"
	"testing"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// fakeAccount stands in for NetBird's own Account model -- only the table
// name and the id column matter to backfillExistingAccounts.
type fakeAccount struct {
	ID string `gorm:"primaryKey;column:id"`
}

func (fakeAccount) TableName() string { return "accounts" }

func newTestStore(t *testing.T, preexisting ...string) *Store {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("db: %v", err)
	}
	if err := db.AutoMigrate(&fakeAccount{}); err != nil {
		t.Fatalf("migrate fake accounts: %v", err)
	}
	for _, id := range preexisting {
		if err := db.Create(&fakeAccount{ID: id}).Error; err != nil {
			t.Fatalf("seed account %s: %v", id, err)
		}
	}
	store, err := NewStore(db)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	return store
}

func TestNewStoreToleratesNoAccountsTable(t *testing.T) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("db: %v", err)
	}
	// Deliberately no fakeAccount migration -- a lighter-weight fixture
	// that never created an "accounts" table at all must not fail to
	// construct this store.
	if _, err := NewStore(db); err != nil {
		t.Fatalf("store: %v", err)
	}
}

func TestNewAccountDefaultsToIncomplete(t *testing.T) {
	s := newTestStore(t)
	got, err := s.Get(WithAccount(context.Background(), "acct-new"))
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Completed {
		t.Fatal("want a brand-new account to default to incomplete")
	}
}

func TestPreexistingAccountIsBackfilledComplete(t *testing.T) {
	s := newTestStore(t, "acct-old")
	got, err := s.Get(WithAccount(context.Background(), "acct-old"))
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !got.Completed {
		t.Fatal("want a pre-existing account to be backfilled as completed")
	}
}

func TestCompleteThenGet(t *testing.T) {
	s := newTestStore(t)
	ctx := WithAccount(context.Background(), "acct-a")
	if _, err := s.Complete(ctx); err != nil {
		t.Fatalf("complete: %v", err)
	}
	got, err := s.Get(ctx)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !got.Completed || got.CompletedAt == nil {
		t.Fatalf("got %+v, want completed with a timestamp", got)
	}
}

func TestCompleteIsAccountScoped(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.Complete(WithAccount(context.Background(), "acct-a")); err != nil {
		t.Fatalf("complete: %v", err)
	}
	got, err := s.Get(WithAccount(context.Background(), "acct-b"))
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Completed {
		t.Fatal("completing one account must not complete another")
	}
}

func TestGetWithoutAccountScopeFails(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.Get(context.Background()); err != ErrNoAccount {
		t.Fatalf("got %v, want ErrNoAccount", err)
	}
}
