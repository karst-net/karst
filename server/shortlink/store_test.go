// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package shortlink

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	dsn := "file:" + uuid.NewString() + "?mode=memory&cache=shared"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	store, err := NewStore(db)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	return store
}

func TestCreateGetList(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	if _, err := store.Create(ctx, "wiki", "https://wiki.example.internal"); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := store.Create(ctx, "dash", "https://dash.example.internal"); err != nil {
		t.Fatalf("create: %v", err)
	}

	link, err := store.Get(ctx, "wiki")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if link.TargetURL != "https://wiki.example.internal" {
		t.Fatalf("unexpected target: %s", link.TargetURL)
	}

	links, err := store.List(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(links) != 2 {
		t.Fatalf("expected 2 links, got %d", len(links))
	}
	if links[0].Keyword != "dash" || links[1].Keyword != "wiki" {
		t.Fatalf("expected alphabetical order, got %v", links)
	}
}

func TestCreateDuplicateFails(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	if _, err := store.Create(ctx, "wiki", "https://wiki.example.internal"); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := store.Create(ctx, "wiki", "https://other.example.internal"); err != ErrExists {
		t.Fatalf("expected ErrExists, got %v", err)
	}
}

func TestCreateValidation(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	cases := []struct {
		name    string
		keyword string
		target  string
		wantErr error
	}{
		{"empty keyword", "", "https://example.internal", ErrInvalidKeyword},
		{"reserved api", "api", "https://example.internal", ErrInvalidKeyword},
		{"reserved healthz", "healthz", "https://example.internal", ErrInvalidKeyword},
		{"relative url", "wiki", "/not-absolute", ErrInvalidTargetURL},
		{"bad scheme", "wiki", "ftp://example.internal/x", ErrInvalidTargetURL},
		{"no host", "wiki", "https://", ErrInvalidTargetURL},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := store.Create(ctx, tc.keyword, tc.target); err != tc.wantErr {
				t.Fatalf("expected %v, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestGetNotFound(t *testing.T) {
	store := newTestStore(t)
	if _, err := store.Get(context.Background(), "nope"); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestUpdate(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	if _, err := store.Create(ctx, "wiki", "https://old.example.internal"); err != nil {
		t.Fatalf("create: %v", err)
	}
	updated, err := store.Update(ctx, "wiki", "https://new.example.internal")
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.TargetURL != "https://new.example.internal" {
		t.Fatalf("unexpected target after update: %s", updated.TargetURL)
	}

	if _, err := store.Update(ctx, "missing", "https://example.internal"); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
	if _, err := store.Update(ctx, "wiki", "not-a-url"); err != ErrInvalidTargetURL {
		t.Fatalf("expected ErrInvalidTargetURL, got %v", err)
	}
}

func TestDelete(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	if _, err := store.Create(ctx, "wiki", "https://example.internal"); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := store.Delete(ctx, "wiki"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := store.Get(ctx, "wiki"); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound after delete, got %v", err)
	}
	if err := store.Delete(ctx, "wiki"); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound on double delete, got %v", err)
	}
}
