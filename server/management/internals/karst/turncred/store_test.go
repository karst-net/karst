// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package turncred_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/netbirdio/netbird/management/internals/karst/turncred"
)

func newStore(t *testing.T) *turncred.Store {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:turncred-store-%s?mode=memory&cache=shared", t.Name())), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	store, err := turncred.NewStore(db)
	require.NoError(t, err)
	return store
}

func TestCreateAndListRoundTrip(t *testing.T) {
	store := newStore(t)
	ctx := turncred.WithAccount(context.Background(), "account-a")

	created, err := store.Create(ctx, turncred.Entry{URI: "turn:turn.example.com:3478", Region: "us"})
	require.NoError(t, err)
	require.Equal(t, "turn:turn.example.com:3478", created.URI)
	require.Equal(t, "us", created.Region)
	require.NotEmpty(t, created.ID)

	list, err := store.List(ctx)
	require.NoError(t, err)
	require.Len(t, list, 1)
	require.Equal(t, created.ID, list[0].ID)

	entries, err := store.Entries(ctx)
	require.NoError(t, err)
	require.Equal(t, []turncred.Entry{{URI: "turn:turn.example.com:3478", Region: "us"}}, entries)
}

func TestCreateDefaultsAnEmptyRegion(t *testing.T) {
	store := newStore(t)
	ctx := turncred.WithAccount(context.Background(), "account-a")

	created, err := store.Create(ctx, turncred.Entry{URI: "turn:turn.example.com:3478"})
	require.NoError(t, err)
	require.Equal(t, turncred.DefaultRegion, created.Region)
}

func TestCreateRejectsAMalformedURI(t *testing.T) {
	store := newStore(t)
	ctx := turncred.WithAccount(context.Background(), "account-a")

	_, err := store.Create(ctx, turncred.Entry{URI: "not-a-turn-uri"})
	require.Error(t, err)
}

func TestDuplicateURIWithinAnAccountIsErrExists(t *testing.T) {
	store := newStore(t)
	ctx := turncred.WithAccount(context.Background(), "account-a")

	_, err := store.Create(ctx, turncred.Entry{URI: "turn:turn.example.com:3478", Region: "us"})
	require.NoError(t, err)

	_, err = store.Create(ctx, turncred.Entry{URI: "turn:turn.example.com:3478", Region: "eu"})
	require.ErrorIs(t, err, turncred.ErrExists)
}

func TestDeleteOfAMissingIDIsErrNotFound(t *testing.T) {
	store := newStore(t)
	ctx := turncred.WithAccount(context.Background(), "account-a")

	err := store.Delete(ctx, "does-not-exist")
	require.ErrorIs(t, err, turncred.ErrNotFound)
}

func TestDeleteRemovesAnEntry(t *testing.T) {
	store := newStore(t)
	ctx := turncred.WithAccount(context.Background(), "account-a")

	created, err := store.Create(ctx, turncred.Entry{URI: "turn:turn.example.com:3478", Region: "us"})
	require.NoError(t, err)

	require.NoError(t, store.Delete(ctx, created.ID))

	list, err := store.List(ctx)
	require.NoError(t, err)
	require.Empty(t, list)
}

// Two accounts must never see each other's entries: an account-scoped
// registry that leaked across accounts would hand one tenant's operator-typed
// TURN servers (and eventually its minted credentials) to another.
func TestAccountsAreIsolated(t *testing.T) {
	store := newStore(t)
	ctxA := turncred.WithAccount(context.Background(), "account-a")
	ctxB := turncred.WithAccount(context.Background(), "account-b")

	_, err := store.Create(ctxA, turncred.Entry{URI: "turn:a.example.com:3478", Region: "us"})
	require.NoError(t, err)
	_, err = store.Create(ctxB, turncred.Entry{URI: "turn:b.example.com:3478", Region: "eu"})
	require.NoError(t, err)

	listA, err := store.List(ctxA)
	require.NoError(t, err)
	require.Len(t, listA, 1)
	require.Equal(t, "turn:a.example.com:3478", listA[0].URI)

	listB, err := store.List(ctxB)
	require.NoError(t, err)
	require.Len(t, listB, 1)
	require.Equal(t, "turn:b.example.com:3478", listB[0].URI)

	// The same URI is independently creatable in a second account: identity is
	// scoped to (account, id), not global.
	_, err = store.Create(ctxB, turncred.Entry{URI: "turn:a.example.com:3478", Region: "eu"})
	require.NoError(t, err)

	// And deleting in one account must not touch the other's row with the same
	// derived id.
	require.NoError(t, store.Delete(ctxB, listA[0].ID))
	listA, err = store.List(ctxA)
	require.NoError(t, err)
	require.Len(t, listA, 1, "deleting account-b's entry removed account-a's")
}

func TestNoAccountInContextIsErrNoAccount(t *testing.T) {
	store := newStore(t)
	ctx := context.Background()

	_, err := store.Create(ctx, turncred.Entry{URI: "turn:a.example.com:3478"})
	require.ErrorIs(t, err, turncred.ErrNoAccount)

	_, err = store.List(ctx)
	require.ErrorIs(t, err, turncred.ErrNoAccount)

	err = store.Delete(ctx, "any-id")
	require.ErrorIs(t, err, turncred.ErrNoAccount)

	_, err = store.Entries(ctx)
	require.ErrorIs(t, err, turncred.ErrNoAccount)
}

// The regression guard for the relayreg.StoredRelay bug this package must not
// repeat: that type has no `json:` tags, so /relays actually serializes as
// capitalized Go field names over the wire rather than the lowercase
// `address`/`tls_server_name`/etc. the OpenAPI schema and console expect.
// StoredTurnServer must marshal with the lowercase keys the contract
// declares.
func TestStoredTurnServerMarshalsLowercaseFields(t *testing.T) {
	record := turncred.StoredTurnServer{
		AccountID: "account-a",
		ID:        "some-id",
		URI:       "turn:turn.example.com:3478",
		Region:    "us",
	}
	raw, err := json.Marshal(record)
	require.NoError(t, err)

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(raw, &decoded))

	require.Equal(t, "some-id", decoded["id"])
	require.Equal(t, "turn:turn.example.com:3478", decoded["uri"])
	require.Equal(t, "us", decoded["region"])
	// AccountID is json:"-": it must never appear on the wire, capitalized or
	// otherwise — it is server-internal scoping, not something a caller reads.
	_, hasAccountID := decoded["AccountID"]
	require.False(t, hasAccountID)
	_, hasAccountIDLower := decoded["account_id"]
	require.False(t, hasAccountIDLower)

	// And the specific bug: no capitalized Go field names on the wire.
	for _, wrong := range []string{"ID", "URI", "Region"} {
		_, present := decoded[wrong]
		require.Falsef(t, present, "response carries capitalized field %q, reproducing the relayreg.StoredRelay bug", wrong)
	}
}
