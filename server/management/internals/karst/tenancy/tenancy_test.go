// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package tenancy_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/netbirdio/netbird/management/internals/karst/tenancy"
)

func newStore(t *testing.T) *tenancy.Store {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:tenancy-store-%s?mode=memory&cache=shared", t.Name())), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	store, err := tenancy.NewStore(db)
	require.NoError(t, err)
	return store
}

func TestNoGrantMeansNoAccess(t *testing.T) {
	store := newStore(t)
	ok, err := store.HasAccess(context.Background(), "user-a", "account-b")
	require.NoError(t, err)
	require.False(t, ok)
}

func TestReconcileGrantsAccess(t *testing.T) {
	store := newStore(t)
	ctx := context.Background()

	require.NoError(t, store.Reconcile(ctx, []tenancy.Grant{{UserID: "user-a", AccountID: "account-b"}}))

	ok, err := store.HasAccess(ctx, "user-a", "account-b")
	require.NoError(t, err)
	require.True(t, ok)

	// A grant is specific to the exact pair -- it does not leak to another
	// account or another user.
	ok, err = store.HasAccess(ctx, "user-a", "account-c")
	require.NoError(t, err)
	require.False(t, ok)
	ok, err = store.HasAccess(ctx, "user-z", "account-b")
	require.NoError(t, err)
	require.False(t, ok)

	accessible, err := store.AccessibleAccounts(ctx, "user-a")
	require.NoError(t, err)
	require.Equal(t, []string{"account-b"}, accessible)
}

func TestReconcileIsDeclarativeNotAdditive(t *testing.T) {
	store := newStore(t)
	ctx := context.Background()

	require.NoError(t, store.Reconcile(ctx, []tenancy.Grant{
		{UserID: "user-a", AccountID: "account-b"},
		{UserID: "user-a", AccountID: "account-c"},
	}))
	accessible, err := store.AccessibleAccounts(ctx, "user-a")
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"account-b", "account-c"}, accessible)

	// A second reconcile with a smaller set revokes what dropped out.
	require.NoError(t, store.Reconcile(ctx, []tenancy.Grant{
		{UserID: "user-a", AccountID: "account-c"},
	}))
	accessible, err = store.AccessibleAccounts(ctx, "user-a")
	require.NoError(t, err)
	require.Equal(t, []string{"account-c"}, accessible)

	ok, err := store.HasAccess(ctx, "user-a", "account-b")
	require.NoError(t, err)
	require.False(t, ok)
}

func TestParseRejectsUnknownFields(t *testing.T) {
	_, err := tenancy.Parse([]byte(`{"grants":[{"user_id":"u","account_id":"a","oops":true}]}`))
	require.Error(t, err)
}

func TestParseRequiresBothIDs(t *testing.T) {
	_, err := tenancy.Parse([]byte(`{"grants":[{"user_id":"u"}]}`))
	require.Error(t, err)
}

func TestParseValidDocument(t *testing.T) {
	grants, err := tenancy.Parse([]byte(`{"grants":[{"user_id":"u","account_id":"a"}]}`))
	require.NoError(t, err)
	require.Equal(t, []tenancy.Grant{{UserID: "u", AccountID: "a"}}, grants)
}
