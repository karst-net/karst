// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package policy_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/netbirdio/netbird/management/internals/karst/policy"
)

func TestVersionsAreAccountScoped(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:policy-scope-%s?mode=memory&cache=shared", t.Name())), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	store, err := policy.NewStore(db)
	require.NoError(t, err)
	document := `{"acls":[]}`
	first, err := store.Write(policy.WithAccount(context.Background(), "account-a"), document, "a", 0)
	require.NoError(t, err)
	require.Equal(t, uint64(1), first.Version)
	second, err := store.Write(policy.WithAccount(context.Background(), "account-b"), document, "b", 0)
	require.NoError(t, err)
	require.Equal(t, uint64(1), second.Version)
	version, err := store.Current(policy.WithAccount(context.Background(), "account-a"))
	require.NoError(t, err)
	require.Equal(t, "a", version.Author)
}
