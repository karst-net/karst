// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package bedrock_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/netbirdio/netbird/management/internals/karst/bedrock"
)

func newStore(t *testing.T) *bedrock.Store {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:bedrock-%s?mode=memory&cache=shared", t.Name())), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	store, err := bedrock.NewStore(db)
	require.NoError(t, err)
	return store
}

func TestEnforcingRequiresExactAcknowledgementSet(t *testing.T) {
	store := newStore(t)
	_, err := store.SetMode(context.Background(), "account-a", bedrock.ModeEnforcing, []string{"node-a"}, []string{"node-a", "node-b"})
	require.ErrorIs(t, err, bedrock.ErrAcknowledgementMismatch)

	configuration, err := store.SetMode(context.Background(), "account-a", bedrock.ModeEnforcing, []string{"node-b", "node-a"}, []string{"node-a", "node-b"})
	require.NoError(t, err)
	require.Equal(t, bedrock.ModeEnforcing, configuration.Mode)

	_, err = store.SetMode(context.Background(), "account-a", bedrock.ModeEnforcing, []string{"node-a", "node-b", "stale-node"}, []string{"node-a", "node-b"})
	require.True(t, errors.Is(err, bedrock.ErrAcknowledgementMismatch))
}
