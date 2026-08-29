// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package bedrock_test

import (
	"bytes"
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

// enrolled is two nodes with distinguishable datapath keys. Coverage binds a
// handle to its keys (spec §6.1), so a fixture that reused one key set could
// not tell "covered" from "covered under a different key".
func enrolled() map[string]bedrock.PeerKeys {
	return map[string]bedrock.PeerKeys{
		"node-a": {KemPublicKey: bytes.Repeat([]byte{0xA1}, 1184), DhPublicKey: bytes.Repeat([]byte{0xA2}, 32)},
		"node-b": {KemPublicKey: bytes.Repeat([]byte{0xB1}, 1184), DhPublicKey: bytes.Repeat([]byte{0xB2}, 32)},
	}
}

// A nil state means no log, under which nothing is covered — so every enrolled
// node is about to be cut off and must be acknowledged by name.
func TestEnforcingRequiresExactacknowledgmentSet(t *testing.T) {
	store := newStore(t)
	ctx := context.Background()
	at := int64(1000)

	_, err := store.SetMode(ctx, "account-a", bedrock.ModeEnforcing, []string{"node-a"}, nil, enrolled(), at)
	require.ErrorIs(t, err, bedrock.ErracknowledgmentMismatch)

	configuration, err := store.SetMode(ctx, "account-a", bedrock.ModeEnforcing, []string{"node-b", "node-a"}, nil, enrolled(), at)
	require.NoError(t, err)
	require.Equal(t, bedrock.ModeEnforcing, configuration.Mode)

	_, err = store.SetMode(ctx, "account-a", bedrock.ModeEnforcing, []string{"node-a", "node-b", "stale-node"}, nil, enrolled(), at)
	require.True(t, errors.Is(err, bedrock.ErracknowledgmentMismatch))
}

// **The defect this replaced.** Coverage used to come from a table nothing ever
// wrote, so every node read as uncovered and enabling enforcement always
// demanded acknowledging the whole network — including nodes that were fully
// countersigned. A guard that always asks for everything is one an operator
// confirms without reading. Coverage now comes from the verified chain, so a
// covered node needs no acknowledgment at all.
func TestACoveredNodeNeedsNoacknowledgment(t *testing.T) {
	store := newStore(t)
	ctx := context.Background()
	at := int64(1000)
	keys := enrolled()

	state := &bedrock.State{
		Covered: map[string]bedrock.NodeCoverage{
			"node-a": {Handle: "node-a", KemPublicKey: keys["node-a"].KemPublicKey, DhPublicKey: keys["node-a"].DhPublicKey},
			"node-b": {Handle: "node-b", KemPublicKey: keys["node-b"].KemPublicKey, DhPublicKey: keys["node-b"].DhPublicKey},
		},
		Revoked: map[string]int64{},
	}

	// Everyone covered: an empty acknowledgment is correct and sufficient.
	configuration, err := store.SetMode(ctx, "account-a", bedrock.ModeEnforcing, nil, state, keys, at)
	require.NoError(t, err)
	require.Equal(t, bedrock.ModeEnforcing, configuration.Mode)

	// And acknowledging a node that is *not* about to be cut off is refused,
	// because a stale confirmation must not look valid.
	_, err = store.SetMode(ctx, "account-b", bedrock.ModeEnforcing, []string{"node-a"}, state, keys, at)
	require.ErrorIs(t, err, bedrock.ErracknowledgmentMismatch)
}

// A node whose keys the log does not cover is uncovered, even though its handle
// appears — the substitution spec §6.1 exists to catch.
func TestASubstitutedKeyCountsAsUncovered(t *testing.T) {
	keys := enrolled()
	state := &bedrock.State{
		Covered: map[string]bedrock.NodeCoverage{
			// node-a's handle, node-b's keys.
			"node-a": {Handle: "node-a", KemPublicKey: keys["node-b"].KemPublicKey, DhPublicKey: keys["node-b"].DhPublicKey},
		},
		Revoked: map[string]int64{},
	}
	require.Equal(t, []string{"node-a", "node-b"}, bedrock.UncoveredAt(state, keys, 1000))
}

func TestUncoveredWithNoLogIsEveryone(t *testing.T) {
	require.Equal(t, []string{"node-a", "node-b"}, bedrock.UncoveredAt(nil, enrolled(), 1000))
}
