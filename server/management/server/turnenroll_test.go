// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package server

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/auth"
)

func TestMintAndConsumeTurnEnrollKey(t *testing.T) {
	manager, _, err := createManager(t)
	require.NoError(t, err)
	account, err := manager.GetOrCreateAccountByUser(context.Background(), auth.UserAuth{UserId: "turn-enroll-user"})
	require.NoError(t, err)

	secret, err := manager.MintTurnEnrollKey(context.Background(), account.Id, time.Minute)
	require.NoError(t, err)
	require.NotEmpty(t, secret)

	accountID, keyID, err := manager.ConsumeTurnEnrollKey(context.Background(), secret)
	require.NoError(t, err)
	require.Equal(t, account.Id, accountID)
	require.NotEmpty(t, keyID)
}

func TestConsumeTurnEnrollKey_IsSingleUse(t *testing.T) {
	manager, _, err := createManager(t)
	require.NoError(t, err)
	account, err := manager.GetOrCreateAccountByUser(context.Background(), auth.UserAuth{UserId: "turn-enroll-user"})
	require.NoError(t, err)

	secret, err := manager.MintTurnEnrollKey(context.Background(), account.Id, time.Minute)
	require.NoError(t, err)

	_, _, err = manager.ConsumeTurnEnrollKey(context.Background(), secret)
	require.NoError(t, err)

	_, _, err = manager.ConsumeTurnEnrollKey(context.Background(), secret)
	require.Error(t, err, "a turn-enroll key must not be redeemable twice")
}

func TestConsumeTurnEnrollKey_RefusesAnUnknownOrExpiredSecret(t *testing.T) {
	manager, _, err := createManager(t)
	require.NoError(t, err)

	_, _, err = manager.ConsumeTurnEnrollKey(context.Background(), "NEVER-MINTED")
	require.Error(t, err)

	account, err := manager.GetOrCreateAccountByUser(context.Background(), auth.UserAuth{UserId: "turn-enroll-user"})
	require.NoError(t, err)
	secret, err := manager.MintTurnEnrollKey(context.Background(), account.Id, -time.Second)
	require.NoError(t, err, "a negative duration mints fine -- it just produces an already-expired key")
	_, _, err = manager.ConsumeTurnEnrollKey(context.Background(), secret)
	require.Error(t, err, "an expired turn-enroll key must be refused")
}

// The whole point of turnEnrollHashDomain: a turn-enroll key and an
// ordinary peer setup key share the same storage mechanism but must never
// be substitutable for each other.
func TestConsumeTurnEnrollKey_RejectsAnOrdinaryPeerSetupKeySecret(t *testing.T) {
	manager, _, err := createManager(t)
	require.NoError(t, err)
	account, err := manager.GetOrCreateAccountByUser(context.Background(), auth.UserAuth{UserId: "turn-enroll-user"})
	require.NoError(t, err)

	peerKey, err := manager.CreateSetupKey(context.Background(), account.Id, "an ordinary peer key",
		types.SetupKeyOneOff, time.Hour, nil, 1, "turn-enroll-user", false, false)
	require.NoError(t, err)
	require.NotEmpty(t, peerKey.Key)

	_, _, err = manager.ConsumeTurnEnrollKey(context.Background(), peerKey.Key)
	require.Error(t, err, "an ordinary peer setup key's plaintext must not redeem as a turn-enroll key")
}

// The same domain separation, checked against the *other* enrollment
// credential kind this system now has: a relay-enroll secret and a
// turn-enroll secret must never be substitutable for each other either,
// even though both are minted by the same Scaler role and stored in the
// same types.SetupKey table.
func TestConsumeTurnEnrollKey_RejectsARelayEnrollKeySecret(t *testing.T) {
	manager, _, err := createManager(t)
	require.NoError(t, err)
	account, err := manager.GetOrCreateAccountByUser(context.Background(), auth.UserAuth{UserId: "turn-enroll-user"})
	require.NoError(t, err)

	relaySecret, err := manager.MintRelayEnrollKey(context.Background(), account.Id, "pool-1", time.Minute)
	require.NoError(t, err)

	_, _, err = manager.ConsumeTurnEnrollKey(context.Background(), relaySecret)
	require.Error(t, err, "a relay-enroll secret must not redeem as a turn-enroll key")

	turnSecret, err := manager.MintTurnEnrollKey(context.Background(), account.Id, time.Minute)
	require.NoError(t, err)

	_, _, err = manager.ConsumeRelayEnrollKey(context.Background(), turnSecret)
	require.Error(t, err, "a turn-enroll secret must not redeem as a relay-enroll key")
}

func TestMintTurnEnrollKey_RequiresAnAccount(t *testing.T) {
	manager, _, err := createManager(t)
	require.NoError(t, err)

	_, err = manager.MintTurnEnrollKey(context.Background(), "", time.Minute)
	require.Error(t, err)
}
