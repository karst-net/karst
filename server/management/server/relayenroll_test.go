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

func TestMintAndConsumeRelayEnrollKey(t *testing.T) {
	manager, _, err := createManager(t)
	require.NoError(t, err)
	account, err := manager.GetOrCreateAccountByUser(context.Background(), auth.UserAuth{UserId: "relay-enroll-user"})
	require.NoError(t, err)

	secret, err := manager.MintRelayEnrollKey(context.Background(), account.Id, "pool-1", time.Minute)
	require.NoError(t, err)
	require.NotEmpty(t, secret)

	accountID, keyID, err := manager.ConsumeRelayEnrollKey(context.Background(), secret)
	require.NoError(t, err)
	require.Equal(t, account.Id, accountID)
	require.NotEmpty(t, keyID)
}

func TestConsumeRelayEnrollKey_IsSingleUse(t *testing.T) {
	manager, _, err := createManager(t)
	require.NoError(t, err)
	account, err := manager.GetOrCreateAccountByUser(context.Background(), auth.UserAuth{UserId: "relay-enroll-user"})
	require.NoError(t, err)

	secret, err := manager.MintRelayEnrollKey(context.Background(), account.Id, "pool-1", time.Minute)
	require.NoError(t, err)

	_, _, err = manager.ConsumeRelayEnrollKey(context.Background(), secret)
	require.NoError(t, err)

	_, _, err = manager.ConsumeRelayEnrollKey(context.Background(), secret)
	require.Error(t, err, "a relay-enroll key must not be redeemable twice")
}

func TestConsumeRelayEnrollKey_RefusesAnUnknownOrExpiredSecret(t *testing.T) {
	manager, _, err := createManager(t)
	require.NoError(t, err)

	_, _, err = manager.ConsumeRelayEnrollKey(context.Background(), "NEVER-MINTED")
	require.Error(t, err)

	account, err := manager.GetOrCreateAccountByUser(context.Background(), auth.UserAuth{UserId: "relay-enroll-user"})
	require.NoError(t, err)
	secret, err := manager.MintRelayEnrollKey(context.Background(), account.Id, "", -time.Second)
	require.NoError(t, err, "a negative duration mints fine -- it just produces an already-expired key")
	_, _, err = manager.ConsumeRelayEnrollKey(context.Background(), secret)
	require.Error(t, err, "an expired relay-enroll key must be refused")
}

// The whole point of relayEnrollHashDomain: a relay-enroll key and an
// ordinary peer setup key share the same storage mechanism but must never
// be substitutable for each other.
func TestConsumeRelayEnrollKey_RejectsAnOrdinaryPeerSetupKeySecret(t *testing.T) {
	manager, _, err := createManager(t)
	require.NoError(t, err)
	account, err := manager.GetOrCreateAccountByUser(context.Background(), auth.UserAuth{UserId: "relay-enroll-user"})
	require.NoError(t, err)

	peerKey, err := manager.CreateSetupKey(context.Background(), account.Id, "an ordinary peer key",
		types.SetupKeyOneOff, time.Hour, nil, 1, "relay-enroll-user", false, false)
	require.NoError(t, err)
	require.NotEmpty(t, peerKey.Key)

	_, _, err = manager.ConsumeRelayEnrollKey(context.Background(), peerKey.Key)
	require.Error(t, err, "an ordinary peer setup key's plaintext must not redeem as a relay-enroll key")
}

func TestMintRelayEnrollKey_RequiresAnAccount(t *testing.T) {
	manager, _, err := createManager(t)
	require.NoError(t, err)

	_, err = manager.MintRelayEnrollKey(context.Background(), "", "", time.Minute)
	require.Error(t, err)
}
