// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package billing

import (
	"bytes"
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/karst/identity"
	"github.com/netbirdio/netbird/management/internals/karst/relayusage"
	"github.com/netbirdio/netbird/management/internals/karst/usage"
)

func TestAuthorizedRelayCreditReservationVerifiesAndBindsMappingAtomically(t *testing.T) {
	store := testBillingStore(t)
	ctx := context.Background()
	require.NoError(t, usage.Migrate(store.db))
	relays, err := relayusage.NewStore(store.db)
	require.NoError(t, err)

	accountID := "managed-account"
	accountCtx := WithAccount(ctx, accountID)
	now := time.Now().UTC()
	start := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	end := start.AddDate(0, 1, 0)
	schedule := testSchedule()
	require.NoError(t, store.PutSchedule(accountCtx, schedule))
	require.NoError(t, store.AssignSchedule(accountCtx, start, end, schedule.Version))
	_, err = store.SetRelaySpendingCap(accountCtx, start, end, 200, true, "account-owner")
	require.NoError(t, err)

	mapping, err := usage.PersistRelayMapping(ctx, store.db, "deployment-a", "aquifer-a", accountID)
	require.NoError(t, err)
	key, err := identity.FromSeed(bytes.Repeat([]byte{44}, identity.SeedSize))
	require.NoError(t, err)
	relayID, err := relays.AuthorizeProducer(ctx, key.Public(), "deployment-a")
	require.NoError(t, err)
	require.NoError(t, relays.AllowMapping(ctx, relayID, mapping.DeploymentID, mapping.Version))
	request := signedCreditRequestForBillingTest(t, key, relayID, mapping.Version, "0102030405060708090a0b0c0d0e0f10", "1112131415161718191a1b1c1d1e1f20", "3000000000")

	first, err := store.ReserveAuthorizedRelayCredits(ctx, relays, start, end, request)
	require.NoError(t, err)
	require.Equal(t, accountID, first.AccountID)
	require.Equal(t, "3000000000", first.GrantedBytes)
	second, err := store.ReserveAuthorizedRelayCredits(ctx, relays, start, end, request)
	require.NoError(t, err)
	require.Equal(t, first.GrantID, second.GrantID, "retry returns the original reservation")

	modified := signedCreditRequestForBillingTest(t, key, relayID, mapping.Version, request.Generation, request.RequestID, "3000000001")
	_, err = store.ReserveAuthorizedRelayCredits(ctx, relays, start, end, modified)
	require.ErrorIs(t, err, ErrCreditRequestConflict, "a request id cannot be reused to mint a larger grant")

	unapproved, err := usage.PersistRelayMapping(ctx, store.db, "deployment-a", "aquifer-other", "other-account")
	require.NoError(t, err)
	unauthorized := signedCreditRequestForBillingTest(t, key, relayID, unapproved.Version, "2122232425262728292a2b2c2d2e2f30", "3132333435363738393a3b3c3d3e3f40", "100")
	_, err = store.ReserveAuthorizedRelayCredits(ctx, relays, start, end, unauthorized)
	require.ErrorIs(t, err, relayusage.ErrMappingNotAllowed)
}

func signedCreditRequestForBillingTest(t *testing.T, key *identity.Key, relayID, mappingVersion, generation, requestID, requested string) relayusage.CreditRequest {
	t.Helper()
	request := relayusage.CreditRequest{RelayID: relayID, DeploymentID: "deployment-a", MappingVersion: mappingVersion,
		Generation: generation, RequestID: requestID, RequestedBytes: requested}
	input, err := request.SigningInput()
	require.NoError(t, err)
	signature, err := key.Sign([]byte(identity.RelayCreditRequestContext), input)
	require.NoError(t, err)
	request.Signature = base64.StdEncoding.EncodeToString(signature)
	return request
}
