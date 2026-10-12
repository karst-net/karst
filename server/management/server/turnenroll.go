// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package server

import (
	"context"
	"crypto/sha256"
	b64 "encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rs/xid"

	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/management/server/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

// turnEnrollHashDomain domain-separates a turn-enroll key's stored hash
// from both an ordinary peer setup key's and a relay-enroll key's
// (relayenroll.go's own relayEnrollHashDomain) — the same ADR-0016
// capability-scoped pattern, reusing [types.SetupKey]'s table, revocation,
// and console visibility rather than inventing a second storage mechanism.
// A turn-enroll secret presented to either of those other redemption paths
// hashes to something neither path ever stored a key under, and vice versa.
const turnEnrollHashDomain = "karst-turn-enroll-v1:"

// defaultTurnEnrollKeyExpiry mirrors relayenroll.go's own
// defaultRelayEnrollKeyExpiry and its reasoning exactly: the window between
// provisioning a new TURN server and that instance calling back to redeem
// its token is a boot sequence, not an operator workflow.
const defaultTurnEnrollKeyExpiry = 10 * time.Minute

func hashTurnEnrollSecret(secret string) string {
	hashed := sha256.Sum256([]byte(turnEnrollHashDomain + strings.ToUpper(secret)))
	return b64.StdEncoding.EncodeToString(hashed[:])
}

// MintTurnEnrollKey issues a short-lived, single-use credential that lets
// one not-yet-registered TURN server complete its own registration through
// [DefaultAccountManager.ConsumeTurnEnrollKey] — the TURN counterpart of
// MintRelayEnrollKey (relayenroll.go), ADR-0045 §7b. Unlike a relay, a TURN
// server has no pinned identity key to pin into the registry (RFC 8656
// authenticates the *client* to the server, never the reverse — see
// turncred's own package doc), so there is no poolID or identity material
// this token needs to carry; the token itself is the entire authorization.
// The caller (the `/turn/enroll-tokens` HTTP handler) has already checked
// that whoever is asking holds a Scaler-role-scoped credential; this method
// does not re-check that, the same division of responsibility
// MintRelayEnrollKey uses.
//
// # Errors
// If accountID is empty, or the key cannot be persisted.
func (am *DefaultAccountManager) MintTurnEnrollKey(ctx context.Context, accountID string, expiresIn time.Duration) (string, error) {
	if accountID == "" {
		return "", status.Errorf(status.InvalidArgument, "turn enroll key needs an account")
	}
	if expiresIn == 0 {
		expiresIn = defaultTurnEnrollKeyExpiry
	}
	secret := strings.ToUpper(uuid.New().String())
	key := &types.SetupKey{
		Id:         xid.New().String(),
		AccountID:  accountID,
		Key:        hashTurnEnrollSecret(secret),
		KeySecret:  types.HiddenKey(secret, 4),
		Name:       "turn enroll",
		Type:       types.SetupKeyOneOff,
		CreatedAt:  time.Now().UTC(),
		ExpiresAt:  util.ToPtr(time.Now().UTC().Add(expiresIn)),
		UpdatedAt:  time.Now().UTC(),
		UsageLimit: 1,
	}
	if err := am.Store.SaveSetupKey(ctx, key); err != nil {
		return "", fmt.Errorf("karst: saving turn enroll key: %w", err)
	}
	am.StoreEvent(ctx, "", key.Id, accountID, activity.SetupKeyCreated, key.EventMeta())
	return secret, nil
}

// ConsumeTurnEnrollKey validates and single-uses a turn-enroll secret,
// returning the account and the spent key's id (for the caller's own audit
// record) if it authorizes a new TURN server to register. Spending happens
// inside one transaction so a key can never authorize two servers even
// under concurrent requests — mirrors ConsumeRelayEnrollKey exactly.
//
// # Errors
// If the secret does not match any key, or the matched key is revoked,
// expired, or already used.
func (am *DefaultAccountManager) ConsumeTurnEnrollKey(ctx context.Context, secret string) (accountID, keyID string, err error) {
	encoded := hashTurnEnrollSecret(secret)
	txErr := am.Store.ExecuteInTransaction(ctx, func(tx store.Store) error {
		key, err := tx.GetSetupKeyBySecret(ctx, store.LockingStrengthUpdate, encoded)
		if err != nil {
			return status.Errorf(status.PermissionDenied, "turn enroll key is invalid")
		}
		if !key.IsValid() {
			return status.Errorf(status.PermissionDenied, "turn enroll key is invalid")
		}
		accountID = key.AccountID
		keyID = key.Id
		return tx.SaveSetupKey(ctx, key.IncrementUsage())
	})
	if txErr != nil {
		return "", "", txErr
	}
	return accountID, keyID, nil
}
