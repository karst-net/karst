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

// relayEnrollHashDomain domain-separates a relay-enroll key's stored hash
// from an ordinary peer setup key's — ADR-0045 §6: "via a short-lived,
// single-use enrollment token minted for that specific instance," following
// ADR-0016's capability-scoped pattern (a distinct cryptographic context,
// not a permission bit) rather than inventing a new storage mechanism.
// Both credential kinds share the [types.SetupKey] table, revocation and
// console visibility NetBird's own peer-enrollment setup keys already use
// (ADR-0045 §6 says to reuse ADR-0016's model, not invent one), but a
// relay-enroll secret presented to the ordinary peer-enrollment path
// (`AddPeer`) hashes to something that row's own hash was never stored
// under, and vice versa — one can never be substituted for the other.
const relayEnrollHashDomain = "karst-relay-enroll-v1:"

// defaultRelayEnrollKeyExpiry bounds how long a minted relay-enroll key
// stays usable if the caller does not say otherwise. Short on purpose: the
// window between the scaler creating an instance and that instance calling
// back to redeem its token is a boot sequence, not an operator workflow —
// nothing should still be waiting on one of these after a few minutes.
const defaultRelayEnrollKeyExpiry = 10 * time.Minute

func hashRelayEnrollSecret(secret string) string {
	hashed := sha256.Sum256([]byte(relayEnrollHashDomain + strings.ToUpper(secret)))
	return b64.StdEncoding.EncodeToString(hashed[:])
}

// MintRelayEnrollKey issues a short-lived, single-use credential that lets
// one not-yet-registered relay complete its own roster admission through
// [DefaultAccountManager.ConsumeRelayEnrollKey] — see this file's own
// package doc and ADR-0045 §6. The caller (the `/relays/enroll-tokens` HTTP
// handler) has already checked that whoever is asking holds a
// Scaler-role-scoped credential; this method does not re-check that, the
// same division of responsibility [MintBootstrapKey] uses.
//
// # Errors
// If accountID is empty, or the key cannot be persisted.
func (am *DefaultAccountManager) MintRelayEnrollKey(ctx context.Context, accountID, poolID string, expiresIn time.Duration) (string, error) {
	if accountID == "" {
		return "", status.Errorf(status.InvalidArgument, "relay enroll key needs an account")
	}
	if expiresIn == 0 {
		expiresIn = defaultRelayEnrollKeyExpiry
	}
	name := "relay enroll"
	if poolID != "" {
		name = fmt.Sprintf("relay enroll: pool %s", poolID)
	}
	secret := strings.ToUpper(uuid.New().String())
	key := &types.SetupKey{
		Id:         xid.New().String(),
		AccountID:  accountID,
		Key:        hashRelayEnrollSecret(secret),
		KeySecret:  types.HiddenKey(secret, 4),
		Name:       name,
		Type:       types.SetupKeyOneOff,
		CreatedAt:  time.Now().UTC(),
		ExpiresAt:  util.ToPtr(time.Now().UTC().Add(expiresIn)),
		UpdatedAt:  time.Now().UTC(),
		UsageLimit: 1,
	}
	if err := am.Store.SaveSetupKey(ctx, key); err != nil {
		return "", fmt.Errorf("karst: saving relay enroll key: %w", err)
	}
	am.StoreEvent(ctx, "", key.Id, accountID, activity.SetupKeyCreated, key.EventMeta())
	return secret, nil
}

// ConsumeRelayEnrollKey validates and single-uses a relay-enroll secret,
// returning the account and the spent key's id (for the caller's own audit
// record) if it authorizes a new relay to enroll. Spending happens inside
// one transaction so a key can never authorize two relays even under
// concurrent requests — the same "only this many existing redemptions" race
// [types.SetupKey.IsOverUsed] exists to close for ordinary setup keys.
//
// # Errors
// If the secret does not match any key, or the matched key is revoked,
// expired, or already used.
func (am *DefaultAccountManager) ConsumeRelayEnrollKey(ctx context.Context, secret string) (accountID, keyID string, err error) {
	encoded := hashRelayEnrollSecret(secret)
	txErr := am.Store.ExecuteInTransaction(ctx, func(tx store.Store) error {
		key, err := tx.GetSetupKeyBySecret(ctx, store.LockingStrengthUpdate, encoded)
		if err != nil {
			return status.Errorf(status.PermissionDenied, "relay enroll key is invalid")
		}
		if !key.IsValid() {
			return status.Errorf(status.PermissionDenied, "relay enroll key is invalid")
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
