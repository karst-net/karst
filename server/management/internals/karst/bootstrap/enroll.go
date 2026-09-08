// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/auth"
)

// The bootstrap key closes the one gap in the deployment walkthrough that has
// no offline path.
//
// A node registers with a setup key. A setup key is issued by the management
// API, which is behind the authorization middleware, which needs a JWT, which
// needs an identity provider. So a self-hoster who has not yet wired an IdP
// into `management.json` cannot enroll a single node — not because anything is
// broken, but because the only door is one they cannot open yet. docs/
// GETTING-STARTED.md §8 says so in as many words, and until this existed the
// answer was to configure an IdP first or write into the store by hand.
//
// This is deliberately *not* a second authentication path. It mints one
// ordinary setup key, once, at startup, against an ordinary account, and
// writes it to a file only root can read. Everything downstream — LoginPeer,
// the usage limit, revocation from the console — is the path a key from the
// API takes, because it *is* a key from the same constructor.
//
// # Why the account comes from the login path rather than a direct create
//
// `GetAccountIDFromUserAuth` is what a real JWT resolves through, single-
// account-mode overrides included. Going through it means the bootstrap user
// lands in the same account the first IdP user will land in later, so the
// nodes enrolled before authentication existed are visible in the console
// after it does. Calling `GetOrCreateAccountByUser` directly would skip the
// domain overrides and strand those nodes in an account nobody can reach —
// a deployment that appears to have lost every node it enrolled.
const (
	// BootstrapUserID owns the account the key is minted against.
	//
	// Stable, and not an email address: it must never collide with a subject
	// an identity provider might later issue, or an IdP user would inherit
	// this user's row.
	BootstrapUserID = "karst-bootstrap"

	// BootstrapKeyName is what the key is called in the console, chosen to
	// read as an instruction to whoever finds it there.
	BootstrapKeyName = "bootstrap (created without an identity provider)"
)

// BootstrapKeyOptions are the properties of the minted key.
//
// The zero value issues at most ten enrollments over one hour. Renewal
// invalidates previous bootstrap credentials, even when their file was lost.
type BootstrapKeyOptions struct {
	UserID     string
	Name       string
	ExpiresIn  time.Duration
	UsageLimit int
}

// MintBootstrapKey creates a bounded bootstrap credential and atomically
// revokes previous credentials with the same bootstrap name.
func MintBootstrapKey(ctx context.Context, accounts account.Manager, opts BootstrapKeyOptions) (string, error) {
	if accounts == nil {
		return "", errors.New("karst: no account manager")
	}
	userID := opts.UserID
	if userID == "" {
		userID = BootstrapUserID
	}
	name := opts.Name
	if name == "" {
		name = BootstrapKeyName
	}

	// Domain and DomainCategory are left empty on purpose. In single-account
	// mode — the fork's default — they are overwritten with the deployment's
	// domain before the account is resolved, which is the behaviour that puts
	// this user and the first IdP user in one account. With single-account
	// mode off, the empty domain routes to a per-user account instead, which
	// is the same thing that would happen to any user of a multi-account
	// deployment and so is the right answer there too.
	accountID, resolvedUser, err := accounts.GetAccountIDFromUserAuth(ctx, auth.UserAuth{UserId: userID})
	if err != nil {
		return "", fmt.Errorf("karst: resolve the bootstrap account: %w", err)
	}

	expiry, limit := opts.ExpiresIn, opts.UsageLimit
	if expiry == 0 {
		expiry = time.Hour
	}
	if limit == 0 {
		limit = 10
	}
	issuer, ok := accounts.(interface {
		RotateBootstrapKey(context.Context, string, string, string, time.Duration, int) (*types.SetupKey, error)
	})
	if !ok {
		return "", errors.New("karst: atomic bootstrap key rotation is unavailable")
	}
	key, err := issuer.RotateBootstrapKey(ctx, accountID, resolvedUser, name, expiry, limit)
	if err != nil {
		return "", fmt.Errorf("karst: create the bootstrap setup key: %w", err)
	}
	// CreateSetupKey puts the plaintext back on the returned struct and only
	// there; the row it saved holds the hash. An empty value here would mean
	// writing an unusable file and reporting success, so it is checked rather
	// than assumed.
	if key.Key == "" {
		return "", errors.New("karst: the bootstrap setup key came back empty")
	}

	log.Warnf("karst: minted a bootstrap enrollment key in account %s. It exists because "+
		"no identity provider is configured and a node cannot enroll without one; "+
		"revoke it from the console (Auth keys) once authentication works.", accountID)
	return key.Key, nil
}
