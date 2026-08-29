// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package control

import (
	"context"
	"errors"
	"fmt"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	nbauth "github.com/netbirdio/netbird/management/server/auth"
	"github.com/netbirdio/netbird/shared/auth"
)

// OIDC registration (PLAN.md §4.2 step 2), and the half of Phase 3's exit
// criterion that reads "a node registers via OIDC against a self-hosted
// server".
//
// The interactive flow itself — device authorization or PKCE, browser, IdP —
// is the fork's and is unchanged. What is new is carrying its result over the
// post-quantum channel and binding it to a Karst node identity. By the time
// any of this runs, the node has already proved possession of its ML-DSA key;
// the token proves *who the operator is*, which is a different question with a
// different answer.

// TokenValidator is the slice of the fork's auth manager needed to turn an ID
// token into a user. Narrow for the same reason PeerLoginer is.
type TokenValidator interface {
	ValidateAndParseToken(ctx context.Context, value string) (auth.UserAuth, *jwtv5.Token, error)
	EnsureUserAccessByJWTGroups(ctx context.Context, userAuth auth.UserAuth, token *jwtv5.Token) (auth.UserAuth, error)
}

// UserProvisioner creates or finds the account a validated user belongs to.
type UserProvisioner interface {
	GetAccountIDFromUserAuth(ctx context.Context, userAuth auth.UserAuth) (string, string, error)
	SyncUserJWTGroups(ctx context.Context, userAuth auth.UserAuth) error
}

// TokenClaimer enforces single use.
type TokenClaimer interface {
	RegisterToken(ctx context.Context, token string, expiresAt time.Time) error
}

// OIDC bundles what LoginHandler needs to accept an ID token. A nil *OIDC
// means the server does not offer interactive registration, and a node
// presenting a token is refused rather than quietly falling back to its setup
// key.
type OIDC struct {
	Tokens   TokenValidator
	Accounts UserProvisioner
	// Claimer is optional. When absent, tokens are not single-use — which is
	// a real weakening, so it is logged once per use rather than silently
	// accepted.
	Claimer TokenClaimer

	// Retries works around IdP propagation: a token minted moments ago can be
	// rejected by a validator whose key or group cache has not caught up. The
	// fork retries three times at 200 ms, and that number is a measured
	// operational fact rather than a guess, so it is kept.
	Retries int
	Backoff time.Duration
}

const (
	defaultRetries = 3
	defaultBackoff = 200 * time.Millisecond
)

// authenticate turns an ID token into a user ID.
//
// `handle` is the *already authenticated* node handle. It is used only for log
// context: the node's identity comes from its ML-DSA signature, and nothing
// here may weaken or override that.
func (o *OIDC) authenticate(ctx context.Context, handle, token string) (string, error) {
	if o == nil || o.Tokens == nil || o.Accounts == nil {
		return "", status.Error(codes.Unimplemented, "this server does not accept OIDC registration")
	}

	retries := o.Retries
	if retries <= 0 {
		retries = defaultRetries
	}
	backoff := o.Backoff
	if backoff <= 0 {
		backoff = defaultBackoff
	}

	var (
		userAuth auth.UserAuth
		parsed   *jwtv5.Token
		err      error
	)
	for i := 0; i < retries; i++ {
		userAuth, parsed, err = o.Tokens.ValidateAndParseToken(ctx, token)
		if err == nil {
			break
		}
		if i < retries-1 {
			log.WithContext(ctx).Warnf(
				"karst: JWT validation failed for node %s (%v); retrying in case the IdP cache is stale",
				handle, err)
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return "", status.Error(codes.Canceled, "canceled while validating token")
			}
		}
	}
	if err != nil {
		// Deliberately terse to the caller. The detail is in the server log;
		// telling an unauthenticated caller *why* its token failed is a probe
		// oracle for token structure.
		return "", status.Error(codes.Unauthenticated, "invalid token")
	}

	if err := o.claim(ctx, handle, token, parsed); err != nil {
		return "", err
	}

	// A user seen for the first time is added to an existing account or given
	// a new one. This must happen before the group sync below, which needs the
	// account to exist.
	accountID, _, err := o.Accounts.GetAccountIDFromUserAuth(ctx, userAuth)
	if err != nil {
		return "", fmt.Errorf("resolve account: %w", err)
	}
	userAuth.AccountId = accountID

	userAuth, err = o.Tokens.EnsureUserAccessByJWTGroups(ctx, userAuth, parsed)
	if err != nil {
		// A user whose JWT groups do not grant access is authenticated but not
		// authorized. That is PermissionDenied, not Unauthenticated: the
		// distinction tells an operator whether to fix the login or the groups.
		return "", status.Error(codes.PermissionDenied, err.Error())
	}

	if err := o.Accounts.SyncUserJWTGroups(ctx, userAuth); err != nil {
		// Non-fatal, matching the fork: group membership is refreshed on the
		// next login, and refusing to register a node because a group sync
		// failed would turn an IdP hiccup into an outage.
		log.WithContext(ctx).Errorf("karst: failed to sync JWT groups for node %s: %v", handle, err)
	}

	if userAuth.UserId == "" {
		// Every downstream check keys on the user. An empty one would create a
		// peer owned by nobody, which no ACL can then describe.
		return "", status.Error(codes.Unauthenticated, "token carries no user identity")
	}
	return userAuth.UserId, nil
}

// claim enforces single use, so a captured token cannot enroll a second node.
func (o *OIDC) claim(ctx context.Context, handle, token string, parsed *jwtv5.Token) error {
	if o.Claimer == nil {
		log.WithContext(ctx).Warnf(
			"karst: no token claimer configured; the ID token used by node %s is replayable", handle)
		return nil
	}
	if parsed == nil {
		return status.Error(codes.Unauthenticated, "token could not be parsed")
	}
	exp, err := parsed.Claims.GetExpirationTime()
	if err != nil || exp == nil {
		// Without an expiry the claim store cannot age the token out, so it
		// would either grow without bound or forget it and allow a replay.
		return status.Error(codes.Unauthenticated, "token has no expiry")
	}

	err = o.Claimer.RegisterToken(ctx, token, exp.Time)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, nbauth.ErrTokenAlreadyUsed), errors.Is(err, nbauth.ErrTokenExpired):
		log.WithContext(ctx).Warnf("karst: %v for node %s", err, handle)
		return status.Error(codes.Unauthenticated, err.Error())
	default:
		// The claim store is unavailable. Failing closed here is deliberate:
		// proceeding would silently drop the single-use guarantee at exactly
		// the moment the component enforcing it is broken.
		return status.Error(codes.Unavailable, "cannot verify token has not been used")
	}
}
