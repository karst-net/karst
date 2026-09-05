// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package control_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	pb "google.golang.org/protobuf/proto"

	"github.com/netbirdio/netbird/management/internals/karst/control"
	nbauth "github.com/netbirdio/netbird/management/server/auth"
	"github.com/netbirdio/netbird/shared/auth"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// ── fakes for the fork's auth surface ───────────────────────────────────────

type fakeTokens struct {
	mu        sync.Mutex
	userID    string
	failFirst int // fail this many times before succeeding, for the retry path
	calls     int
	validErr  error
	groupsErr error
	exp       time.Time
	noExp     bool // produce a token carrying no exp claim at all
}

func (f *fakeTokens) ValidateAndParseToken(_ context.Context, _ string) (auth.UserAuth, *jwtv5.Token, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.validErr != nil {
		return auth.UserAuth{}, nil, f.validErr
	}
	if f.calls <= f.failFirst {
		return auth.UserAuth{}, nil, errors.New("idp cache is stale")
	}
	claims := jwtv5.RegisteredClaims{}
	if !f.noExp {
		exp := f.exp
		if exp.IsZero() {
			exp = time.Now().Add(time.Hour)
		}
		claims.ExpiresAt = jwtv5.NewNumericDate(exp)
	}
	tok := jwtv5.NewWithClaims(jwtv5.SigningMethodHS256, claims)
	return auth.UserAuth{UserId: f.userID, AccountId: "acct"}, tok, nil
}

func (f *fakeTokens) EnsureUserAccessByJWTGroups(_ context.Context, ua auth.UserAuth, _ *jwtv5.Token) (auth.UserAuth, error) {
	if f.groupsErr != nil {
		return auth.UserAuth{}, f.groupsErr
	}
	return ua, nil
}

type fakeProvisioner struct {
	accountErr error
	syncErr    error
	synced     bool
}

func (f *fakeProvisioner) GetAccountIDFromUserAuth(_ context.Context, _ auth.UserAuth) (string, string, error) {
	if f.accountErr != nil {
		return "", "", f.accountErr
	}
	return "acct", "", nil
}

func (f *fakeProvisioner) SyncUserJWTGroups(_ context.Context, _ auth.UserAuth) error {
	f.synced = true
	return f.syncErr
}

type fakeClaimer struct {
	mu   sync.Mutex
	seen map[string]bool
	err  error
}

func (f *fakeClaimer) RegisterToken(_ context.Context, token string, _ time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	if f.seen == nil {
		f.seen = map[string]bool{}
	}
	if f.seen[token] {
		return nbauth.ErrTokenAlreadyUsed
	}
	f.seen[token] = true
	return nil
}

// ── harness ─────────────────────────────────────────────────────────────────

func oidcLoginRequest(t *testing.T, token, setupKey string) []byte {
	t.Helper()
	out, err := pb.Marshal(&proto.KarstLoginRequest{
		JwtToken:     token,
		SetupKey:     setupKey,
		Meta:         &proto.PeerSystemMeta{Hostname: "h", GoOS: "linux", NetbirdVersion: "0.0.0"},
		KemPublicKey: bytesRepeat(0xAB, 1568),
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return out
}

func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

// runOIDCLogin drives a full authenticated login carrying an ID token.
func runOIDCLogin(t *testing.T, o *control.OIDC, accounts control.PeerLoginer, token, setupKey string) error {
	t.Helper()
	svc, client, key, cleanup := newLoginFixtureWithOIDC(t, accounts, o)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	stream, err := client.Session(ctx)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	cl, err := control.Dial(stream, svc.Pins(), identityVerifier(), nil, signerFor(key), true)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	_, err = cl.Request(oidcLoginRequest(t, token, setupKey))
	return err
}

// ── tests ───────────────────────────────────────────────────────────────────

func TestOIDCLoginPassesTheUserToTheBusinessLayer(t *testing.T) {
	accounts := &fakeAccounts{}
	o := &control.OIDC{
		Tokens:   &fakeTokens{userID: "alice@example.com"},
		Accounts: &fakeProvisioner{},
		Claimer:  &fakeClaimer{},
	}
	if err := runOIDCLogin(t, o, accounts, "a-token", ""); err != nil {
		t.Fatalf("login: %v", err)
	}
	if accounts.gotLogin.UserID != "alice@example.com" {
		t.Fatalf("UserID: got %q want alice@example.com", accounts.gotLogin.UserID)
	}
	if accounts.gotLogin.SetupKey != "" {
		t.Fatal("a setup key was invented for an OIDC login")
	}
}

// A token that fails validation must be fatal. Falling through to the
// setup-key path would register the node with no user while the operator
// believes they authenticated as themselves.
func TestInvalidTokenDoesNotFallBackToTheSetupKey(t *testing.T) {
	accounts := &fakeAccounts{}
	o := &control.OIDC{
		Tokens:   &fakeTokens{validErr: errors.New("bad signature")},
		Accounts: &fakeProvisioner{},
		Claimer:  &fakeClaimer{},
		Retries:  1,
	}
	err := runOIDCLogin(t, o, accounts, "bad-token", "A-VALID-SETUP-KEY")
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("got %v want Unauthenticated", err)
	}
	if accounts.calls != 0 {
		t.Fatal("a login with an invalid token still reached the business layer")
	}
}

// A server with no OIDC configured must refuse a token rather than ignore it.
func TestTokenRefusedWhenOIDCIsNotConfigured(t *testing.T) {
	accounts := &fakeAccounts{}
	err := runOIDCLogin(t, nil, accounts, "a-token", "SETUP-KEY")
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("got %v want Unimplemented", err)
	}
	if accounts.calls != 0 {
		t.Fatal("the token was ignored and the login proceeded on the setup key")
	}
}

// The setup-key path still works when OIDC is configured but no token is sent.
func TestSetupKeyStillWorksAlongsideOIDC(t *testing.T) {
	accounts := &fakeAccounts{}
	o := &control.OIDC{
		Tokens:   &fakeTokens{userID: "alice@example.com"},
		Accounts: &fakeProvisioner{},
		Claimer:  &fakeClaimer{},
	}
	if err := runOIDCLogin(t, o, accounts, "", "SETUP-KEY"); err != nil {
		t.Fatalf("login: %v", err)
	}
	if accounts.gotLogin.UserID != "" {
		t.Fatal("a user was invented for a setup-key login")
	}
	if accounts.gotLogin.SetupKey != "SETUP-KEY" {
		t.Fatal("the setup key was not forwarded")
	}
}

// Single use: a captured token must not enroll a second node.
func TestTokenIsSingleUse(t *testing.T) {
	claimer := &fakeClaimer{}
	newOIDC := func() *control.OIDC {
		return &control.OIDC{
			Tokens:   &fakeTokens{userID: "alice@example.com"},
			Accounts: &fakeProvisioner{},
			Claimer:  claimer,
		}
	}
	if err := runOIDCLogin(t, newOIDC(), &fakeAccounts{}, "one-shot", ""); err != nil {
		t.Fatalf("first login: %v", err)
	}
	second := &fakeAccounts{}
	err := runOIDCLogin(t, newOIDC(), second, "one-shot", "")
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("a replayed token was accepted: %v", err)
	}
	if second.calls != 0 {
		t.Fatal("a replayed token reached the business layer")
	}
}

// If the claim store is broken, fail closed. Proceeding would drop the
// single-use guarantee at exactly the moment its enforcer is unavailable.
func TestClaimStoreFailureFailsClosed(t *testing.T) {
	accounts := &fakeAccounts{}
	o := &control.OIDC{
		Tokens:   &fakeTokens{userID: "alice@example.com"},
		Accounts: &fakeProvisioner{},
		Claimer:  &fakeClaimer{err: errors.New("database down")},
	}
	err := runOIDCLogin(t, o, accounts, "a-token", "")
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("got %v want Unavailable", err)
	}
	if accounts.calls != 0 {
		t.Fatal("a login proceeded while single use could not be verified")
	}
}

// A token with no expiry cannot be aged out of the claim store, so it would
// either grow without bound or be forgotten and become replayable.
func TestTokenWithoutExpiryRejected(t *testing.T) {
	claimer := &fakeClaimer{}
	accounts := &fakeAccounts{}
	o := &control.OIDC{
		Tokens:   &fakeTokens{userID: "alice@example.com", noExp: true},
		Accounts: &fakeProvisioner{},
		Claimer:  claimer,
	}
	if err := runOIDCLogin(t, o, accounts, "no-exp", ""); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("got %v want Unauthenticated", err)
	}
	if accounts.calls != 0 {
		t.Fatal("a token with no expiry reached the business layer")
	}
	if len(claimer.seen) != 0 {
		t.Fatal("a token with no expiry was registered in the claim store")
	}
}

// An already-expired token is rejected by the claim store, and that rejection
// must surface rather than being swallowed.
func TestExpiredTokenRejected(t *testing.T) {
	accounts := &fakeAccounts{}
	o := &control.OIDC{
		Tokens:   &fakeTokens{userID: "alice@example.com", exp: time.Now().Add(-time.Hour)},
		Accounts: &fakeProvisioner{},
		Claimer:  &fakeClaimer{err: nbauth.ErrTokenExpired},
	}
	if err := runOIDCLogin(t, o, accounts, "old-token", ""); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("got %v want Unauthenticated", err)
	}
	if accounts.calls != 0 {
		t.Fatal("an expired token reached the business layer")
	}
}

// Authenticated but not authorized is PermissionDenied, not Unauthenticated:
// the distinction tells an operator whether to fix the login or the groups.
func TestGroupRejectionIsPermissionDenied(t *testing.T) {
	accounts := &fakeAccounts{}
	o := &control.OIDC{
		Tokens: &fakeTokens{
			userID:    "alice@example.com",
			groupsErr: errors.New("user is in no permitted group"),
		},
		Accounts: &fakeProvisioner{},
		Claimer:  &fakeClaimer{},
	}
	err := runOIDCLogin(t, o, accounts, "a-token", "")
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("got %v want PermissionDenied", err)
	}
	if accounts.calls != 0 {
		t.Fatal("an unauthorized user reached the business layer")
	}
}

// Validation is retried, because a token minted moments ago can be rejected by
// a validator whose IdP cache has not caught up.
func TestValidationIsRetried(t *testing.T) {
	tokens := &fakeTokens{userID: "alice@example.com", failFirst: 2}
	o := &control.OIDC{
		Tokens:   tokens,
		Accounts: &fakeProvisioner{},
		Claimer:  &fakeClaimer{},
		Retries:  3,
		Backoff:  time.Millisecond,
	}
	if err := runOIDCLogin(t, o, &fakeAccounts{}, "slow-token", ""); err != nil {
		t.Fatalf("login: %v", err)
	}
	if tokens.calls != 3 {
		t.Fatalf("validator called %d times, want 3", tokens.calls)
	}
}

// A group-sync failure must not block registration: an IdP hiccup should not
// become an outage, and membership refreshes on the next login.
func TestGroupSyncFailureIsNotFatal(t *testing.T) {
	accounts := &fakeAccounts{}
	prov := &fakeProvisioner{syncErr: errors.New("idp unreachable")}
	o := &control.OIDC{
		Tokens:   &fakeTokens{userID: "alice@example.com"},
		Accounts: prov,
		Claimer:  &fakeClaimer{},
	}
	if err := runOIDCLogin(t, o, accounts, "a-token", ""); err != nil {
		t.Fatalf("a group-sync failure blocked registration: %v", err)
	}
	if !prov.synced {
		t.Fatal("group sync was never attempted")
	}
	if accounts.gotLogin.UserID != "alice@example.com" {
		t.Fatal("the user was lost when group sync failed")
	}
}

// A token that validates but carries no user would create a peer owned by
// nobody, which no ACL can then describe.
func TestTokenWithNoUserRejected(t *testing.T) {
	accounts := &fakeAccounts{}
	o := &control.OIDC{
		Tokens:   &fakeTokens{userID: ""},
		Accounts: &fakeProvisioner{},
		Claimer:  &fakeClaimer{},
	}
	if err := runOIDCLogin(t, o, accounts, "a-token", ""); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("got %v want Unauthenticated", err)
	}
	if accounts.calls != 0 {
		t.Fatal("a userless token reached the business layer")
	}
}

// An account-resolution failure must not be reported as an auth failure: the
// operator's credentials were fine and the server is at fault.
func TestAccountResolutionFailureIsNotAnAuthFailure(t *testing.T) {
	o := &control.OIDC{
		Tokens:   &fakeTokens{userID: "alice@example.com"},
		Accounts: &fakeProvisioner{accountErr: errors.New("store unavailable")},
		Claimer:  &fakeClaimer{},
	}
	err := runOIDCLogin(t, o, &fakeAccounts{}, "a-token", "")
	if err == nil {
		t.Fatal("an account failure was reported as success")
	}
	if c := status.Code(err); c == codes.Unauthenticated || c == codes.PermissionDenied {
		t.Fatalf("a server-side failure was reported as %v, which blames the operator", c)
	}
}
