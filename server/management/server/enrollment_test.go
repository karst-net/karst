// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.
package server

import (
	"context"
	"crypto/mlkem"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"
	pb "google.golang.org/protobuf/proto"
	"gorm.io/gorm"

	karstapi "github.com/netbirdio/netbird/management/internals/karst/api"
	karstcontrol "github.com/netbirdio/netbird/management/internals/karst/control"
	karstidentity "github.com/netbirdio/netbird/management/internals/karst/identity"
	karstnode "github.com/netbirdio/netbird/management/internals/karst/node"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/auth"
	"github.com/netbirdio/netbird/shared/management/proto"
)

func enrollmentFixture(t *testing.T) (*DefaultAccountManager, *types.User) {
	t.Helper()
	am, _, err := createManager(t)
	require.NoError(t, err)
	ctx := context.Background()
	account := newAccountWithId(ctx, "enrollment-account", "owner", "", "", "", false)
	require.NoError(t, am.Store.SaveAccount(ctx, account))
	user := types.NewRegularUser("member", "", "")
	user.AccountID = account.Id
	require.NoError(t, am.Store.SaveUser(ctx, user))
	return am, user
}

func storedEnrollment(t *testing.T, am *DefaultAccountManager, secret string) *types.SetupKey {
	t.Helper()
	sum := sha256.Sum256([]byte(strings.ToUpper(secret)))
	key, err := am.Store.GetSetupKeyBySecret(context.Background(), store.LockingStrengthNone, base64.StdEncoding.EncodeToString(sum[:]))
	require.NoError(t, err)
	return key
}

func enrollPeer(am *DefaultAccountManager, secret, identity string) (*nbpeer.Peer, error) {
	peer, _, _, _, err := am.LoginPeer(context.Background(), types.PeerLogin{WireGuardPubKey: identity, SetupKey: secret, Meta: nbpeer.PeerSystemMeta{Hostname: identity, GoOS: "linux"}})
	return peer, err
}

func TestEnrollmentMemberAndSingleUse(t *testing.T) {
	am, user := enrollmentFixture(t)
	ctx := context.Background()
	_, err := am.CreateSetupKey(ctx, user.AccountID, "admin key", types.SetupKeyReusable, time.Hour, nil, 0, user.Id, false, false)
	require.Error(t, err, "self-enrollment must not grant administrative key permissions")
	key, err := am.CreateEnrollmentKey(ctx, user.AccountID, user.Id)
	require.NoError(t, err)
	require.Equal(t, user.Id, storedEnrollment(t, am, key.Key).OwnerUserID)
	first, err := enrollPeer(am, key.Key, "first-device")
	require.NoError(t, err)
	require.Equal(t, user.Id, first.UserID)
	require.Equal(t, 1, storedEnrollment(t, am, key.Key).UsedTimes)
	_, err = enrollPeer(am, key.Key, "second-device")
	require.Error(t, err)
	// A lost response/cache does not need a fresh grant or create another peer.
	again, err := enrollPeer(am, "", "first-device")
	require.NoError(t, err)
	require.Equal(t, first.ID, again.ID)
}

func TestEnrollmentRejectsInvalidOrIneligible(t *testing.T) {
	for _, mode := range []string{"expired", "revoked", "blocked", "pending", "deleted", "wrong-account"} {
		t.Run(mode, func(t *testing.T) {
			am, user := enrollmentFixture(t)
			ctx := context.Background()
			key, err := am.CreateEnrollmentKey(ctx, user.AccountID, user.Id)
			require.NoError(t, err)
			stored := storedEnrollment(t, am, key.Key)
			switch mode {
			case "expired":
				at := time.Now().Add(-time.Minute)
				stored.ExpiresAt = &at
			case "revoked":
				stored.Revoked = true
			case "blocked":
				user.Blocked = true
			case "pending":
				user.PendingApproval = true
			case "wrong-account":
				user.AccountID = "another-account"
			case "deleted":
				require.NoError(t, am.Store.DeleteUser(ctx, user.AccountID, user.Id))
			}
			require.NoError(t, am.Store.SaveSetupKey(ctx, stored))
			if mode != "deleted" {
				require.NoError(t, am.Store.SaveUser(ctx, user))
			}
			_, err = enrollPeer(am, key.Key, "rejected-device")
			require.Error(t, err)
			_, err = am.Store.GetPeerByPeerPubKey(ctx, store.LockingStrengthNone, "rejected-device")
			require.Error(t, err, "rejected enrollment must leave no peer")
			require.Zero(t, storedEnrollment(t, am, key.Key).UsedTimes)
			if mode == "expired" || mode == "revoked" {
				_, _, _, _, err = am.LoginPeer(ctx, types.PeerLogin{WireGuardPubKey: "jwt-rejected-device", UserID: user.Id, EnrollmentUserID: user.Id, SetupKey: key.Key, Meta: nbpeer.PeerSystemMeta{Hostname: "jwt-rejected-device"}})
				require.Error(t, err, "neither a JWT nor legacy owner metadata may bypass key validity")
			}
			if mode == "blocked" || mode == "pending" || mode == "deleted" || mode == "wrong-account" {
				_, err = am.CreateEnrollmentKey(ctx, "enrollment-account", user.Id)
				require.Error(t, err)
			}
		})
	}
}

func TestEnrollmentConcurrentRedemption(t *testing.T) {
	am, user := enrollmentFixture(t)
	key, err := am.CreateEnrollmentKey(context.Background(), user.AccountID, user.Id)
	require.NoError(t, err)
	start := make(chan struct{})
	results := make(chan error, 8)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, err := enrollPeer(am, key.Key, fmt.Sprintf("device-%d", i))
			results <- err
		}(i)
	}
	close(start)
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		}
	}
	require.Equal(t, 1, successes)
	require.Equal(t, 1, storedEnrollment(t, am, key.Key).UsedTimes)
}

func TestEnrollmentIssuanceIsBounded(t *testing.T) {
	am, user := enrollmentFixture(t)
	for i := 0; i < 5; i++ {
		_, err := am.CreateEnrollmentKey(context.Background(), user.AccountID, user.Id)
		require.NoError(t, err)
	}
	_, err := am.CreateEnrollmentKey(context.Background(), user.AccountID, user.Id)
	require.ErrorContains(t, err, "too many enrollment requests")
}

// This crosses the HTTP issuer, real account manager and control redemption
// boundary. The authenticated subject is supplied as middleware would supply
// it; neither permission enforcement nor key issuance is replaced by a fake.
func TestEnrollmentPortalThroughControl(t *testing.T) {
	am, user := enrollmentFixture(t)
	nodes, err := karstnode.NewStore(am.Store.(*store.SqlStore).GetDB())
	require.NoError(t, err)
	router := mux.NewRouter()
	karstapi.RegisterEndpoints(nodes, am, am, nil, nil, nil, nil, nil, nil, am.permissionsManager, router)
	req := httptest.NewRequest(http.MethodPost, "/karst/v1/me/devices/enroll", nil)
	req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{AccountId: user.AccountID, UserId: user.Id})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	var grant struct {
		Key string `json:"key"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &grant))
	signer, err := karstidentity.Generate()
	require.NoError(t, err)
	kem, err := mlkem.GenerateKey1024()
	require.NoError(t, err)
	raw, err := pb.Marshal(&proto.KarstLoginRequest{SetupKey: grant.Key, Meta: &proto.PeerSystemMeta{Hostname: "member-device"}, KemPublicKey: kem.EncapsulationKey().Bytes()})
	require.NoError(t, err)
	handler := karstcontrol.LoginHandler{Nodes: nodes, Accounts: am}
	db := am.Store.(*store.SqlStore).GetDB()
	failIdentityWrite := true
	require.NoError(t, db.Callback().Create().Before("gorm:create").Register("enrollment-fault", func(tx *gorm.DB) {
		if tx.Statement.Table == "karst_node_identities" && failIdentityWrite {
			failIdentityWrite = false
			tx.AddError(errors.New("injected identity write failure"))
		}
	}))
	defer func() { require.NoError(t, db.Callback().Create().Remove("enrollment-fault")) }()
	_, err = handler.Handle(context.Background(), nil, signer.Public(), raw)
	require.ErrorContains(t, err, "injected identity write failure")
	require.Equal(t, 1, storedEnrollment(t, am, grant.Key).UsedTimes)
	_, err = nodes.Get(karstnode.Handle(signer.Public()))
	require.Error(t, err)
	// Retry the same proven identity after the business transaction committed.
	// It must repair the missing identity record without consuming another key.
	_, err = handler.Handle(context.Background(), nil, signer.Public(), raw)
	require.NoError(t, err)
	peer, err := am.Store.GetPeerByPeerPubKey(context.Background(), store.LockingStrengthNone, karstnode.Handle(signer.Public()))
	require.NoError(t, err)
	require.Equal(t, user.Id, peer.UserID)
	second, err := karstidentity.Generate()
	require.NoError(t, err)
	_, err = handler.Handle(context.Background(), nil, second.Public(), raw)
	require.Error(t, err, "the same portal credential must never enroll a second identity")
	_, err = nodes.Get(karstnode.Handle(second.Public()))
	require.Error(t, err)
}

func TestDeviceInvitationNeedsNoRecipientAccount(t *testing.T) {
	am, member := enrollmentFixture(t)
	ctx := context.Background()
	group := &types.Group{ID: "invited-devices", AccountID: member.AccountID, Name: "Invited devices", Issued: "api"}
	require.NoError(t, am.Store.CreateGroup(ctx, group))
	_, err := am.CreateDeviceInvitation(ctx, member.AccountID, member.Id, "Laptop", []string{group.ID})
	require.Error(t, err, "members cannot issue administrative invitations")
	key, err := am.CreateDeviceInvitation(ctx, member.AccountID, "owner", "Laptop", []string{group.ID})
	require.NoError(t, err)
	stored := storedEnrollment(t, am, key.Key)
	require.Empty(t, stored.OwnerUserID, "recipient does not need an account")
	require.Equal(t, "owner", stored.InvitationIssuerID)
	require.NotContains(t, stored.EventMeta(), "key")
	require.Error(t, am.DeleteSetupKey(ctx, member.AccountID, "owner", stored.Id), "history cannot be deleted to evade issuance limits")
	require.Equal(t, 1, stored.UsageLimit)
	require.WithinDuration(t, time.Now().Add(24*time.Hour), stored.GetExpiresAt(), time.Minute)
	changed := stored.Copy()
	changed.AutoGroups = nil
	_, err = am.SaveSetupKey(ctx, member.AccountID, changed, "owner")
	require.Error(t, err, "an issued invitation cannot change access scope")
	device, err := enrollPeer(am, key.Key, "invited-device")
	require.NoError(t, err)
	require.Empty(t, device.UserID)
	groups, err := am.Store.GetPeerGroupIDs(ctx, store.LockingStrengthNone, member.AccountID, device.ID)
	require.NoError(t, err)
	require.Contains(t, groups, group.ID)
	_, err = enrollPeer(am, key.Key, "another-invited-device")
	require.Error(t, err)
}

func TestDeviceInvitationHTTPLifecycle(t *testing.T) {
	am, member := enrollmentFixture(t)
	ctx := context.Background()
	group := &types.Group{ID: "http-invited", AccountID: member.AccountID, Name: "Invited", Issued: "api"}
	require.NoError(t, am.Store.CreateGroup(ctx, group))
	nodes, err := karstnode.NewStore(am.Store.(*store.SqlStore).GetDB())
	require.NoError(t, err)
	router := mux.NewRouter()
	karstapi.RegisterEndpoints(nodes, am, am, nil, nil, nil, nil, nil, nil, am.permissionsManager, router)
	request := func(method, path, body, user string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{AccountId: member.AccountID, UserId: user})
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec
	}
	body := `{"name":"Laptop","groups":["http-invited"]}`
	denied := request(http.MethodPost, "/karst/v1/invitations", body, member.Id)
	require.Equal(t, http.StatusForbidden, denied.Code)
	created := request(http.MethodPost, "/karst/v1/invitations", body, "owner")
	require.Equal(t, http.StatusOK, created.Code, created.Body.String())
	require.Equal(t, "no-store", created.Header().Get("Cache-Control"))
	var grant struct {
		ID         string `json:"id"`
		Credential string `json:"credential"`
		State      string `json:"state"`
	}
	require.NoError(t, json.Unmarshal(created.Body.Bytes(), &grant))
	require.NotEmpty(t, grant.Credential)
	require.Equal(t, "pending", grant.State)
	listed := request(http.MethodGet, "/karst/v1/invitations", "", "owner")
	require.Equal(t, http.StatusOK, listed.Code, listed.Body.String())
	require.NotContains(t, listed.Body.String(), grant.Credential)
	require.NotContains(t, listed.Body.String(), "credential")
	revoked := request(http.MethodPost, "/karst/v1/invitations/"+grant.ID+"/revoke", "", "owner")
	require.Equal(t, http.StatusOK, revoked.Code, revoked.Body.String())
	require.Contains(t, revoked.Body.String(), `"state":"revoked"`)
	require.NotContains(t, revoked.Body.String(), grant.Credential)
	_, err = enrollPeer(am, grant.Credential, "revoked-invited-device")
	require.Error(t, err)
}

func TestDeviceInvitationConcurrentRedemptionAndExpiry(t *testing.T) {
	am, member := enrollmentFixture(t)
	ctx := context.Background()
	group := &types.Group{ID: "invitation-race", AccountID: member.AccountID, Name: "Invitation race", Issued: "api"}
	require.NoError(t, am.Store.CreateGroup(ctx, group))
	grant, err := am.CreateDeviceInvitation(ctx, member.AccountID, "owner", "Concurrent device", []string{group.ID})
	require.NoError(t, err)
	var wait sync.WaitGroup
	outcomes := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wait.Add(1)
		go func(i int) {
			defer wait.Done()
			_, err := enrollPeer(am, grant.Key, fmt.Sprintf("invitation-race-%d", i))
			outcomes <- err
		}(i)
	}
	wait.Wait()
	close(outcomes)
	accepted := 0
	for err := range outcomes {
		if err == nil {
			accepted++
		}
	}
	require.Equal(t, 1, accepted)
	require.Equal(t, 1, storedEnrollment(t, am, grant.Key).UsedTimes)
	expired, err := am.CreateDeviceInvitation(ctx, member.AccountID, "owner", "Expired device", []string{group.ID})
	require.NoError(t, err)
	stored := storedEnrollment(t, am, expired.Key)
	past := time.Now().Add(-time.Minute)
	stored.ExpiresAt = &past
	require.NoError(t, am.Store.SaveSetupKey(ctx, stored))
	_, err = enrollPeer(am, expired.Key, "expired-invitation-device")
	require.Error(t, err)
	require.Zero(t, storedEnrollment(t, am, expired.Key).UsedTimes)
}

// Revocation must not reset the persisted issuance window.
func TestDeviceInvitationIssuanceIsBounded(t *testing.T) {
	am, member := enrollmentFixture(t)
	ctx := context.Background()
	group := &types.Group{ID: "invitation-limit", AccountID: member.AccountID, Name: "Invited", Issued: "api"}
	require.NoError(t, am.Store.CreateGroup(ctx, group))
	for i := 0; i < 20; i++ {
		key, err := am.CreateDeviceInvitation(ctx, member.AccountID, "owner", "Laptop", []string{group.ID})
		require.NoError(t, err)
		key.Revoked = true
		_, err = am.SaveSetupKey(ctx, member.AccountID, key, "owner")
		require.NoError(t, err)
	}
	_, err := am.CreateDeviceInvitation(ctx, member.AccountID, "owner", "Laptop", []string{group.ID})
	require.ErrorContains(t, err, "too many invitations")
}

func TestDeviceInvitationCanBeRevokedAfterGroupRemoval(t *testing.T) {
	am, member := enrollmentFixture(t)
	ctx := context.Background()
	group := &types.Group{ID: "removed-invitation-group", AccountID: member.AccountID, Name: "Invited", Issued: "api"}
	require.NoError(t, am.Store.CreateGroup(ctx, group))
	key, err := am.CreateDeviceInvitation(ctx, member.AccountID, "owner", "Laptop", []string{group.ID})
	require.NoError(t, err)
	require.NoError(t, am.Store.DeleteGroup(ctx, member.AccountID, group.ID))
	key.Revoked = true
	_, err = am.SaveSetupKey(ctx, member.AccountID, key, "owner")
	require.NoError(t, err)
	_, err = enrollPeer(am, key.Key, "revoked-with-removed-group")
	require.Error(t, err)
	require.Zero(t, storedEnrollment(t, am, key.Key).UsedTimes)
}
