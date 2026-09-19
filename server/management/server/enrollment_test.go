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
	meshdomainmanager "github.com/netbirdio/netbird/management/internals/modules/meshdomain/manager"
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
	karstapi.RegisterEndpoints(nodes, am, am, nil, nil, nil, nil, nil, nil, am, am.permissionsManager, nil, router)
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
	_, err := am.CreateDeviceInvitation(ctx, member.AccountID, member.Id, "Laptop", []string{group.ID}, "")
	require.Error(t, err, "members cannot issue administrative invitations")
	key, err := am.CreateDeviceInvitation(ctx, member.AccountID, "owner", "Laptop", []string{group.ID}, "")
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

func TestDeviceInvitationNameBecomesPeerIdentity(t *testing.T) {
	am, member := enrollmentFixture(t)
	ctx := context.Background()
	group := &types.Group{ID: "named-devices", AccountID: member.AccountID, Name: "Named devices", Issued: "api"}
	require.NoError(t, am.Store.CreateGroup(ctx, group))

	key, err := am.CreateDeviceInvitation(ctx, member.AccountID, "owner", "Adrian's MacBook Pro!", []string{group.ID}, "")
	require.NoError(t, err)

	// The client's self-reported hostname must be ignored in favor of the
	// admin's invitation name: this is the whole point of #163.
	device, err := enrollPeer(am, key.Key, "some-clients-own-hostname")
	require.NoError(t, err)
	require.Equal(t, "Adrian's MacBook Pro!", device.Name, "peer.Name keeps the admin's literal invitation text")
	require.Equal(t, "adrian-s-macbook-pro-", device.DNSLabel, "DNSLabel is the same grammar-sanitized parse hostnames already get")
	require.NotContains(t, device.DNSLabel, "some-clients-own-hostname")
}

func TestDeviceInvitationRejectsUnnameableLabel(t *testing.T) {
	am, member := enrollmentFixture(t)
	ctx := context.Background()
	group := &types.Group{ID: "unnameable", AccountID: member.AccountID, Name: "Unnameable", Issued: "api"}
	require.NoError(t, am.Store.CreateGroup(ctx, group))

	_, err := am.CreateDeviceInvitation(ctx, member.AccountID, "owner", "!!!", []string{group.ID}, "")
	require.Error(t, err, "a name with no letters or digits cannot become a DNS label")
}

func TestEnrollmentKeyPortalPlaceholderNameStaysOffPeers(t *testing.T) {
	am, user := enrollmentFixture(t)
	ctx := context.Background()

	key, err := am.CreateEnrollmentKey(ctx, user.AccountID, user.Id)
	require.NoError(t, err)
	require.Equal(t, "portal device", storedEnrollment(t, am, key.Key).Name, "sanity: the portal key really does carry a fixed placeholder name")

	device, err := enrollPeer(am, key.Key, "my-real-laptop")
	require.NoError(t, err)
	require.Equal(t, "my-real-laptop", device.Name, "the portal key's placeholder name must never become a peer's identity")
}

func TestDeviceInvitationIntoMeshDomainIsQualified(t *testing.T) {
	am, member := enrollmentFixture(t)
	ctx := context.Background()
	group := &types.Group{ID: "domain-devices", AccountID: member.AccountID, Name: "Domain devices", Issued: "api"}
	require.NoError(t, am.Store.CreateGroup(ctx, group))

	domainManager := meshdomainmanager.NewManager(am.Store, am, am.permissionsManager)
	root, err := domainManager.CreateDomain(ctx, member.AccountID, "owner", "", "acme")
	require.NoError(t, err)
	engineering, err := domainManager.CreateDomain(ctx, member.AccountID, "owner", root.ID, "engineering")
	require.NoError(t, err)

	key, err := am.CreateDeviceInvitation(ctx, member.AccountID, "owner", "build-box", []string{group.ID}, engineering.ID)
	require.NoError(t, err)

	device, err := enrollPeer(am, key.Key, "whatever-the-client-calls-itself")
	require.NoError(t, err)
	require.Equal(t, engineering.ID, device.DomainID)
	require.Equal(t, "build-box.engineering.acme", device.DNSLabel, "the peer's DNS label is qualified by its mesh domain's Path")
}

func TestDeviceInvitationDelegatedSubdomainAdmin(t *testing.T) {
	am, member := enrollmentFixture(t)
	ctx := context.Background()
	group := &types.Group{ID: "delegated-devices", AccountID: member.AccountID, Name: "Delegated devices", Issued: "api"}
	require.NoError(t, am.Store.CreateGroup(ctx, group))

	domainManager := meshdomainmanager.NewManager(am.Store, am, am.permissionsManager)
	root, err := domainManager.CreateDomain(ctx, member.AccountID, "owner", "", "acme")
	require.NoError(t, err)
	engineering, err := domainManager.CreateDomain(ctx, member.AccountID, "owner", root.ID, "engineering")
	require.NoError(t, err)
	sales, err := domainManager.CreateDomain(ctx, member.AccountID, "owner", root.ID, "sales")
	require.NoError(t, err)

	// member.Id is an ordinary account member with zero account-wide grants
	// (enrollmentFixture's fixture user, types.NewRegularUser) -- without a
	// delegation, issuing any invitation is refused, matching
	// TestDeviceInvitationNeedsNoRecipientAccount.
	_, err = am.CreateDeviceInvitation(ctx, member.AccountID, member.Id, "should-fail", []string{group.ID}, engineering.ID)
	require.Error(t, err)

	_, err = domainManager.DelegateDomainAdmin(ctx, member.AccountID, "owner", engineering.ID, member.Id)
	require.NoError(t, err)

	// Now delegated for "engineering" specifically: can issue into it or a
	// subdomain created under it, but not into the unrelated "sales" domain.
	key, err := am.CreateDeviceInvitation(ctx, member.AccountID, member.Id, "delegated-device", []string{group.ID}, engineering.ID)
	require.NoError(t, err)
	device, err := enrollPeer(am, key.Key, "irrelevant-hostname")
	require.NoError(t, err)
	require.Equal(t, "delegated-device.engineering.acme", device.DNSLabel)

	_, err = am.CreateDeviceInvitation(ctx, member.AccountID, member.Id, "should-still-fail", []string{group.ID}, sales.ID)
	require.Error(t, err, "delegation to engineering must not reach the sibling sales domain")
}

func TestDeviceInvitationDelegatedAdminListsAndRevokesOwnDomainOnly(t *testing.T) {
	am, member := enrollmentFixture(t)
	ctx := context.Background()
	group := &types.Group{ID: "listing-devices", AccountID: member.AccountID, Name: "Listing devices", Issued: "api"}
	require.NoError(t, am.Store.CreateGroup(ctx, group))

	domainManager := meshdomainmanager.NewManager(am.Store, am, am.permissionsManager)
	root, err := domainManager.CreateDomain(ctx, member.AccountID, "owner", "", "acme")
	require.NoError(t, err)
	engineering, err := domainManager.CreateDomain(ctx, member.AccountID, "owner", root.ID, "engineering")
	require.NoError(t, err)

	// A pre-existing root invitation the delegated admin has no relation to.
	unrelated, err := am.CreateDeviceInvitation(ctx, member.AccountID, "owner", "root-device", []string{group.ID}, "")
	require.NoError(t, err)

	_, err = am.ListDeviceInvitations(ctx, member.AccountID, member.Id)
	require.Error(t, err, "no account-wide grant and no delegation yet: refused outright")

	_, err = domainManager.DelegateDomainAdmin(ctx, member.AccountID, "owner", engineering.ID, member.Id)
	require.NoError(t, err)

	own, err := am.CreateDeviceInvitation(ctx, member.AccountID, member.Id, "own-device", []string{group.ID}, engineering.ID)
	require.NoError(t, err)

	visible, err := am.ListDeviceInvitations(ctx, member.AccountID, member.Id)
	require.NoError(t, err)
	ids := make([]string, len(visible))
	for i, key := range visible {
		ids[i] = key.Id
	}
	require.Contains(t, ids, own.Id)
	require.NotContains(t, ids, unrelated.Id, "a delegated admin must not see an invitation outside their domain")

	revoked, err := am.RevokeDeviceInvitation(ctx, member.AccountID, member.Id, own.Id)
	require.NoError(t, err)
	require.True(t, revoked.Revoked)

	_, err = am.RevokeDeviceInvitation(ctx, member.AccountID, member.Id, unrelated.Id)
	require.Error(t, err, "a delegated admin must not revoke an invitation outside their domain")

	// The owner is unaffected: sees and can act on everything regardless of
	// domain delegation.
	all, err := am.ListDeviceInvitations(ctx, member.AccountID, "owner")
	require.NoError(t, err)
	require.Len(t, all, 2)
}

func TestUpdatePeer_MovesBetweenDomainsAndRequalifiesLabel(t *testing.T) {
	am, member := enrollmentFixture(t)
	ctx := context.Background()
	group := &types.Group{ID: "move-devices", AccountID: member.AccountID, Name: "Move devices", Issued: "api"}
	require.NoError(t, am.Store.CreateGroup(ctx, group))

	domainManager := meshdomainmanager.NewManager(am.Store, am, am.permissionsManager)
	root, err := domainManager.CreateDomain(ctx, member.AccountID, "owner", "", "acme")
	require.NoError(t, err)
	engineering, err := domainManager.CreateDomain(ctx, member.AccountID, "owner", root.ID, "engineering")
	require.NoError(t, err)
	sales, err := domainManager.CreateDomain(ctx, member.AccountID, "owner", root.ID, "sales")
	require.NoError(t, err)

	key, err := am.CreateDeviceInvitation(ctx, member.AccountID, "owner", "movable", []string{group.ID}, engineering.ID)
	require.NoError(t, err)
	device, err := enrollPeer(am, key.Key, "irrelevant-hostname")
	require.NoError(t, err)
	require.Equal(t, "movable.engineering.acme", device.DNSLabel)

	// Same name, different domain: the label is fully requalified, not just
	// appended to.
	update := device.Copy()
	update.DomainID = sales.ID
	moved, err := am.UpdatePeer(ctx, member.AccountID, "owner", update)
	require.NoError(t, err)
	require.Equal(t, sales.ID, moved.DomainID)
	require.Equal(t, "movable.sales.acme", moved.DNSLabel)

	// Moving back out to the account root drops the domain qualifier
	// entirely.
	update = moved.Copy()
	update.DomainID = ""
	backToRoot, err := am.UpdatePeer(ctx, member.AccountID, "owner", update)
	require.NoError(t, err)
	require.Equal(t, "", backToRoot.DomainID)
	require.Equal(t, "movable", backToRoot.DNSLabel)

	// A PUT that never mentions domain at all -- Copy() carries the current
	// DomainID forward unchanged, the same contract the fork's own generic
	// /api/peers/{id} handler relies on (peers_handler.go) so an edit to an
	// unrelated field can never silently reset a peer's domain.
	update = backToRoot.Copy()
	update.DomainID = engineering.ID
	inEngineering, err := am.UpdatePeer(ctx, member.AccountID, "owner", update)
	require.NoError(t, err)
	untouched := inEngineering.Copy()
	untouched.SSHEnabled = !untouched.SSHEnabled
	stillInEngineering, err := am.UpdatePeer(ctx, member.AccountID, "owner", untouched)
	require.NoError(t, err)
	require.Equal(t, engineering.ID, stillInEngineering.DomainID)
	require.Equal(t, "movable.engineering.acme", stillInEngineering.DNSLabel)
}

func TestUpdatePeer_DomainMoveRequiresAuthorizationOnBothEnds(t *testing.T) {
	am, member := enrollmentFixture(t)
	ctx := context.Background()
	group := &types.Group{ID: "scoped-move-devices", AccountID: member.AccountID, Name: "Scoped move devices", Issued: "api"}
	require.NoError(t, am.Store.CreateGroup(ctx, group))

	domainManager := meshdomainmanager.NewManager(am.Store, am, am.permissionsManager)
	root, err := domainManager.CreateDomain(ctx, member.AccountID, "owner", "", "acme")
	require.NoError(t, err)
	engineering, err := domainManager.CreateDomain(ctx, member.AccountID, "owner", root.ID, "engineering")
	require.NoError(t, err)
	sales, err := domainManager.CreateDomain(ctx, member.AccountID, "owner", root.ID, "sales")
	require.NoError(t, err)
	_, err = domainManager.DelegateDomainAdmin(ctx, member.AccountID, "owner", engineering.ID, member.Id)
	require.NoError(t, err)

	key, err := am.CreateDeviceInvitation(ctx, member.AccountID, "owner", "scoped-device", []string{group.ID}, engineering.ID)
	require.NoError(t, err)
	device, err := enrollPeer(am, key.Key, "irrelevant-hostname")
	require.NoError(t, err)

	// The delegated admin can edit a peer already in their own domain...
	update := device.Copy()
	update.SSHEnabled = true
	edited, err := am.UpdatePeer(ctx, member.AccountID, member.Id, update)
	require.NoError(t, err)
	require.True(t, edited.SSHEnabled)

	// ...but cannot move it into a domain they do not also administer...
	update = edited.Copy()
	update.DomainID = sales.ID
	_, err = am.UpdatePeer(ctx, member.AccountID, member.Id, update)
	require.Error(t, err, "moving into sales requires authorization over the destination too")

	// ...nor move a peer already in sales into their own domain: the source
	// end needs authorization just as much as the destination does.
	salesKey, err := am.CreateDeviceInvitation(ctx, member.AccountID, "owner", "sales-device", []string{group.ID}, sales.ID)
	require.NoError(t, err)
	salesDevice, err := enrollPeer(am, salesKey.Key, "another-irrelevant-hostname")
	require.NoError(t, err)
	update = salesDevice.Copy()
	update.DomainID = engineering.ID
	_, err = am.UpdatePeer(ctx, member.AccountID, member.Id, update)
	require.Error(t, err, "moving out of sales requires authorization over the source too, not just the destination")
}

func TestDeviceInvitationHTTPLifecycle(t *testing.T) {
	am, member := enrollmentFixture(t)
	ctx := context.Background()
	group := &types.Group{ID: "http-invited", AccountID: member.AccountID, Name: "Invited", Issued: "api"}
	require.NoError(t, am.Store.CreateGroup(ctx, group))
	nodes, err := karstnode.NewStore(am.Store.(*store.SqlStore).GetDB())
	require.NoError(t, err)
	router := mux.NewRouter()
	karstapi.RegisterEndpoints(nodes, am, am, nil, nil, nil, nil, nil, nil, am, am.permissionsManager, nil, router)
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

// /karst/v1/invitations* is exempt from the blanket KarstControl gate
// (ADR-0032) so a domain-delegated admin, who by definition has no
// account-wide grant, can still create, list and revoke a device invitation
// over real HTTP -- not just through DefaultAccountManager directly.
func TestDeviceInvitationHTTPDelegatedAdminReachesOwnDomainOnly(t *testing.T) {
	am, member := enrollmentFixture(t)
	ctx := context.Background()
	group := &types.Group{ID: "http-delegated", AccountID: member.AccountID, Name: "Delegated", Issued: "api"}
	require.NoError(t, am.Store.CreateGroup(ctx, group))
	nodes, err := karstnode.NewStore(am.Store.(*store.SqlStore).GetDB())
	require.NoError(t, err)

	domainManager := meshdomainmanager.NewManager(am.Store, am, am.permissionsManager)
	root, err := domainManager.CreateDomain(ctx, member.AccountID, "owner", "", "acme")
	require.NoError(t, err)
	engineering, err := domainManager.CreateDomain(ctx, member.AccountID, "owner", root.ID, "engineering")
	require.NoError(t, err)
	sales, err := domainManager.CreateDomain(ctx, member.AccountID, "owner", root.ID, "sales")
	require.NoError(t, err)
	_, err = domainManager.DelegateDomainAdmin(ctx, member.AccountID, "owner", engineering.ID, member.Id)
	require.NoError(t, err)

	router := mux.NewRouter()
	karstapi.RegisterEndpoints(nodes, am, am, nil, nil, nil, nil, nil, nil, am, am.permissionsManager, domainManager, router)
	request := func(method, path, body, user string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{AccountId: member.AccountID, UserId: user})
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec
	}

	// Create into the delegated domain: no account-wide grant needed.
	inDomain := request(http.MethodPost, "/karst/v1/invitations", `{"name":"eng-box","groups":["http-delegated"],"domain_id":"`+engineering.ID+`"}`, member.Id)
	require.Equal(t, http.StatusOK, inDomain.Code, inDomain.Body.String())
	var grant struct {
		ID string `json:"id"`
	}
	require.NoError(t, json.Unmarshal(inDomain.Body.Bytes(), &grant))

	// The unrelated sales domain is out of reach.
	outOfScope := request(http.MethodPost, "/karst/v1/invitations", `{"name":"sales-box","groups":["http-delegated"],"domain_id":"`+sales.ID+`"}`, member.Id)
	require.Equal(t, http.StatusForbidden, outOfScope.Code, outOfScope.Body.String())

	// The delegated admin sees their own invitation when listing.
	listed := request(http.MethodGet, "/karst/v1/invitations", "", member.Id)
	require.Equal(t, http.StatusOK, listed.Code, listed.Body.String())
	require.Contains(t, listed.Body.String(), grant.ID)

	// ...and can revoke it.
	revoked := request(http.MethodPost, "/karst/v1/invitations/"+grant.ID+"/revoke", "", member.Id)
	require.Equal(t, http.StatusOK, revoked.Code, revoked.Body.String())
	require.Contains(t, revoked.Body.String(), `"state":"revoked"`)
}

func TestDeviceInvitationConcurrentRedemptionAndExpiry(t *testing.T) {
	am, member := enrollmentFixture(t)
	ctx := context.Background()
	group := &types.Group{ID: "invitation-race", AccountID: member.AccountID, Name: "Invitation race", Issued: "api"}
	require.NoError(t, am.Store.CreateGroup(ctx, group))
	grant, err := am.CreateDeviceInvitation(ctx, member.AccountID, "owner", "Concurrent device", []string{group.ID}, "")
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
	expired, err := am.CreateDeviceInvitation(ctx, member.AccountID, "owner", "Expired device", []string{group.ID}, "")
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
		key, err := am.CreateDeviceInvitation(ctx, member.AccountID, "owner", "Laptop", []string{group.ID}, "")
		require.NoError(t, err)
		key.Revoked = true
		_, err = am.SaveSetupKey(ctx, member.AccountID, key, "owner")
		require.NoError(t, err)
	}
	_, err := am.CreateDeviceInvitation(ctx, member.AccountID, "owner", "Laptop", []string{group.ID}, "")
	require.ErrorContains(t, err, "too many invitations")
}

func TestDeviceInvitationCanBeRevokedAfterGroupRemoval(t *testing.T) {
	am, member := enrollmentFixture(t)
	ctx := context.Background()
	group := &types.Group{ID: "removed-invitation-group", AccountID: member.AccountID, Name: "Invited", Issued: "api"}
	require.NoError(t, am.Store.CreateGroup(ctx, group))
	key, err := am.CreateDeviceInvitation(ctx, member.AccountID, "owner", "Laptop", []string{group.ID}, "")
	require.NoError(t, err)
	require.NoError(t, am.Store.DeleteGroup(ctx, member.AccountID, group.ID))
	key.Revoked = true
	_, err = am.SaveSetupKey(ctx, member.AccountID, key, "owner")
	require.NoError(t, err)
	_, err = enrollPeer(am, key.Key, "revoked-with-removed-group")
	require.Error(t, err)
	require.Zero(t, storedEnrollment(t, am, key.Key).UsedTimes)
}
