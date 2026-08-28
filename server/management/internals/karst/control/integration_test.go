// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package control_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/gorilla/mux"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	pb "google.golang.org/protobuf/proto"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/netbirdio/netbird/management/internals/controllers/network_map/controller"
	"github.com/netbirdio/netbird/management/internals/controllers/network_map/update_channel"
	karstapi "github.com/netbirdio/netbird/management/internals/karst/api"
	"github.com/netbirdio/netbird/management/internals/karst/channel"
	"github.com/netbirdio/netbird/management/internals/karst/control"
	"github.com/netbirdio/netbird/management/internals/karst/identity"
	"github.com/netbirdio/netbird/management/internals/karst/node"
	"github.com/netbirdio/netbird/management/internals/modules/peers"
	ephemeral_manager "github.com/netbirdio/netbird/management/internals/modules/peers/ephemeral/manager"
	"github.com/netbirdio/netbird/management/internals/server/config"
	nbserver "github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/activity"
	nbcache "github.com/netbirdio/netbird/management/server/cache"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/geolocation"
	"github.com/netbirdio/netbird/management/server/idp"
	"github.com/netbirdio/netbird/management/server/integrations/port_forwarding"
	"github.com/netbirdio/netbird/management/server/job"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/settings"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/telemetry"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/auth"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// This is the one test that does not use a fake.
//
// Every other test in this package proves Karst's own layers against a
// one-method stub of the account manager. That validates the contract Karst
// depends on but says nothing about whether the *real* manager accepts a
// Karst node handle where it expects a WireGuard public key. This one builds
// the actual DefaultAccountManager over a real SQLite store loaded from
// upstream's own fixture, and drives it through a real PQ handshake on a real
// gRPC connection.

// fixturePath resolves upstream's test SQL relative to this file, since the
// test's working directory is this package rather than management/server.
func fixturePath(t *testing.T, name string) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate this source file")
	}
	// .../management/internals/karst/control/integration_test.go
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "server", "testdata", name)
}

func realAccountManager(t *testing.T, idpManager ...idp.Manager) (*nbserver.DefaultAccountManager, store.Store) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the SQLite store is not properly supported on Windows")
	}
	ctx := context.Background()

	s, cleanup, err := store.NewTestStoreFromSQL(ctx, fixturePath(t, "extended-store.sql"), t.TempDir())
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(cleanup)

	metrics, err := telemetry.NewDefaultAppMetrics(ctx)
	if err != nil {
		t.Fatalf("metrics: %v", err)
	}

	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)
	settingsManager := settings.NewMockManager(ctrl)
	settingsManager.EXPECT().GetExtraSettings(gomock.Any(), gomock.Any()).
		Return(&types.ExtraSettings{}, nil).AnyTimes()

	permissionsManager := permissions.NewManager(s)
	peersManager := peers.NewManager(s, permissionsManager)

	cacheStore, err := nbcache.NewStore(ctx, 100*time.Millisecond, 300*time.Millisecond, 100)
	if err != nil {
		t.Fatalf("cache: %v", err)
	}
	updateManager := update_channel.NewPeersUpdateManager(metrics)
	requestBuffer := nbserver.NewAccountRequestBuffer(ctx, s)
	networkMapController := controller.NewController(ctx, s, metrics, updateManager, requestBuffer,
		nbserver.MockIntegratedValidator{}, settingsManager, "netbird.cloud",
		port_forwarding.NewControllerMock(),
		ephemeral_manager.NewEphemeralManager(s, peers.NewManager(s, permissionsManager)),
		&config.Config{})

	var manager idp.Manager
	if len(idpManager) != 0 {
		manager = idpManager[0]
	}
	am, err := nbserver.BuildManager(ctx, nil, s, networkMapController,
		job.NewJobManager(nil, s, peersManager), manager, "", &activity.InMemoryEventStore{},
		geolocation.Geolocation(nil), false, nbserver.MockIntegratedValidator{}, metrics,
		port_forwarding.NewControllerMock(), settingsManager, permissionsManager, false, cacheStore)
	if err != nil {
		t.Fatalf("BuildManager: %v", err)
	}
	return am, s
}

// TestRegistrationAgainstTheRealAccountManager is the end-to-end proof: a Karst
// node with an ML-DSA-65 identity registers over the post-quantum channel and
// a peer row lands in the database keyed by its handle.
func TestRegistrationAgainstTheRealAccountManager(t *testing.T) {
	am, s := realAccountManager(t)
	ctx := context.Background()

	const (
		accountID = "bf1c8084-ba50-4ce7-9439-34653001fc3b"
		userID    = "edafee4e-63fb-11ec-90d6-0242ac120003"
	)
	db, err := gorm.Open(sqlite.Open("file:karstint?mode=memory&cache=shared"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("karst db: %v", err)
	}
	nodes, err := node.NewStore(db)
	if err != nil {
		t.Fatalf("node store: %v", err)
	}
	router := mux.NewRouter()
	karstapi.RegisterEndpoints(nodes, am, am, nil, nil, nil, nil, nil, permissions.NewManager(s), router)
	portalRequest := func(method, path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, nil)
		req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{AccountId: accountID, UserId: userID})
		response := httptest.NewRecorder()
		router.ServeHTTP(response, req)
		return response
	}
	response := portalRequest(http.MethodPost, "/karst/v1/me/devices/enrol")
	if response.Code != http.StatusOK {
		t.Fatalf("create portal enrolment key: status=%d body=%s", response.Code, response.Body.String())
	}
	var enrolment struct {
		Key string `json:"key"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &enrolment); err != nil || enrolment.Key == "" {
		t.Fatalf("portal enrolment response: key=%q err=%v", enrolment.Key, err)
	}
	setupKey := enrolment.Key

	static, err := channel.GenerateStatic()
	if err != nil {
		t.Fatalf("static: %v", err)
	}
	srvKey, err := identity.Generate()
	if err != nil {
		t.Fatalf("server identity: %v", err)
	}
	key, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	svc := control.New(static, identity.ControlSigner{Key: srvKey}, nodes.LookupFunc(), identity.ControlVerifier{},
		&control.LoginHandler{Nodes: nodes, Accounts: am})

	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	proto.RegisterKarstControlServiceServer(srv, svc)
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	dialCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	stream, err := proto.NewKarstControlServiceClient(conn).Session(dialCtx)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	cl, err := control.Dial(stream, svc.Pins(), identity.ControlVerifier{}, nil,
		identity.ControlSigner{Key: key}, true)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}

	payload, err := pb.Marshal(&proto.KarstLoginRequest{
		SetupKey:     setupKey,
		Meta:         &proto.PeerSystemMeta{Hostname: "karst-node", GoOS: "linux", NetbirdVersion: "0.0.0"},
		KemPublicKey: validKemKey(0xAB),
		DhPublicKey:  bytes.Repeat([]byte{0xCD}, 32),
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	raw, err := cl.Request(payload)
	if err != nil {
		t.Fatalf("login against the real manager: %v", err)
	}
	resp := &proto.KarstLoginResponse{}
	if err := pb.Unmarshal(raw, resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	handle := node.Handle(key.Public())
	if string(resp.GetNodeId()) != handle {
		t.Fatalf("node_id: got %q want %q", resp.GetNodeId(), handle)
	}
	if resp.GetPeerIp() == "" {
		t.Fatal("the real manager assigned no address")
	}

	// The decisive assertion: a peer row exists, found by the Karst handle, in
	// the column the fork indexes as a WireGuard public key.
	peer, err := s.GetPeerByPeerPubKey(ctx, store.LockingStrengthShare, handle)
	if err != nil {
		t.Fatalf("no peer row for the Karst handle: %v", err)
	}
	if peer.Key != handle {
		t.Fatalf("peer.Key: got %q want %q", peer.Key, handle)
	}
	if peer.IP.String() != resp.GetPeerIp() {
		t.Fatalf("address disagreement: row %s, response %s", peer.IP, resp.GetPeerIp())
	}

	// The same real account manager backs the browser-facing portal handlers.
	// Drive those handlers after a genuine PQ registration to prove that a
	// client user's lifecycle is not merely a JavaScript fixture: its device is
	// visible, a user-scoped one-time key can be issued, and revocation removes
	// both the fork peer and Karst identity record.
	response = portalRequest(http.MethodGet, "/karst/v1/me/devices")
	if response.Code != http.StatusOK {
		t.Fatalf("list portal devices: status=%d body=%s", response.Code, response.Body.String())
	}
	var devices []struct {
		Handle   string `json:"handle"`
		Platform string `json:"platform"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &devices); err != nil {
		t.Fatalf("decode portal devices: %v", err)
	}
	if len(devices) != 1 || devices[0].Handle != handle || devices[0].Platform != "linux" {
		t.Fatalf("portal devices: %#v", devices)
	}

	response = portalRequest(http.MethodDelete, "/karst/v1/me/devices/"+url.PathEscape(handle))
	if response.Code != http.StatusNoContent {
		t.Fatalf("revoke portal device: status=%d body=%s", response.Code, response.Body.String())
	}
	if _, err := nodes.Get(handle); err == nil {
		t.Fatal("Karst identity survived portal revocation")
	}
	if _, err := s.GetPeerByPeerPubKey(ctx, store.LockingStrengthShare, handle); err == nil {
		t.Fatal("fork peer survived portal revocation")
	}

	t.Logf("registered: handle=%s ip=%s dns=%s", handle, peer.IP, peer.DNSLabel)
}

func TestConsoleUserLifecycleAgainstTheRealAccountManager(t *testing.T) {
	const (
		accountID = "bf1c8084-ba50-4ce7-9439-34653001fc3b"
		adminID   = "edafee4e-63fb-11ec-90d6-0242ac120003"
		memberID  = "portal-member"
	)
	pending := true
	users := map[string]*idp.UserData{
		adminID: {ID: adminID, Email: "admin@example.test", Name: "Admin", AppMetadata: idp.AppMetadata{WTAccountID: accountID}},
	}
	mock := &idp.MockIDP{}
	mock.GetAccountFunc = func(context.Context, string) ([]*idp.UserData, error) {
		out := make([]*idp.UserData, 0, len(users))
		for _, user := range users {
			out = append(out, user)
		}
		return out, nil
	}
	mock.GetUserDataByIDFunc = func(_ context.Context, userID string, _ idp.AppMetadata) (*idp.UserData, error) {
		return users[userID], nil
	}
	mock.GetUserByEmailFunc = func(_ context.Context, email string) ([]*idp.UserData, error) {
		for _, user := range users {
			if user.Email == email {
				return []*idp.UserData{user}, nil
			}
		}
		return nil, nil
	}
	mock.CreateUserFunc = func(_ context.Context, email, name, _, _ string) (*idp.UserData, error) {
		user := &idp.UserData{ID: memberID, Email: email, Name: name, AppMetadata: idp.AppMetadata{WTAccountID: accountID, WTPendingInvite: &pending}}
		users[memberID] = user
		return user, nil
	}
	mock.InviteUserByIDFunc = func(_ context.Context, userID string) error {
		if users[userID] == nil {
			return fmt.Errorf("unknown user")
		}
		return nil
	}
	mock.DeleteUserFunc = func(_ context.Context, userID string) error { delete(users, userID); return nil }

	am, s := realAccountManager(t, mock)
	ctx := context.Background()
	created, err := am.CreateUser(ctx, accountID, adminID, &types.UserInfo{Email: "member@example.test", Name: "Portal member", Role: string(types.UserRoleUser), Issued: types.UserIssuedAPI})
	if err != nil {
		t.Fatalf("create console user: %v", err)
	}
	if created.ID != memberID || created.Status != string(types.UserStatusInvited) {
		t.Fatalf("created user: %#v", created)
	}
	if err := am.InviteUser(ctx, accountID, adminID, memberID); err != nil {
		t.Fatalf("resend invitation: %v", err)
	}
	linuxKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("generate member peer key: %v", err)
	}
	memberPeer, _, _, _, err := am.AddPeer(ctx, accountID, "", memberID, &nbpeer.Peer{
		Key:  linuxKey.PublicKey().String(),
		Meta: nbpeer.PeerSystemMeta{Hostname: "portal-member-linux", GoOS: "linux", Platform: "linux"},
	}, false)
	if err != nil {
		t.Fatalf("enrol member Linux client: %v", err)
	}
	if memberPeer.UserID != memberID || memberPeer.Meta.GoOS != "linux" {
		t.Fatalf("enrolled member peer: %#v", memberPeer)
	}
	if err := am.DeleteUser(ctx, accountID, adminID, memberID); err != nil {
		t.Fatalf("deprovision console user: %v", err)
	}
	if _, err := s.GetUserByUserID(ctx, store.LockingStrengthNone, memberID); err == nil {
		t.Fatal("deprovisioned user survived")
	}
	if _, err := s.GetPeerByPeerPubKey(ctx, store.LockingStrengthNone, memberPeer.Key); err == nil {
		t.Fatal("deprovisioned user's Linux peer retained mesh access")
	}
}
