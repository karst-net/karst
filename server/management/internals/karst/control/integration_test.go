// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package control_test

import (
	"bytes"
	"context"
	"net"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	pb "google.golang.org/protobuf/proto"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/netbirdio/netbird/management/internals/controllers/network_map/controller"
	"github.com/netbirdio/netbird/management/internals/controllers/network_map/update_channel"
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
	"github.com/netbirdio/netbird/management/server/geolocation"
	"github.com/netbirdio/netbird/management/server/integrations/port_forwarding"
	"github.com/netbirdio/netbird/management/server/job"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/settings"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/telemetry"
	"github.com/netbirdio/netbird/management/server/types"
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

func realAccountManager(t *testing.T) (*nbserver.DefaultAccountManager, store.Store) {
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

	am, err := nbserver.BuildManager(ctx, nil, s, networkMapController,
		job.NewJobManager(nil, s, peersManager), nil, "", &activity.InMemoryEventStore{},
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

	// Mint a setup key rather than reusing one from the fixture: stored keys
	// are SHA-256 hashed (types.GenerateSetupKey), so the fixture rows carry a
	// digest and only CreateSetupKey's return value has the plaintext a node
	// can actually present.
	const (
		accountID = "bf1c8084-ba50-4ce7-9439-34653001fc3b"
		userID    = "edafee4e-63fb-11ec-90d6-0242ac120003"
	)
	created, err := am.CreateSetupKey(ctx, accountID, "karst-integration",
		types.SetupKeyReusable, time.Hour, nil, 999, userID, false, false)
	if err != nil {
		t.Fatalf("create setup key: %v", err)
	}
	setupKey := created.Key

	db, err := gorm.Open(sqlite.Open("file:karstint?mode=memory&cache=shared"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("karst db: %v", err)
	}
	nodes, err := node.NewStore(db)
	if err != nil {
		t.Fatalf("node store: %v", err)
	}

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
	t.Logf("registered: handle=%s ip=%s dns=%s", handle, peer.IP, peer.DNSLabel)
}
