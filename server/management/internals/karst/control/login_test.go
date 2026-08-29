// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package control_test

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	pb "google.golang.org/protobuf/proto"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/netbirdio/netbird/management/internals/karst/channel"
	"github.com/netbirdio/netbird/management/internals/karst/control"
	"github.com/netbirdio/netbird/management/internals/karst/identity"
	"github.com/netbirdio/netbird/management/internals/karst/node"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// fakeAccounts records what the business layer was asked to do. The real
// account manager needs a database, an IdP and a network; the contract Karst
// depends on is one method, so that is what is faked.
type fakeAccounts struct {
	gotLogin types.PeerLogin
	calls    int
	err      error
}

func (f *fakeAccounts) LoginPeer(_ context.Context, login types.PeerLogin) (*nbpeer.Peer, *types.Network, []*posture.Checks, bool, error) {
	f.calls++
	f.gotLogin = login
	if f.err != nil {
		return nil, nil, nil, false, f.err
	}
	return &nbpeer.Peer{
		ID:       "peer-1",
		Key:      login.WireGuardPubKey,
		IP:       netip.MustParseAddr("100.64.0.7"),
		DNSLabel: "test-host",
	}, nil, nil, false, nil
}

func newLoginFixture(t *testing.T, accounts control.PeerLoginer) (*control.Service, proto.KarstControlServiceClient, *identity.Key, func()) {
	return newLoginFixtureWithOIDC(t, accounts, nil)
}

// identityVerifier and signerFor keep the OIDC tests readable.
func identityVerifier() channel.Verifier { return identity.ControlVerifier{} }

func signerFor(k *identity.Key) channel.Signer { return identity.ControlSigner{Key: k} }

func newLoginFixtureWithOIDC(t *testing.T, accounts control.PeerLoginer, oidc *control.OIDC) (*control.Service, proto.KarstControlServiceClient, *identity.Key, func()) {
	t.Helper()

	db, err := gorm.Open(sqlite.Open("file:logintest?mode=memory&cache=shared"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("db: %v", err)
	}
	if err := db.Exec("DROP TABLE IF EXISTS karst_node_identities").Error; err != nil {
		t.Fatalf("reset: %v", err)
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
		&control.LoginHandler{Nodes: nodes, Accounts: accounts, OIDC: oidc})

	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	proto.RegisterKarstControlServiceServer(srv, svc)
	go func() { _ = srv.Serve(lis) }()

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	return svc, proto.NewKarstControlServiceClient(conn), key, func() {
		_ = conn.Close()
		srv.Stop()
		_ = lis.Close()
	}
}

func loginRequest(t *testing.T, hostname string) []byte {
	t.Helper()
	out, err := pb.Marshal(&proto.KarstLoginRequest{
		SetupKey: "SETUP-KEY",
		Meta:     &proto.PeerSystemMeta{Hostname: hostname, GoOS: "linux", NetbirdVersion: "0.0.0"},
		// PHREATIC's static keys. Registration refuses a node without them:
		// peers cannot handshake with a node whose data-plane keys are
		// unknown, and it would simply be skipped when building netmaps.
		KemPublicKey: validKemKey(0xAB),
		DhPublicKey:  bytes.Repeat([]byte{0xCD}, 32),
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return out
}

// The whole path: PQ handshake over gRPC, then a login that reaches the
// business layer and comes back with an assigned address.
func TestLoginReachesTheBusinessLayer(t *testing.T) {
	accounts := &fakeAccounts{}
	svc, client, key, cleanup := newLoginFixture(t, accounts)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	stream, err := client.Session(ctx)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	cl, err := control.Dial(stream, svc.Pins(), identity.ControlVerifier{}, nil,
		identity.ControlSigner{Key: key}, true)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}

	raw, err := cl.Request(loginRequest(t, "test-host"))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	resp := &proto.KarstLoginResponse{}
	if err := pb.Unmarshal(raw, resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if accounts.calls != 1 {
		t.Fatalf("LoginPeer called %d times, want 1", accounts.calls)
	}
	if resp.GetPeerIp() != "100.64.0.7" {
		t.Fatalf("peer ip: got %q", resp.GetPeerIp())
	}
	if accounts.gotLogin.SetupKey != "SETUP-KEY" {
		t.Fatalf("setup key not forwarded: %q", accounts.gotLogin.SetupKey)
	}
	if accounts.gotLogin.Meta.Hostname != "test-host" {
		t.Fatalf("hostname not forwarded: %q", accounts.gotLogin.Meta.Hostname)
	}
}

// The handle handed to the business layer must be derived from the key the
// node *proved* it holds, and must be shaped like the WireGuard key the forked
// schema's column and unique index expect.
func TestHandleIsDerivedFromTheAuthenticatedIdentity(t *testing.T) {
	accounts := &fakeAccounts{}
	svc, client, key, cleanup := newLoginFixture(t, accounts)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	stream, err := client.Session(ctx)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	cl, err := control.Dial(stream, svc.Pins(), identity.ControlVerifier{}, nil,
		identity.ControlSigner{Key: key}, true)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	raw, err := cl.Request(loginRequest(t, "h"))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	resp := &proto.KarstLoginResponse{}
	if err := pb.Unmarshal(raw, resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	want := node.Handle(key.Public())
	if accounts.gotLogin.WireGuardPubKey != want {
		t.Fatalf("handle: got %q want %q", accounts.gotLogin.WireGuardPubKey, want)
	}
	if len(accounts.gotLogin.WireGuardPubKey) != node.HandleLength {
		t.Fatalf("handle length %d, want %d — will not fit the peers.key index",
			len(accounts.gotLogin.WireGuardPubKey), node.HandleLength)
	}
	if !bytes.Equal(resp.GetNodeId(), []byte(want)) {
		t.Fatal("response node_id does not match the handle used")
	}
}

// Reconnecting must land on the same peer record, or every reconnect creates a
// new node and leaks addresses.
func TestReconnectYieldsTheSameHandle(t *testing.T) {
	accounts := &fakeAccounts{}
	svc, client, key, cleanup := newLoginFixture(t, accounts)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	login := func(nodeID []byte, present bool) string {
		t.Helper()
		stream, err := client.Session(ctx)
		if err != nil {
			t.Fatalf("connect: %v", err)
		}
		cl, err := control.Dial(stream, svc.Pins(), identity.ControlVerifier{}, nodeID,
			identity.ControlSigner{Key: key}, present)
		if err != nil {
			t.Fatalf("handshake: %v", err)
		}
		if _, err := cl.Request(loginRequest(t, "h")); err != nil {
			t.Fatalf("login: %v", err)
		}
		return accounts.gotLogin.WireGuardPubKey
	}

	first := login(nil, true)
	// Second time the node knows its handle, so the server looks the identity
	// up rather than taking a presented one.
	second := login([]byte(first), false)

	if first != second {
		t.Fatalf("reconnect changed the handle: %q then %q", first, second)
	}
	if accounts.calls != 2 {
		t.Fatalf("LoginPeer called %d times, want 2", accounts.calls)
	}
}

// A request with no meta must be refused before it reaches the business layer.
func TestLoginWithoutMetaRejected(t *testing.T) {
	accounts := &fakeAccounts{}
	svc, client, key, cleanup := newLoginFixture(t, accounts)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	stream, err := client.Session(ctx)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	cl, err := control.Dial(stream, svc.Pins(), identity.ControlVerifier{}, nil,
		identity.ControlSigner{Key: key}, true)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	payload, err := pb.Marshal(&proto.KarstLoginRequest{
		SetupKey:     "K",
		KemPublicKey: validKemKey(0xAB),
		DhPublicKey:  bytes.Repeat([]byte{0xCD}, 32),
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := cl.Request(payload); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("got %v want FailedPrecondition", err)
	}
	if accounts.calls != 0 {
		t.Fatal("a login without meta reached the business layer")
	}
}

// A business-layer rejection — a bad setup key, say — must surface to the node
// rather than being swallowed.
func TestBusinessLayerErrorPropagates(t *testing.T) {
	accounts := &fakeAccounts{err: errors.New("invalid setup key")}
	svc, client, key, cleanup := newLoginFixture(t, accounts)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	stream, err := client.Session(ctx)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	cl, err := control.Dial(stream, svc.Pins(), identity.ControlVerifier{}, nil,
		identity.ControlSigner{Key: key}, true)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if _, err := cl.Request(loginRequest(t, "h")); err == nil {
		t.Fatal("a rejected login reported success")
	}
}

// A refused enrollment must not create an identity row. In particular, the
// control handshake proved the identity key before this point, but possession
// of that key is not authorization to consume durable server state.
func TestRejectedLoginDoesNotPersistAnIdentity(t *testing.T) {
	accounts := &fakeAccounts{err: errors.New("invalid setup key")}
	db, err := gorm.Open(sqlite.Open("file:login-rejected-identity?mode=memory&cache=shared"),
		&gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("db: %v", err)
	}
	nodes, err := node.NewStore(db)
	if err != nil {
		t.Fatalf("node store: %v", err)
	}
	key, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	h := &control.LoginHandler{Nodes: nodes, Accounts: accounts}

	if _, err := h.Handle(context.Background(), nil, key.Public(), loginRequest(t, "h")); err == nil {
		t.Fatal("a rejected login reported success")
	}
	if _, err := nodes.Get(node.Handle(key.Public())); !errors.Is(err, node.ErrUnknownNode) {
		t.Fatalf("rejected login persisted an identity: %v", err)
	}
}

// The same ordering protects an established node: a rejected attempt to
// rotate keys must leave the keys currently serving its peers untouched.
func TestRejectedLoginDoesNotRotateDataPlaneKeys(t *testing.T) {
	accounts := &fakeAccounts{err: errors.New("invalid setup key")}
	db, err := gorm.Open(sqlite.Open("file:login-rejected-rotation?mode=memory&cache=shared"),
		&gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("db: %v", err)
	}
	nodes, err := node.NewStore(db)
	if err != nil {
		t.Fatalf("node store: %v", err)
	}
	key, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	old := node.DataPlaneKeys{KemPublicKey: validKemKey(0x11), DhPublicKey: bytes.Repeat([]byte{0x22}, 32)}
	handle, err := nodes.Register(key.Public(), old)
	if err != nil {
		t.Fatalf("seed identity: %v", err)
	}

	req := &proto.KarstLoginRequest{
		SetupKey:     "REJECTED",
		Meta:         &proto.PeerSystemMeta{Hostname: "h"},
		KemPublicKey: validKemKey(0x33),
		DhPublicKey:  bytes.Repeat([]byte{0x44}, 32),
	}
	payload, err := pb.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	h := &control.LoginHandler{Nodes: nodes, Accounts: accounts}
	if _, err := h.Handle(context.Background(), nil, key.Public(), payload); err == nil {
		t.Fatal("a rejected login reported success")
	}
	got, err := nodes.Get(handle)
	if err != nil {
		t.Fatalf("get identity: %v", err)
	}
	if !bytes.Equal(got.KemPublicKey, old.KemPublicKey) || !bytes.Equal(got.DhPublicKey, old.DhPublicKey) {
		t.Fatal("rejected login rotated data-plane keys")
	}
}

// Garbage inside an otherwise valid envelope must not reach the business
// layer. The envelope authenticates the sender; it says nothing about whether
// the payload parses.
func TestMalformedPayloadRejected(t *testing.T) {
	accounts := &fakeAccounts{}
	svc, client, key, cleanup := newLoginFixture(t, accounts)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	stream, err := client.Session(ctx)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	cl, err := control.Dial(stream, svc.Pins(), identity.ControlVerifier{}, nil,
		identity.ControlSigner{Key: key}, true)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if _, err := cl.Request([]byte{0xFF, 0xFF, 0xFF, 0xFF}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("got %v want InvalidArgument", err)
	}
	if accounts.calls != 0 {
		t.Fatal("malformed payload reached the business layer")
	}
}
