// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package control_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	pb "google.golang.org/protobuf/proto"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/netbirdio/netbird/management/internals/karst/channel"
	"github.com/netbirdio/netbird/management/internals/karst/control"
	"github.com/netbirdio/netbird/management/internals/karst/identity"
	"github.com/netbirdio/netbird/management/internals/karst/node"
	"github.com/netbirdio/netbird/management/internals/karst/psk"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// Phase 3 exit criterion, §2.6:
//
//	"an automated scan of logs, traces, and a generated karst bugreport over a
//	 full registration-to-handshake run finds zero PSK bytes. The log scan runs
//	 in CI, not as a one-time check — this is a regression that gets
//	 reintroduced, not one that gets fixed once."
//
// So this is a test, not a script anyone has to remember to run. It drives a
// real node through registration and a netmap fetch over the real channel with
// logging turned up to Trace, captures everything written, and asserts that
// none of the PSKs the server just distributed appear in it — in raw, hex,
// base64 or Go-literal form.
//
// The psk.Key type makes this pass by construction: String, GoString,
// MarshalText, MarshalJSON and fmt.Formatter all redact. This test is what
// notices when someone reaches past that with .Bytes() and logs the result.

// leakScanner captures everything the server logs.
type leakScanner struct {
	buf bytes.Buffer
}

func (l *leakScanner) Write(p []byte) (int, error) { return l.buf.Write(p) }

// captureLogs redirects logrus for the duration of the test. The fork logs
// through the package-level logger, so this catches the server's own output as
// well as anything Karst adds.
func captureLogs(t *testing.T) *leakScanner {
	t.Helper()
	s := &leakScanner{}

	prevOut := log.StandardLogger().Out
	prevLevel := log.GetLevel()
	log.SetOutput(s)
	log.SetLevel(log.TraceLevel)
	t.Cleanup(func() {
		log.SetOutput(prevOut)
		log.SetLevel(prevLevel)
	})
	return s
}

// encodings returns every rendering of a secret a logger might plausibly
// produce. Checking only the raw bytes would miss the most likely leak of all,
// which is somebody writing %x.
func encodings(secret []byte) map[string]string {
	var goLit strings.Builder
	for i, b := range secret {
		if i > 0 {
			goLit.WriteString(" ")
		}
		fmt.Fprintf(&goLit, "%d", b)
	}
	return map[string]string{
		"hex":           hex.EncodeToString(secret),
		"HEX":           strings.ToUpper(hex.EncodeToString(secret)),
		"base64":        base64.StdEncoding.EncodeToString(secret),
		"base64url":     base64.URLEncoding.EncodeToString(secret),
		"go byte slice": goLit.String(),
		"raw":           string(secret),
	}
}

func TestNoPSKBytesReachTheLogs(t *testing.T) {
	scanner := captureLogs(t)

	db, err := gorm.Open(sqlite.Open("file:leakscan?mode=memory&cache=shared"), &gorm.Config{Logger: logger.Discard})
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

	// Two peers so the netmap actually carries PSKs.
	dpk := func(seed byte) node.DataPlaneKeys {
		return node.DataPlaneKeys{
			KemPublicKey: validKemKey(seed),
		}
	}
	self, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	selfH, err := nodes.Register(self.Public(), dpk(1))
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	peerKey, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	peerH, err := nodes.Register(peerKey.Public(), dpk(2))
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	peers := &fakePeers{
		byKey:     map[string]*nbpeer.Peer{},
		accountOf: map[string]string{},
	}
	selfPeer := &nbpeer.Peer{ID: "peer-self", Key: selfH, AccountID: "acct",
		IP: netip.MustParseAddr("100.64.0.1"), DNSLabel: "self"}
	otherPeer := &nbpeer.Peer{ID: "peer-other", Key: peerH, AccountID: "acct",
		IP: netip.MustParseAddr("100.64.0.2"), DNSLabel: "other"}
	for _, p := range []*nbpeer.Peer{selfPeer, otherPeer} {
		peers.byKey[p.Key] = p
		peers.accountOf[p.Key] = "acct"
		peers.list = append(peers.list, p)
	}

	master, err := psk.GenerateSoftwareMaster()
	if err != nil {
		t.Fatalf("master: %v", err)
	}
	deriver, err := psk.NewDeriver(master)
	if err != nil {
		t.Fatalf("deriver: %v", err)
	}

	static, err := channel.GenerateStatic()
	if err != nil {
		t.Fatalf("static: %v", err)
	}
	srvKey, err := identity.Generate()
	if err != nil {
		t.Fatalf("server identity: %v", err)
	}

	netmap := &control.NetmapHandler{Nodes: nodes, Peers: peers, PSK: deriver}
	netmap.Epoch.Store(7)
	svc := control.New(static, identity.ControlSigner{Key: srvKey}, nodes.LookupFunc(),
		identity.ControlVerifier{}, netmap)

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

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	stream, err := proto.NewKarstControlServiceClient(conn).Session(ctx)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	cl, err := control.Dial(stream, svc.Pins(), identity.ControlVerifier{}, nil,
		identity.ControlSigner{Key: self}, true)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}

	payload, err := pb.Marshal(&proto.KarstNetmapRequest{})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	raw, err := cl.Request(payload)
	if err != nil {
		t.Fatalf("netmap: %v", err)
	}
	resp := &proto.KarstNetmapResponse{}
	if err := pb.Unmarshal(raw, resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// The success path is quiet, which is good for secrets and useless for a
	// scan: an earlier version of this test captured zero bytes and therefore
	// proved nothing at all. Drive the branches that do log.
	_, _ = cl.Request([]byte{0xFF, 0xFF, 0xFF}) // malformed payload

	// A forged envelope on a fresh connection: the server logs the rejection
	// along with the node it came from.
	func() {
		s2, err := proto.NewKarstControlServiceClient(conn).Session(ctx)
		if err != nil {
			return
		}
		c2, err := control.Dial(s2, svc.Pins(), identity.ControlVerifier{}, []byte(selfH),
			identity.ControlSigner{Key: self}, false)
		if err != nil {
			return
		}
		_ = s2.Send(&proto.KarstClientMessage{
			Msg: &proto.KarstClientMessage_Envelope{Envelope: &proto.KarstEnvelope{
				NodeId: []byte(selfH), Body: bytes.Repeat([]byte{0xAA}, 64), Seq: 9, Version: 1,
			}},
		})
		_, _ = s2.Recv()
		_ = c2
	}()

	// A handshake that fails verification, which the server also logs.
	func() {
		s3, err := proto.NewKarstControlServiceClient(conn).Session(ctx)
		if err != nil {
			return
		}
		imposter, err := identity.Generate()
		if err != nil {
			return
		}
		_, _ = control.Dial(s3, svc.Pins(), identity.ControlVerifier{}, []byte(selfH),
			identity.ControlSigner{Key: imposter}, false)
		_, _ = s3.Recv()
	}()

	// Let the server goroutines finish writing.
	time.Sleep(200 * time.Millisecond)

	if len(resp.GetPeers()) == 0 {
		t.Fatal("netmap carried no peers, so this test would prove nothing")
	}
	logged := scanner.buf.String()

	// A scan over an empty buffer passes trivially and reads as assurance.
	// Refuse to be that test.
	if len(logged) < 64 {
		t.Fatalf("captured only %d bytes of log output: the scan would pass "+
			"trivially. Either the server stopped logging on its error paths, "+
			"or this test stopped reaching them.", len(logged))
	}

	// Every secret field, not just the obvious one. psk_previous was added
	// later for §7.3 rotation and is exactly as secret; a scan that checks
	// only `psk` would have gone on passing while half the key material went
	// unexamined.
	type secretField struct {
		what  string
		bytes []byte
	}
	var secrets []secretField
	for _, p := range resp.GetPeers() {
		secrets = append(secrets,
			secretField{"psk", p.GetPsk()},
			secretField{"psk_previous", p.GetPskPrevious()})
	}

	found := 0
	for _, s := range secrets {
		if len(s.bytes) != psk.Size {
			t.Fatalf("%s is %d bytes, want %d", s.what, len(s.bytes), psk.Size)
		}
		found++
		for name, enc := range encodings(s.bytes) {
			if strings.Contains(logged, enc) {
				t.Errorf("%s appeared in the logs as %s", s.what, name)
			}
		}
		// A prefix is enough to be a leak, and catches truncated logging.
		if bytes.Contains([]byte(logged), s.bytes[:8]) {
			t.Errorf("a %s prefix appeared in the logs", s.what)
		}
	}
	if found == 0 {
		t.Fatal("no PSKs were checked")
	}
	t.Logf("checked %d secret fields against %d bytes of captured log output", found, len(logged))
}

// The scanner must be able to fail. A leak test that cannot detect a leak is
// worse than none, because it reads as assurance.
func TestLeakScannerDetectsAPlantedLeak(t *testing.T) {
	scanner := captureLogs(t)

	master, err := psk.GenerateSoftwareMaster()
	if err != nil {
		t.Fatalf("master: %v", err)
	}
	d, err := psk.NewDeriver(master)
	if err != nil {
		t.Fatalf("deriver: %v", err)
	}
	k, err := d.Pair("alice", "bob", 1)
	if err != nil {
		t.Fatalf("pair: %v", err)
	}

	// Exactly the mistake the psk.Key type exists to prevent: reaching past it
	// with .Bytes() and handing the result to a logger.
	log.Infof("peer psk: %x", k.Bytes())

	logged := scanner.buf.String()
	leaked := false
	for _, enc := range encodings(k.Bytes()) {
		if strings.Contains(logged, enc) {
			leaked = true
		}
	}
	if !leaked {
		t.Fatal("the scanner did not detect a deliberately planted PSK leak")
	}

	// And the type itself does not leak when used as intended.
	scanner.buf.Reset()
	log.Infof("peer psk: %v, %s, %x", k, k, k)
	if strings.Contains(scanner.buf.String(), hex.EncodeToString(k.Bytes())) {
		t.Fatal("psk.Key leaked through a normal format verb")
	}
	if !strings.Contains(scanner.buf.String(), "redacted") {
		t.Fatal("psk.Key did not redact")
	}
}
