// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package control_test

import (
	"bytes"
	"context"
	"crypto/mlkem"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	pb "google.golang.org/protobuf/proto"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/netbirdio/netbird/management/internals/karst/bedrock"
	"github.com/netbirdio/netbird/management/internals/karst/control"
	"github.com/netbirdio/netbird/management/internals/karst/identity"
	"github.com/netbirdio/netbird/management/internals/karst/node"
	"github.com/netbirdio/netbird/management/internals/karst/policy"
	"github.com/netbirdio/netbird/management/internals/karst/psk"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// fakePeers is the account manager's peer-listing surface. As with
// fakeAccounts, the real thing needs a database and a network; the contract
// the netmap depends on is four methods.
type fakePeers struct {
	byKey     map[string]*nbpeer.Peer
	accountOf map[string]string
	list      []*nbpeer.Peer
	// prefixErr makes AccountPrefixes fail, so the handler's refusal to fall
	// back to a bare address can be tested.
	prefixErr error
	// narrowPrefix returns a different allocation, so the version's dependence
	// on it can be tested.
	narrowPrefix bool
}

func (f *fakePeers) GetAccountIDForPeerKey(_ context.Context, key string) (string, error) {
	id, ok := f.accountOf[key]
	if !ok {
		return "", context.Canceled // any error; the handler maps it to NotFound
	}
	return id, nil
}

func (f *fakePeers) GetPeerByPeerPubKey(_ context.Context, key string) (*nbpeer.Peer, error) {
	p, ok := f.byKey[key]
	if !ok {
		return nil, context.Canceled
	}
	return p, nil
}

func (f *fakePeers) GetPeersFromAccount(_ context.Context, _, _, _ string) ([]*nbpeer.Peer, error) {
	return f.list, nil
}

// The fork allocates a /16 out of 100.64.0.0/10 and a /64 ULA.
func (f *fakePeers) AccountPrefixes(_ context.Context, _ string) (uint8, uint8, error) {
	if f.prefixErr != nil {
		return 0, 0, f.prefixErr
	}
	if f.narrowPrefix {
		return 24, 64, nil
	}
	return 16, 64, nil
}

type netFixture struct {
	handler *control.NetmapHandler
	deriver *psk.Deriver
	self    *identity.Key
	selfH   string
	peerH   []string
	peers   *fakePeers
}

func newNetmapFixture(t *testing.T, peerCount int) *netFixture {
	t.Helper()

	db, err := gorm.Open(sqlite.Open("file:netmaptest?mode=memory&cache=shared"), &gorm.Config{Logger: logger.Discard})
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

	keys := func(seed byte) node.DataPlaneKeys {
		return node.DataPlaneKeys{
			KemPublicKey: validKemKey(seed),
			DhPublicKey:  bytes.Repeat([]byte{seed ^ 0xFF}, 32),
		}
	}

	self, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	selfH, err := nodes.Register(self.Public(), keys(1))
	if err != nil {
		t.Fatalf("register self: %v", err)
	}

	fp := &fakePeers{
		byKey:     map[string]*nbpeer.Peer{},
		accountOf: map[string]string{},
	}
	selfPeer := &nbpeer.Peer{
		ID: "peer-self", Key: selfH, AccountID: "acct",
		IP: netip.MustParseAddr("100.64.0.1"), DNSLabel: "self",
	}
	fp.byKey[selfH] = selfPeer
	fp.accountOf[selfH] = "acct"
	fp.list = append(fp.list, selfPeer)

	var peerH []string
	for i := 0; i < peerCount; i++ {
		k, err := identity.Generate()
		if err != nil {
			t.Fatalf("identity: %v", err)
		}
		h, err := nodes.Register(k.Public(), keys(byte(10+i)))
		if err != nil {
			t.Fatalf("register peer: %v", err)
		}
		p := &nbpeer.Peer{
			ID: "peer-" + h[:6], Key: h, AccountID: "acct",
			IP: netip.MustParseAddr("100.64.0." + itoa(2+i)), DNSLabel: "p" + itoa(i),
		}
		fp.byKey[h] = p
		fp.accountOf[h] = "acct"
		fp.list = append(fp.list, p)
		peerH = append(peerH, h)
	}

	master, err := psk.GenerateSoftwareMaster()
	if err != nil {
		t.Fatalf("master: %v", err)
	}
	deriver, err := psk.NewDeriver(master)
	if err != nil {
		t.Fatalf("deriver: %v", err)
	}

	return &netFixture{
		handler: &control.NetmapHandler{Nodes: nodes, Peers: fp, PSK: deriver, Epoch: 3},
		deriver: deriver,
		self:    self,
		selfH:   selfH,
		peerH:   peerH,
		peers:   fp,
	}
}

func itoa(i int) string {
	if i < 10 {
		return string(rune('0' + i))
	}
	return string(rune('0'+i/10)) + string(rune('0'+i%10))
}

func requestNetmap(t *testing.T, f *netFixture, known uint64) *proto.KarstNetmapResponse {
	t.Helper()
	payload, err := pb.Marshal(&proto.KarstNetmapRequest{KnownVersion: known})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	raw, err := f.handler.Handle(context.Background(), nil, f.self.Public(), payload)
	if err != nil {
		t.Fatalf("netmap: %v", err)
	}
	resp := &proto.KarstNetmapResponse{}
	if err := pb.Unmarshal(raw, resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return resp
}

func TestNetmapCarriesPeersAndKeys(t *testing.T) {
	f := newNetmapFixture(t, 3)
	resp := requestNetmap(t, f, 0)

	if len(resp.GetPeers()) != 3 {
		t.Fatalf("got %d peers, want 3", len(resp.GetPeers()))
	}
	if string(resp.GetNodeId()) != f.selfH {
		t.Fatal("netmap is not addressed to the requesting node")
	}
	if resp.GetPskEpoch() != 3 {
		t.Fatalf("psk epoch: got %d want 3", resp.GetPskEpoch())
	}
	for _, p := range resp.GetPeers() {
		if len(p.GetKemPublicKey()) != 1184 {
			t.Fatalf("kem key is %d bytes, want 1184", len(p.GetKemPublicKey()))
		}
		if len(p.GetDhPublicKey()) != 32 {
			t.Fatalf("dh key is %d bytes, want 32", len(p.GetDhPublicKey()))
		}
		if len(p.GetPsk()) != psk.Size {
			t.Fatalf("psk is %d bytes, want %d", len(p.GetPsk()), psk.Size)
		}
		if len(p.GetAllowedIps()) == 0 {
			t.Fatal("peer has no allowed IPs, so nothing would route to it")
		}
	}
}

// A node must never appear in its own netmap: it would derive a self-pair PSK,
// which psk.Pair refuses, and route its own address to itself.
func TestNetmapExcludesSelf(t *testing.T) {
	f := newNetmapFixture(t, 2)
	resp := requestNetmap(t, f, 0)
	for _, p := range resp.GetPeers() {
		if string(p.GetNodeId()) == f.selfH {
			t.Fatal("the requesting node appears in its own netmap")
		}
	}
}

// The decisive property: the PSK a node is given for a peer must equal the one
// that peer is given for it. If these disagree, every handshake between them
// fails, and it fails in a way that looks like a key mismatch.
func TestPSKAgreesWithTheOtherEnd(t *testing.T) {
	f := newNetmapFixture(t, 2)
	resp := requestNetmap(t, f, 0)

	for _, p := range resp.GetPeers() {
		peer := string(p.GetNodeId())
		// What the *peer* would be handed for us.
		mirrored, err := f.deriver.Pair(peer, f.selfH, 3)
		if err != nil {
			t.Fatalf("derive: %v", err)
		}
		if !bytes.Equal(p.GetPsk(), mirrored.Bytes()) {
			t.Fatalf("PSK disagrees between the two ends of pair (%s, %s)", f.selfH, peer)
		}
		disco, err := f.deriver.Disco(peer, f.selfH, 3)
		if err != nil {
			t.Fatalf("derive disco key: %v", err)
		}
		if !bytes.Equal(p.GetDiscoKey(), disco.Bytes()) {
			t.Fatalf("disco key disagrees between the two ends of pair (%s, %s)", f.selfH, peer)
		}
		if bytes.Equal(p.GetPsk(), p.GetDiscoKey()) {
			t.Fatalf("PSK and disco key are equal for pair (%s, %s)", f.selfH, peer)
		}
	}
}

func TestPSKsAreDistinctPerPeer(t *testing.T) {
	f := newNetmapFixture(t, 3)
	resp := requestNetmap(t, f, 0)

	seen := map[string]string{}
	for _, p := range resp.GetPeers() {
		k := string(p.GetPsk())
		if other, dup := seen[k]; dup {
			t.Fatalf("peers %s and %s were given the same PSK", other, p.GetNodeId())
		}
		seen[k] = string(p.GetNodeId())
	}
}

// The epoch must actually select a generation, or rotation is a no-op.
func TestEpochChangesEveryPSK(t *testing.T) {
	f := newNetmapFixture(t, 2)
	before := requestNetmap(t, f, 0)

	f.handler.Epoch = 4
	after := requestNetmap(t, f, 0)

	if after.GetPskEpoch() != 4 {
		t.Fatalf("epoch not reported: got %d", after.GetPskEpoch())
	}
	for i := range before.GetPeers() {
		if bytes.Equal(before.GetPeers()[i].GetPsk(), after.GetPeers()[i].GetPsk()) {
			t.Fatal("a PSK survived an epoch change")
		}
	}
}

// Peer ordering must be stable, or a node cannot tell a real change from map
// iteration order — which is what would make delta push impossible later.
func TestPeerOrderIsStable(t *testing.T) {
	f := newNetmapFixture(t, 4)
	first := requestNetmap(t, f, 0)
	for i := 0; i < 5; i++ {
		next := requestNetmap(t, f, 0)
		for j := range first.GetPeers() {
			if !bytes.Equal(first.GetPeers()[j].GetNodeId(), next.GetPeers()[j].GetNodeId()) {
				t.Fatal("peer order changed between identical requests")
			}
		}
	}
}

// A peer registered in the account but with no Karst data-plane keys cannot be
// handshaked with. Shipping it would produce an unusable entry and a PSK for a
// pair that cannot use it.
func TestPeersWithoutDataPlaneKeysAreOmitted(t *testing.T) {
	f := newNetmapFixture(t, 1)

	fp := f.handler.Peers.(*fakePeers)
	ghost := &nbpeer.Peer{
		ID: "peer-ghost", Key: "GHOSTaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=", AccountID: "acct",
		IP: netip.MustParseAddr("100.64.0.99"), DNSLabel: "ghost",
	}
	fp.byKey[ghost.Key] = ghost
	fp.list = append(fp.list, ghost)

	resp := requestNetmap(t, f, 0)
	for _, p := range resp.GetPeers() {
		if string(p.GetNodeId()) == ghost.Key {
			t.Fatal("a peer with no data-plane keys was shipped in the netmap")
		}
	}
	if len(resp.GetPeers()) != 1 {
		t.Fatalf("got %d peers, want 1", len(resp.GetPeers()))
	}
}

// The netmap is built from the authenticated identity, never from the request,
// so a node cannot ask for another node's netmap — and so cannot ask for PSKs
// it has no business holding.
func TestNetmapIsScopedToTheAuthenticatedIdentity(t *testing.T) {
	f := newNetmapFixture(t, 2)

	other, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	payload, err := pb.Marshal(&proto.KarstNetmapRequest{})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// An identity that is not registered gets nothing, regardless of what the
	// request says.
	if _, err := f.handler.Handle(context.Background(), []byte(f.selfH), other.Public(), payload); err == nil {
		t.Fatal("an unregistered identity was served a netmap")
	}
}

func TestMalformedNetmapRequestRejected(t *testing.T) {
	f := newNetmapFixture(t, 1)
	if _, err := f.handler.Handle(context.Background(), nil, f.self.Public(),
		[]byte{0xFF, 0xFF, 0xFF, 0xFF}); err == nil {
		t.Fatal("malformed request accepted")
	}
}

// The version must be a function of content, not of how many times it has been
// asked for. The implementation this replaced returned known_version+1, which
// changed on every request and so could never answer "has anything changed?".
func TestVersionIsContentDerived(t *testing.T) {
	f := newNetmapFixture(t, 3)

	first := requestNetmap(t, f, 0)
	second := requestNetmap(t, f, 0)
	if first.GetVersion() != second.GetVersion() {
		t.Fatal("identical netmaps produced different versions")
	}
	if first.GetVersion() == 0 {
		t.Fatal("version zero is reserved for 'I hold nothing'")
	}
}

func TestVersionChangesWithContent(t *testing.T) {
	f := newNetmapFixture(t, 2)
	base := requestNetmap(t, f, 0).GetVersion()

	t.Run("epoch rotation", func(t *testing.T) {
		f.handler.Epoch = 99
		defer func() { f.handler.Epoch = 3 }()
		if requestNetmap(t, f, 0).GetVersion() == base {
			t.Fatal("rotating the PSK epoch did not change the version")
		}
	})

	t.Run("peer added", func(t *testing.T) {
		fp := f.handler.Peers.(*fakePeers)
		saved := fp.list
		defer func() { fp.list = saved }()

		k, err := identity.Generate()
		if err != nil {
			t.Fatalf("identity: %v", err)
		}
		h, err := f.handler.Nodes.Register(k.Public(), node.DataPlaneKeys{
			KemPublicKey: validKemKey(0x77),
			DhPublicKey:  bytes.Repeat([]byte{0x88}, 32),
		})
		if err != nil {
			t.Fatalf("register: %v", err)
		}
		p := &nbpeer.Peer{ID: "peer-new", Key: h, AccountID: "acct",
			IP: netip.MustParseAddr("100.64.0.77"), DNSLabel: "new"}
		fp.byKey[h] = p
		fp.list = append(append([]*nbpeer.Peer{}, saved...), p)

		if requestNetmap(t, f, 0).GetVersion() == base {
			t.Fatal("adding a peer did not change the version")
		}
	})

	t.Run("peer removed", func(t *testing.T) {
		fp := f.handler.Peers.(*fakePeers)
		saved := fp.list
		defer func() { fp.list = saved }()
		fp.list = saved[:len(saved)-1]

		if requestNetmap(t, f, 0).GetVersion() == base {
			t.Fatal("removing a peer did not change the version")
		}
	})

	t.Run("relay registry changed", func(t *testing.T) {
		saved := f.handler.Relays
		defer func() { f.handler.Relays = saved }()
		f.handler.Relays = []*proto.KarstRelay{{
			Address:       "127.0.0.1:443",
			TlsServerName: "relay.test",
			RelayId:       bytes.Repeat([]byte{0x91}, 32),
			IdentityKey:   bytes.Repeat([]byte{0x92}, 2592),
			Region:        "test",
		}}

		if requestNetmap(t, f, 0).GetVersion() == base {
			t.Fatal("changing the relay registry did not change the version")
		}
		if requestNetmap(t, f, base).GetUnchanged() {
			// A node holding the pre-change version must receive the new relay
			// key; treating it as unchanged pins it to a retired relay forever.
			t.Fatal("a node holding the old relay registry was told nothing changed")
		}
	})
}

// A node that already holds the current version is told so and sent no peers,
// which is the whole point: re-shipping 1184-byte keys and a PSK per peer on
// every poll is pure waste.
func TestUnchangedShortCircuit(t *testing.T) {
	f := newNetmapFixture(t, 3)
	full := requestNetmap(t, f, 0)
	if len(full.GetPeers()) != 3 || full.GetUnchanged() {
		t.Fatal("the first fetch should be a full netmap")
	}

	again := requestNetmap(t, f, full.GetVersion())
	if !again.GetUnchanged() {
		t.Fatal("a matching known_version was not reported as unchanged")
	}
	if len(again.GetPeers()) != 0 {
		t.Fatalf("unchanged response carried %d peers", len(again.GetPeers()))
	}
	if again.GetVersion() != full.GetVersion() {
		t.Fatal("the version moved even though nothing changed")
	}
}

// "Unchanged" and "you have no peers" are different states. Conflating them
// would leave a node holding a peer that has been removed from the network,
// forever.
func TestUnchangedIsDistinctFromAnEmptyPeerList(t *testing.T) {
	f := newNetmapFixture(t, 0)
	resp := requestNetmap(t, f, 0)
	if resp.GetUnchanged() {
		t.Fatal("a genuinely empty netmap was reported as unchanged")
	}
	if len(resp.GetPeers()) != 0 {
		t.Fatal("expected no peers")
	}
	// And a node holding that version is then told nothing changed.
	again := requestNetmap(t, f, resp.GetVersion())
	if !again.GetUnchanged() {
		t.Fatal("re-asking with the empty netmap's version was not unchanged")
	}
}

// A stale version must produce the full netmap, not an unchanged response.
func TestStaleVersionGetsFullNetmap(t *testing.T) {
	f := newNetmapFixture(t, 2)
	resp := requestNetmap(t, f, 0xDEADBEEF)
	if resp.GetUnchanged() {
		t.Fatal("a stale version was reported as unchanged")
	}
	if len(resp.GetPeers()) != 2 {
		t.Fatalf("got %d peers, want 2", len(resp.GetPeers()))
	}
}

// The version travels in clear, so it must not be a function of secret
// material. A PSK is determined by (pair, epoch, master), so hashing the peer
// set and epoch detects the same changes without hashing the keys themselves.
func TestVersionDoesNotDependOnPSKBytes(t *testing.T) {
	f := newNetmapFixture(t, 2)
	before := requestNetmap(t, f, 0)

	// A different master changes every PSK but nothing else about the netmap.
	master, err := psk.GenerateSoftwareMaster()
	if err != nil {
		t.Fatalf("master: %v", err)
	}
	d, err := psk.NewDeriver(master)
	if err != nil {
		t.Fatalf("deriver: %v", err)
	}
	f.handler.PSK = d
	after := requestNetmap(t, f, 0)

	if bytes.Equal(before.GetPeers()[0].GetPsk(), after.GetPeers()[0].GetPsk()) {
		t.Fatal("changing the master did not change the PSKs; the test proves nothing")
	}
	if before.GetVersion() != after.GetVersion() {
		t.Fatal("the version changed with the PSK bytes, so it is derived from secret material")
	}
}

// phreatic-v1.md §7.3: "Responders MUST accept epoch n and n-1 and MUST reject
// any other." A netmap that ships only the current epoch cannot satisfy that,
// so a rotation would leave nodes unable to answer peers that have not
// refetched — and §7.3 resolves an absent PSK by falling back to all zeros,
// making the symptom a fleet-wide silent downgrade rather than an outage.
func TestNetmapCarriesBothEpochs(t *testing.T) {
	f := newNetmapFixture(t, 2)
	resp := requestNetmap(t, f, 0)

	for _, p := range resp.GetPeers() {
		if len(p.GetPsk()) != psk.Size {
			t.Fatalf("current psk is %d bytes", len(p.GetPsk()))
		}
		if len(p.GetPskPrevious()) != psk.Size {
			t.Fatalf("previous psk is %d bytes; a responder cannot accept epoch n-1", len(p.GetPskPrevious()))
		}
		if bytes.Equal(p.GetPsk(), p.GetPskPrevious()) {
			t.Fatal("the two epochs derived the same PSK, so rotation would be a no-op")
		}
	}
}

// The decisive rotation property: what a node is handed as `psk_previous`
// after a rotation must be exactly what it was handed as `psk` before it. If
// these disagree, a peer mid-rotation is rejected.
func TestRotationIsSeamless(t *testing.T) {
	f := newNetmapFixture(t, 2)

	before := requestNetmap(t, f, 0)
	f.handler.Epoch++
	after := requestNetmap(t, f, 0)

	if after.GetPskEpoch() != before.GetPskEpoch()+1 {
		t.Fatal("the epoch did not advance")
	}
	for i, p := range after.GetPeers() {
		old := before.GetPeers()[i]
		if !bytes.Equal(p.GetNodeId(), old.GetNodeId()) {
			t.Fatal("peer order changed across the rotation")
		}
		if !bytes.Equal(p.GetPskPrevious(), old.GetPsk()) {
			t.Fatal("psk_previous after rotation != psk before it: a peer that " +
				"has not refetched would be rejected")
		}
		if bytes.Equal(p.GetPsk(), old.GetPsk()) {
			t.Fatal("the current PSK did not change across a rotation")
		}
	}
}

// Both ends must agree on the previous epoch too, not just the current one.
func TestPreviousEpochPSKAlsoAgrees(t *testing.T) {
	f := newNetmapFixture(t, 2)
	resp := requestNetmap(t, f, 0)

	for _, p := range resp.GetPeers() {
		peer := string(p.GetNodeId())
		mirrored, err := f.deriver.Pair(peer, f.selfH, resp.GetPskEpoch()-1)
		if err != nil {
			t.Fatalf("derive: %v", err)
		}
		if !bytes.Equal(p.GetPskPrevious(), mirrored.Bytes()) {
			t.Fatal("the previous-epoch PSK disagrees between the two ends")
		}
	}
}

// Epoch 0 has no predecessor. Shipping zeros there would be indistinguishable
// from the all-zero fallback, which is a real and different security state.
func TestEpochZeroHasNoPrevious(t *testing.T) {
	f := newNetmapFixture(t, 1)
	f.handler.Epoch = 0
	resp := requestNetmap(t, f, 0)

	for _, p := range resp.GetPeers() {
		if len(p.GetPskPrevious()) != 0 {
			t.Fatal("epoch 0 shipped a previous PSK, which cannot exist")
		}
		if len(p.GetPsk()) != psk.Size {
			t.Fatal("epoch 0 has no current PSK")
		}
	}
}

// ── the ACL-derived packet filter (§4.3) ────────────────────────────────────

const netmapPolicy = `{
  "groups": { "group:all": ["u-self", "u-peer"] },
  "acls": [
    { "action": "accept", "src": ["group:all"], "dst": ["*:22,443"] }
  ]
}`

func withPolicy(t *testing.T, f *netFixture, src string) {
	t.Helper()
	d, err := policy.Parse([]byte(src))
	if err != nil {
		t.Fatalf("parse policy: %v", err)
	}
	f.handler.Policy = d
	// The compiler resolves group membership through the peer's user, so the
	// fixture's peers need one.
	fp := f.handler.Peers.(*fakePeers)
	for _, p := range fp.list {
		if p.Key == f.selfH {
			p.UserID = "u-self"
		} else {
			p.UserID = "u-peer"
		}
	}
}

func TestNetmapCarriesTheCompiledFilter(t *testing.T) {
	f := newNetmapFixture(t, 2)
	withPolicy(t, f, netmapPolicy)

	resp := requestNetmap(t, f, 0)
	if len(resp.GetPacketFilter()) == 0 {
		t.Fatal("the netmap carried no packet filter")
	}
	var ports []uint32
	for _, r := range resp.GetPacketFilter() {
		if len(r.GetSrcs()) == 0 {
			t.Fatal("a filter rule has no sources, which a permissive evaluator could read as 'any'")
		}
		for _, p := range r.GetPorts() {
			ports = append(ports, p.GetFirst())
		}
	}
	if len(ports) == 0 {
		t.Fatal("a filter rule has no ports")
	}
}

// No policy means an empty filter, which is default deny — never "unfiltered".
func TestNoPolicyMeansAnEmptyFilter(t *testing.T) {
	f := newNetmapFixture(t, 2)
	resp := requestNetmap(t, f, 0)
	if len(resp.GetPacketFilter()) != 0 {
		t.Fatalf("no policy produced %d filter rules", len(resp.GetPacketFilter()))
	}
}

// A policy edit must reach nodes that already hold a netmap. If the version
// did not cover the filter, every node would be told "unchanged" and the new
// rules would never arrive — an edit that appears to apply and does not.
func TestPolicyChangeBumpsTheVersion(t *testing.T) {
	f := newNetmapFixture(t, 2)
	withPolicy(t, f, netmapPolicy)
	before := requestNetmap(t, f, 0)

	withPolicy(t, f, `{
      "groups": { "group:all": ["u-self", "u-peer"] },
      "acls": [
        { "action": "accept", "src": ["group:all"], "dst": ["*:8080"] }
      ]
    }`)
	after := requestNetmap(t, f, 0)

	if after.GetVersion() == before.GetVersion() {
		t.Fatal("a policy change left the netmap version unchanged, so nodes " +
			"holding the old one would never be sent the new rules")
	}
	if requestNetmap(t, f, before.GetVersion()).GetUnchanged() {
		t.Fatal("a node holding the pre-change version was told nothing changed")
	}
}

// The filter must be scoped to the requesting node.
func TestFilterIsCompiledForTheRequestingNode(t *testing.T) {
	f := newNetmapFixture(t, 2)
	withPolicy(t, f, `{
      "groups": { "group:all": ["u-self", "u-peer"] },
      "acls": [
        { "action": "accept", "src": ["group:all"], "dst": ["`+f.selfH+`:22"] }
      ]
    }`)
	resp := requestNetmap(t, f, 0)
	if len(resp.GetPacketFilter()) == 0 {
		t.Fatal("a rule naming this node by handle produced no filter for it")
	}
}

// ── true delta push ─────────────────────────────────────────────────────────

// digestsOf builds the "what I hold" list a node would send after receiving
// a netmap.
func digestsOf(resp *proto.KarstNetmapResponse) []*proto.KarstPeerDigest {
	var out []*proto.KarstPeerDigest
	for _, p := range resp.GetPeers() {
		out = append(out, &proto.KarstPeerDigest{
			NodeId: p.GetNodeId(),
			Digest: control.PeerDigest(p, resp.GetPskEpoch()),
		})
	}
	return out
}

func requestDelta(t *testing.T, f *netFixture, holds []*proto.KarstPeerDigest) *proto.KarstNetmapResponse {
	t.Helper()
	payload, err := pb.Marshal(&proto.KarstNetmapRequest{Holds: holds})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	raw, err := f.handler.Handle(context.Background(), nil, f.self.Public(), payload)
	if err != nil {
		t.Fatalf("netmap: %v", err)
	}
	resp := &proto.KarstNetmapResponse{}
	if err := pb.Unmarshal(raw, resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return resp
}

// A node that holds everything current is sent nothing.
// ── home relay, ponor-v1.md §9.1 ────────────────────────────────────────────

// requestNetmapReporting polls as self while reporting a home relay.
func requestNetmapReporting(t *testing.T, f *netFixture, relay []byte) (*proto.KarstNetmapResponse, error) {
	t.Helper()
	payload, err := pb.Marshal(&proto.KarstNetmapRequest{HomeRelay: relay})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	raw, err := f.handler.Handle(context.Background(), nil, f.self.Public(), payload)
	if err != nil {
		return nil, err
	}
	resp := &proto.KarstNetmapResponse{}
	if err := pb.Unmarshal(raw, resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return resp, nil
}

// The report a node makes about itself is kept, and cleared when it withdraws.
//
// The node measured this; the server cannot. Dropping it would leave the field
// present on the wire in both directions and empty everywhere in between —
// which is exactly the state this replaces.
func TestReportedHomeRelayIsRecorded(t *testing.T) {
	f := newNetmapFixture(t, 2)
	relay := bytes.Repeat([]byte{0x5C}, 32)

	if _, err := requestNetmapReporting(t, f, relay); err != nil {
		t.Fatalf("netmap: %v", err)
	}
	rec, err := f.handler.Nodes.Get(f.selfH)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !bytes.Equal(rec.HomeRelay, relay) {
		t.Fatalf("stored %x, want %x", rec.HomeRelay, relay)
	}

	// A node that loses its relay reports none, and the record must follow it
	// down: peers left dialling a relay this node no longer holds reach
	// nothing, and a stale entry is indistinguishable from a live one.
	if _, err := requestNetmapReporting(t, f, nil); err != nil {
		t.Fatalf("netmap: %v", err)
	}
	rec, err = f.handler.Nodes.Get(f.selfH)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(rec.HomeRelay) != 0 {
		t.Fatalf("a withdrawn home relay is still stored as %x", rec.HomeRelay)
	}
}

// And it reaches the peers, which is the only reason to store it.
func TestHomeRelayReachesPeers(t *testing.T) {
	f := newNetmapFixture(t, 2)
	relay := bytes.Repeat([]byte{0xA3}, 32)
	if err := f.handler.Nodes.SetHomeRelay(f.peerH[0], relay); err != nil {
		t.Fatalf("set: %v", err)
	}

	resp := requestNetmap(t, f, 0)
	var seen bool
	for _, p := range resp.GetPeers() {
		if string(p.GetNodeId()) != f.peerH[0] {
			if len(p.GetHomeRelay()) != 0 {
				t.Fatalf("a peer holding no relay was given one: %x", p.GetHomeRelay())
			}
			continue
		}
		seen = true
		if !bytes.Equal(p.GetHomeRelay(), relay) {
			t.Fatalf("peer carries %x, want %x", p.GetHomeRelay(), relay)
		}
	}
	if !seen {
		t.Fatal("the peer that reported a relay was not in the netmap")
	}
}

// A move must be delivered. The digest and the version both cover the field,
// so a peer that changes relay comes back in the delta — without that, the
// server answers "unchanged" forever and every other node keeps dialling a
// relay the peer has left.
func TestHomeRelayMoveIsDelivered(t *testing.T) {
	f := newNetmapFixture(t, 3)
	full := requestNetmap(t, f, 0)
	holds := digestsOf(full)

	target := string(full.GetPeers()[1].GetNodeId())
	if err := f.handler.Nodes.SetHomeRelay(target, bytes.Repeat([]byte{0x77}, 32)); err != nil {
		t.Fatalf("set: %v", err)
	}

	d := requestDelta(t, f, holds)
	if len(d.GetPeers()) != 1 {
		t.Fatalf("got %d changed peers, want 1", len(d.GetPeers()))
	}
	if string(d.GetPeers()[0].GetNodeId()) != target {
		t.Fatal("the wrong peer was sent")
	}
	if !bytes.Equal(d.GetPeers()[0].GetHomeRelay(), bytes.Repeat([]byte{0x77}, 32)) {
		t.Fatalf("the moved relay was not delivered: %x", d.GetPeers()[0].GetHomeRelay())
	}
}

// A value that cannot be a relay id is refused rather than stored.
//
// Silently ignoring it would leave the node believing it had published a relay
// while its peers dialled the old one — unreachable, with nothing anywhere
// saying why.
func TestMalformedHomeRelayIsRefused(t *testing.T) {
	f := newNetmapFixture(t, 1)
	if _, err := requestNetmapReporting(t, f, []byte{1, 2, 3}); err == nil {
		t.Fatal("a 3-byte home relay id was accepted")
	}
	// And the refusal is of that field rather than of the node: a well-formed
	// report still works afterwards.
	if _, err := requestNetmapReporting(t, f, bytes.Repeat([]byte{9}, 32)); err != nil {
		t.Fatalf("a well-formed report was refused: %v", err)
	}
}

func TestDeltaSendsNothingWhenUpToDate(t *testing.T) {
	f := newNetmapFixture(t, 3)
	full := requestNetmap(t, f, 0)

	d := requestDelta(t, f, digestsOf(full))
	if !d.GetDelta() {
		t.Fatal("a request carrying digests was not answered with a delta")
	}
	if len(d.GetPeers()) != 0 {
		t.Fatalf("an up-to-date node was re-sent %d peers", len(d.GetPeers()))
	}
	if len(d.GetRemovedPeers()) != 0 {
		t.Fatalf("an up-to-date node was told to remove %d peers", len(d.GetRemovedPeers()))
	}
}

// A changed peer comes back, and only that peer.
func TestDeltaSendsOnlyWhatChanged(t *testing.T) {
	f := newNetmapFixture(t, 3)
	full := requestNetmap(t, f, 0)
	holds := digestsOf(full)

	// Change one peer's DNS label.
	target := string(full.GetPeers()[1].GetNodeId())
	fp := f.handler.Peers.(*fakePeers)
	fp.byKey[target].DNSLabel = "renamed"

	d := requestDelta(t, f, holds)
	if len(d.GetPeers()) != 1 {
		t.Fatalf("got %d changed peers, want 1", len(d.GetPeers()))
	}
	if string(d.GetPeers()[0].GetNodeId()) != target {
		t.Fatal("the wrong peer was sent")
	}
	if d.GetPeers()[0].GetDnsName() != "renamed" {
		t.Fatal("the change was not reflected")
	}
}

// A peer that has gone away is named for removal, not silently omitted — a
// node cannot tell "absent because unchanged" from "absent because gone".
func TestDeltaNamesRemovedPeers(t *testing.T) {
	f := newNetmapFixture(t, 3)
	full := requestNetmap(t, f, 0)
	holds := digestsOf(full)

	gone := string(full.GetPeers()[0].GetNodeId())
	fp := f.handler.Peers.(*fakePeers)
	var kept []*nbpeer.Peer
	for _, p := range fp.list {
		if p.Key != gone {
			kept = append(kept, p)
		}
	}
	fp.list = kept

	d := requestDelta(t, f, holds)
	if len(d.GetRemovedPeers()) != 1 {
		t.Fatalf("got %d removals, want 1", len(d.GetRemovedPeers()))
	}
	if string(d.GetRemovedPeers()[0]) != gone {
		t.Fatal("the wrong peer was named for removal")
	}
	if len(d.GetPeers()) != 0 {
		t.Fatalf("unchanged peers were re-sent alongside the removal")
	}
}

// A brand-new peer arrives as a change, since the node holds no digest for it.
func TestDeltaSendsNewPeers(t *testing.T) {
	f := newNetmapFixture(t, 2)
	full := requestNetmap(t, f, 0)
	holds := digestsOf(full)

	k, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	h, err := f.handler.Nodes.Register(k.Public(), node.DataPlaneKeys{
		KemPublicKey: validKemKey(0x55),
		DhPublicKey:  bytes.Repeat([]byte{0x66}, 32),
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	fp := f.handler.Peers.(*fakePeers)
	p := &nbpeer.Peer{ID: "peer-new", Key: h, AccountID: "acct",
		IP: netip.MustParseAddr("100.64.0.44"), DNSLabel: "new"}
	fp.byKey[h] = p
	fp.list = append(fp.list, p)

	d := requestDelta(t, f, holds)
	if len(d.GetPeers()) != 1 || string(d.GetPeers()[0].GetNodeId()) != h {
		t.Fatalf("the new peer was not sent: %d peers", len(d.GetPeers()))
	}
	if len(d.GetPeers()[0].GetPsk()) != psk.Size {
		t.Fatal("the new peer arrived without a PSK")
	}
}

// A rotation must invalidate every digest, or nodes keep stale PSKs.
func TestEpochRotationInvalidatesEveryDigest(t *testing.T) {
	f := newNetmapFixture(t, 3)
	full := requestNetmap(t, f, 0)
	holds := digestsOf(full)

	f.handler.Epoch++
	d := requestDelta(t, f, holds)
	if len(d.GetPeers()) != 3 {
		t.Fatalf("after a rotation %d of 3 peers were resent; the rest would "+
			"keep a stale PSK", len(d.GetPeers()))
	}
	for _, p := range d.GetPeers() {
		if len(p.GetPsk()) != psk.Size || len(p.GetPskPrevious()) != psk.Size {
			t.Fatal("a rotated entry arrived without both epochs")
		}
	}
}

// Applying a delta must converge on exactly the full netmap. The version is
// computed over the complete set, so a node that applies the delta and
// recomputes can check it agrees — and the server's own version must not
// change just because the answer was a delta.
func TestDeltaConvergesOnTheFullNetmap(t *testing.T) {
	f := newNetmapFixture(t, 4)
	full := requestNetmap(t, f, 0)

	fp := f.handler.Peers.(*fakePeers)
	fp.byKey[string(full.GetPeers()[0].GetNodeId())].DNSLabel = "changed"

	after := requestNetmap(t, f, 0)
	d := requestDelta(t, f, digestsOf(full))

	if d.GetVersion() != after.GetVersion() {
		t.Fatal("the delta's version disagrees with the full netmap it should converge on")
	}

	// Apply the delta to what the node held.
	held := map[string]*proto.KarstNetmapPeer{}
	for _, p := range full.GetPeers() {
		held[string(p.GetNodeId())] = p
	}
	for _, p := range d.GetPeers() {
		held[string(p.GetNodeId())] = p
	}
	for _, id := range d.GetRemovedPeers() {
		delete(held, string(id))
	}

	if len(held) != len(after.GetPeers()) {
		t.Fatalf("after applying the delta the node holds %d peers, server has %d",
			len(held), len(after.GetPeers()))
	}
	for _, want := range after.GetPeers() {
		got, ok := held[string(want.GetNodeId())]
		if !ok {
			t.Fatalf("peer %s missing after applying the delta", want.GetNodeId())
		}
		if got.GetDnsName() != want.GetDnsName() {
			t.Fatalf("peer %s did not converge: %q vs %q",
				want.GetNodeId(), got.GetDnsName(), want.GetDnsName())
		}
	}
}

// A digest for a peer the node was never entitled to is simply named for
// removal: it cannot be used to fish for entries.
func TestUnknownDigestIsAnInstructionToRemove(t *testing.T) {
	f := newNetmapFixture(t, 2)
	full := requestNetmap(t, f, 0)
	holds := append(digestsOf(full), &proto.KarstPeerDigest{
		NodeId: []byte("a-peer-in-another-account"), Digest: 1234,
	})

	d := requestDelta(t, f, holds)
	if len(d.GetPeers()) != 0 {
		t.Fatal("an invented digest caused peers to be sent")
	}
	if len(d.GetRemovedPeers()) != 1 || string(d.GetRemovedPeers()[0]) != "a-peer-in-another-account" {
		t.Fatal("an invented digest was not simply named for removal")
	}
}

// An empty holds list means "send everything", and must not be mistaken for
// "I hold nothing, therefore everything is removed".
func TestNoDigestsMeansFullNetmap(t *testing.T) {
	f := newNetmapFixture(t, 3)
	resp := requestDelta(t, f, nil)
	if resp.GetDelta() {
		t.Fatal("a request with no digests was answered with a delta")
	}
	if len(resp.GetPeers()) != 3 {
		t.Fatalf("got %d peers, want the full set of 3", len(resp.GetPeers()))
	}
}

// A delta must not carry the same PSKs as an unchanged entry would; every
// entry sent is complete and usable on its own.
func TestDeltaEntriesAreComplete(t *testing.T) {
	f := newNetmapFixture(t, 2)
	full := requestNetmap(t, f, 0)
	holds := digestsOf(full)

	target := string(full.GetPeers()[0].GetNodeId())
	f.handler.Peers.(*fakePeers).byKey[target].DNSLabel = "x"

	d := requestDelta(t, f, holds)
	if len(d.GetPeers()) != 1 {
		t.Fatalf("got %d peers", len(d.GetPeers()))
	}
	p := d.GetPeers()[0]
	if len(p.GetKemPublicKey()) != 1184 || len(p.GetDhPublicKey()) != 32 {
		t.Fatal("a delta entry omitted the PHREATIC keys")
	}
	if len(p.GetPsk()) != psk.Size || len(p.GetAllowedIps()) == 0 {
		t.Fatal("a delta entry is not self-contained")
	}
}

// ── the node's own addresses ────────────────────────────────────────────────

// **The address a node assigns to its interface must carry the on-link prefix.**
//
// A bare address is a /32: the interface comes up, the node has an address,
// and no peer is on-link — so nothing routes and every packet is dropped
// before it reaches the tunnel. The symptom looks exactly like a handshake
// failure, which is a long way from the cause.
//
// Note the deliberate asymmetry with a peer's allowed_ips, which *is* a
// single-host prefix: that states which addresses a peer owns, this states
// which addresses are reachable over the interface.
func TestTheNodesOwnAddressCarriesTheOnLinkPrefix(t *testing.T) {
	f := newNetmapFixture(t, 1)
	resp := requestNetmap(t, f, 0)

	addrs := resp.GetAddresses()
	if len(addrs) == 0 {
		t.Fatal("the netmap carries no address for the node")
	}
	if addrs[0] != "100.64.0.1/16" {
		t.Fatalf("address %q: want the account's /16, not a bare address or a /32", addrs[0])
	}

	for _, p := range resp.GetPeers() {
		for _, ip := range p.GetAllowedIps() {
			if !strings.HasSuffix(ip, "/32") && !strings.HasSuffix(ip, "/128") {
				t.Fatalf("peer allowed_ip %q is not a single host; a peer owns "+
					"addresses, it does not define the on-link prefix", ip)
			}
		}
	}
}

// If the account's network cannot be read, the netmap fails. It must not fall
// back to a bare address: that produces a node that comes up, reports itself
// healthy, and cannot reach anything.
func TestAnUnreadableAccountNetworkIsFatalRatherThanADegradedAddress(t *testing.T) {
	f := newNetmapFixture(t, 1)
	f.peers.prefixErr = errors.New("network unavailable")

	payload, err := pb.Marshal(&proto.KarstNetmapRequest{})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := f.handler.Handle(context.Background(), nil, f.self.Public(), payload); err == nil {
		t.Fatal("a netmap was produced without the account's prefix")
	}
}

// A change of prefix is a change of netmap, so it must move the version — or
// nodes would be told "unchanged" and keep an interface that cannot reach
// their peers.
func TestChangingTheOnLinkPrefixChangesTheVersion(t *testing.T) {
	f := newNetmapFixture(t, 1)
	before := requestNetmap(t, f, 0).GetVersion()

	f.peers.narrowPrefix = true
	after := requestNetmap(t, f, 0).GetVersion()

	if before == after {
		t.Fatal("the on-link prefix is not part of the netmap version")
	}
}

// validKemKey makes a real ML-KEM-768 encapsulation key.
//
// A 1184-byte pattern is not one: FIPS 203 requires every 12-bit coefficient to
// be below q, and node.Register now checks that rather than only the length —
// because a key that does not parse is shipped to every peer in the account and
// none of them can handshake with it.
func validKemKey(seed byte) []byte {
	var s [64]byte
	for i := range s {
		s[i] = seed + byte(i)
	}
	dk, err := mlkem.NewDecapsulationKey768(s[:])
	if err != nil {
		panic("mlkem seed: " + err.Error())
	}
	return dk.EncapsulationKey().Bytes()
}

// ── the Bedrock disclosure gate ─────────────────────────────────────────────

// stubBedrock stands in for the account's log. It reports a fixed mode and a
// fixed covered set, because what is under test is the handler's gate and not
// the chain verification that produces the set — that has its own tests.
type stubBedrock struct {
	mode     proto.KarstBedrockMode
	state    *bedrock.State
	stateErr error
}

func (s *stubBedrock) Head(context.Context, string) ([]byte, uint64, error) {
	if s.state == nil {
		return nil, 0, bedrock.ErrNoLog
	}
	return s.state.Head, s.state.HeadSeq, nil
}

func (s *stubBedrock) State(context.Context, string) (*bedrock.State, error) {
	if s.stateErr != nil {
		return nil, s.stateErr
	}
	return s.state, nil
}

func (s *stubBedrock) Mode(context.Context, string) proto.KarstBedrockMode { return s.mode }

// coveringState builds a State that covers exactly the given handles, with the
// data-plane keys the node store holds for each.
func coveringState(t *testing.T, f *netFixture, handles ...string) *bedrock.State {
	t.Helper()
	st := &bedrock.State{
		Covered: map[string]bedrock.NodeCoverage{},
		Revoked: map[string]int64{},
		Head:    bytes.Repeat([]byte{0xAA}, 64),
		HeadSeq: 1,
	}
	for _, h := range handles {
		id, err := f.handler.Nodes.Get(h)
		if err != nil {
			t.Fatalf("get %s: %v", h, err)
		}
		st.Covered[h] = bedrock.NodeCoverage{
			Handle:       h,
			IdentityKey:  id.PublicKey,
			KemPublicKey: id.KemPublicKey,
			DhPublicKey:  id.DhPublicKey,
		}
	}
	return st
}

func netmapErr(t *testing.T, f *netFixture) error {
	t.Helper()
	payload, err := pb.Marshal(&proto.KarstNetmapRequest{})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	_, err = f.handler.Handle(context.Background(), nil, f.self.Public(), payload)
	return err
}

// **The disclosure the gate exists to stop.** A netmap carries every peer's
// keys, addresses and a per-pair PSK, so handing one to a node the log does not
// cover leaks the shape of the network — and its PSKs — to whoever presented a
// setup key.
func TestEnforcingRefusesANetmapToAnUncoveredNode(t *testing.T) {
	f := newNetmapFixture(t, 2)
	stub := &stubBedrock{
		mode:  proto.KarstBedrockMode_KARST_BEDROCK_MODE_ENFORCING,
		state: coveringState(t, f), // covers nobody
	}
	f.handler.Bedrock = stub
	f.handler.BedrockMode = stub

	err := netmapErr(t, f)
	if err == nil {
		t.Fatal("an uncovered node was served a netmap under enforcement")
	}
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("code = %v, want PermissionDenied", status.Code(err))
	}
	if !strings.Contains(err.Error(), "countersigned") {
		t.Errorf("the refusal does not say why: %v", err)
	}
}

func TestEnforcingServesACoveredNode(t *testing.T) {
	f := newNetmapFixture(t, 2)
	stub := &stubBedrock{
		mode:  proto.KarstBedrockMode_KARST_BEDROCK_MODE_ENFORCING,
		state: coveringState(t, f, f.selfH),
	}
	f.handler.Bedrock = stub
	f.handler.BedrockMode = stub

	if err := netmapErr(t, f); err != nil {
		t.Fatalf("a covered node was refused: %v", err)
	}
}

// This uses a real root-and-authority signed log rather than manufacturing a
// coverage map. It joins the signing semantics to the netmap disclosure gate:
// the node admitted under enforcing is covered by exactly the static keys it
// presented when enrolling.
func TestEnforcingServesNodeCoveredByARealBedrockCeremony(t *testing.T) {
	f := newNetmapFixture(t, 2)
	root, err := bedrock.GenerateRoot()
	if err != nil {
		t.Fatalf("root: %v", err)
	}
	authority, err := bedrock.GenerateAuthority()
	if err != nil {
		t.Fatalf("authority: %v", err)
	}
	builder := bedrock.NewBuilder()
	genesis, input := builder.Prepare(1000, bedrock.OpGenesis, bedrock.GenesisBody("test.karst.", [][]byte{root.Public()}, 1, [][]byte{authority.Public()}, 1))
	rootSigs, err := bedrock.SignRoots(input, bedrock.RootSigner{Index: 0, Key: root})
	if err != nil {
		t.Fatalf("sign genesis: %v", err)
	}
	if err := builder.Commit(genesis, rootSigs); err != nil {
		t.Fatalf("commit genesis: %v", err)
	}
	identity, err := f.handler.Nodes.Get(f.selfH)
	if err != nil {
		t.Fatalf("self identity: %v", err)
	}
	nodeSign, input := builder.Prepare(1100, bedrock.OpNodeSign, bedrock.NodeSignBody(f.selfH, identity.PublicKey, identity.KemPublicKey, identity.DhPublicKey, 0, 0))
	authoritySigs, err := bedrock.SignAuthorities(input, bedrock.AuthoritySigner{Index: 0, Key: authority})
	if err != nil {
		t.Fatalf("sign node: %v", err)
	}
	if err := builder.Commit(nodeSign, authoritySigs); err != nil {
		t.Fatalf("commit node: %v", err)
	}
	state, err := builder.Verify()
	if err != nil {
		t.Fatalf("verify ceremony: %v", err)
	}
	stub := &stubBedrock{mode: proto.KarstBedrockMode_KARST_BEDROCK_MODE_ENFORCING, state: state}
	f.handler.Bedrock = stub
	f.handler.BedrockMode = stub
	if err := netmapErr(t, f); err != nil {
		t.Fatalf("ceremony-covered node was refused: %v", err)
	}
}

// The complementary outcome must come from the same verified-log path: a
// valid genesis alone establishes a lock, but it does not silently cover a
// newly enrolled node merely because the server knows that node's identity.
func TestEnforcingRefusesNodeAbsentFromARealBedrockCeremony(t *testing.T) {
	f := newNetmapFixture(t, 2)
	root, err := bedrock.GenerateRoot()
	if err != nil {
		t.Fatalf("root: %v", err)
	}
	authority, err := bedrock.GenerateAuthority()
	if err != nil {
		t.Fatalf("authority: %v", err)
	}
	builder := bedrock.NewBuilder()
	genesis, input := builder.Prepare(1000, bedrock.OpGenesis, bedrock.GenesisBody("test.karst.", [][]byte{root.Public()}, 1, [][]byte{authority.Public()}, 1))
	rootSigs, err := bedrock.SignRoots(input, bedrock.RootSigner{Index: 0, Key: root})
	if err != nil {
		t.Fatalf("sign genesis: %v", err)
	}
	if err := builder.Commit(genesis, rootSigs); err != nil {
		t.Fatalf("commit genesis: %v", err)
	}
	state, err := builder.Verify()
	if err != nil {
		t.Fatalf("verify ceremony: %v", err)
	}
	stub := &stubBedrock{mode: proto.KarstBedrockMode_KARST_BEDROCK_MODE_ENFORCING, state: state}
	f.handler.Bedrock = stub
	f.handler.BedrockMode = stub
	if err := netmapErr(t, f); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("uncovered node error code = %v, want PermissionDenied; err=%v", status.Code(err), err)
	}
}

// **Advisory must not cut anyone off.** That is the entire reason the mode
// exists: an operator sees what enforcement would do before it does it. A
// server that refused netmaps in advisory mode would do the thing advisory is
// for avoiding.
func TestAdvisoryStillServesAnUncoveredNode(t *testing.T) {
	f := newNetmapFixture(t, 2)
	stub := &stubBedrock{
		mode:  proto.KarstBedrockMode_KARST_BEDROCK_MODE_ADVISORY,
		state: coveringState(t, f),
	}
	f.handler.Bedrock = stub
	f.handler.BedrockMode = stub

	if err := netmapErr(t, f); err != nil {
		t.Fatalf("advisory mode refused a netmap: %v", err)
	}
}

func TestOffStillServesAnUncoveredNode(t *testing.T) {
	f := newNetmapFixture(t, 2)
	stub := &stubBedrock{
		mode:  proto.KarstBedrockMode_KARST_BEDROCK_MODE_OFF,
		state: coveringState(t, f),
	}
	f.handler.Bedrock = stub
	f.handler.BedrockMode = stub

	if err := netmapErr(t, f); err != nil {
		t.Fatalf("mode off refused a netmap: %v", err)
	}
}

// Enforcing with no log covers nobody, so every node is refused. That is a
// severe outcome and the correct reading; the test exists so it is a decision
// on the record rather than something discovered during an outage.
func TestEnforcingWithNoLogRefusesEveryone(t *testing.T) {
	f := newNetmapFixture(t, 2)
	stub := &stubBedrock{
		mode:     proto.KarstBedrockMode_KARST_BEDROCK_MODE_ENFORCING,
		stateErr: bedrock.ErrNoLog,
	}
	f.handler.Bedrock = stub
	f.handler.BedrockMode = stub

	err := netmapErr(t, f)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code = %v, want PermissionDenied", status.Code(err))
	}
	if !strings.Contains(err.Error(), "no log") {
		t.Errorf("the refusal does not name the cause: %v", err)
	}
}

// A root-signed `disable` retires the mechanism, so the gate stands down with
// it. Anything else would leave enforcement half-on: no netmaps, and no way to
// turn that off short of editing the database.
func TestADisabledLogStandsTheGateDown(t *testing.T) {
	f := newNetmapFixture(t, 2)
	state := coveringState(t, f) // covers nobody
	state.Disabled = true
	stub := &stubBedrock{
		mode:  proto.KarstBedrockMode_KARST_BEDROCK_MODE_ENFORCING,
		state: state,
	}
	f.handler.Bedrock = stub
	f.handler.BedrockMode = stub

	if err := netmapErr(t, f); err != nil {
		t.Fatalf("a disabled log still refused a netmap: %v", err)
	}
}

// A server with no Bedrock configured at all is the common case and must be
// untouched by any of this.
func TestNoBedrockConfiguredIsUnaffected(t *testing.T) {
	f := newNetmapFixture(t, 2)
	if err := netmapErr(t, f); err != nil {
		t.Fatalf("a server without Bedrock refused a netmap: %v", err)
	}
}
