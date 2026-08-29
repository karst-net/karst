// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package main

import (
	"context"
	"crypto/mlkem"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sync"

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

// The netmap fixture: the *real* LoginHandler and NetmapHandler over an
// in-memory account.
//
// The account manager is stood in for, because standing up the fork's real one
// needs a SQL fixture, a metrics registry and four managers — and what is under
// test here is the node side of the wire, not the fork's business layer, which
// has its own tests (TestRegistrationAgainstTheRealAccountManager).
//
// Everything else is production code: the node store, the PSK deriver, the ACL
// compiler, the netmap assembly, the version hash and the request router. A
// Rust node driven against this exercises the whole pipeline it would use
// against a real deployment.

// The account's overlay allocation, matching what the fork hands out: a /16 out
// of 100.64.0.0/10 and a /64 ULA.
const (
	fixtureV4Bits = 16
	fixtureV6Bits = 64
)

type memoryAccount struct {
	mu    sync.Mutex
	peers map[string]*nbpeer.Peer
	order []string
	next  int
}

func newMemoryAccount() *memoryAccount {
	return &memoryAccount{peers: map[string]*nbpeer.Peer{}, next: 1}
}

// register adds a peer, assigning the next free address. Returns its assigned
// IP so the login response can carry it.
func (m *memoryAccount) register(handle, hostname string) *nbpeer.Peer {
	m.mu.Lock()
	defer m.mu.Unlock()

	if p, ok := m.peers[handle]; ok {
		return p
	}
	m.next++
	p := &nbpeer.Peer{
		ID:        fmt.Sprintf("peer-%d", m.next),
		Key:       handle,
		AccountID: "fixture-account",
		UserID:    "fixture-user",
		DNSLabel:  hostname,
		IP:        netip.AddrFrom4([4]byte{100, 64, 0, byte(m.next)}),
	}
	m.peers[handle] = p
	m.order = append(m.order, handle)
	return p
}

// remove deletes a peer, the way deprovisioning a user or revoking a device
// does. It reports whether anything was there.
//
// The netmap handler recomputes from this map on every request, so the removal
// is visible to every *other* node the moment their next netmap is assembled —
// which is precisely the latency plans/phase-5/08-scim-and-groups.md §2 is
// about, and what `a_revoked_peer_loses_its_session` measures.
func (m *memoryAccount) remove(handle string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.peers[handle]; !ok {
		return false
	}
	delete(m.peers, handle)
	for i, h := range m.order {
		if h == handle {
			m.order = append(m.order[:i], m.order[i+1:]...)
			break
		}
	}
	return true
}

// listing is one row of the control surface's peer list.
type listing struct {
	Handle string `json:"handle"`
	Label  string `json:"label"`
	IP     string `json:"ip"`
}

// list returns the account's peers in registration order.
//
// The end-to-end test needs to name a specific device to revoke, and the only
// identifier it can see from the outside is the overlay address its peer holds
// — `karst status` prints allowed_ips and not handles. Both aquifer nodes run
// on one machine and therefore register the same hostname, so the label cannot
// discriminate either. The address can.
func (m *memoryAccount) list() []listing {
	m.mu.Lock()
	defer m.mu.Unlock()

	out := make([]listing, 0, len(m.order))
	for _, handle := range m.order {
		p, ok := m.peers[handle]
		if !ok {
			continue
		}
		out = append(out, listing{Handle: handle, Label: p.DNSLabel, IP: p.IP.String()})
	}
	return out
}

// ── control.PeerLoginer ─────────────────────────────────────────────────────

func (m *memoryAccount) GetAccountIDForPeerKey(_ context.Context, key string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.peers[key]; !ok {
		return "", errors.New("no such peer")
	}
	return "fixture-account", nil
}

func (m *memoryAccount) GetPeerByPeerPubKey(_ context.Context, key string) (*nbpeer.Peer, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.peers[key]
	if !ok {
		return nil, errors.New("no such peer")
	}
	return p, nil
}

func (m *memoryAccount) GetPeersFromAccount(_ context.Context, _, _, _ string) ([]*nbpeer.Peer, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*nbpeer.Peer, 0, len(m.order))
	for _, h := range m.order {
		out = append(out, m.peers[h])
	}
	return out, nil
}

func (m *memoryAccount) AccountPrefixes(context.Context, string) (uint8, uint8, error) {
	return fixtureV4Bits, fixtureV6Bits, nil
}

// ── the router ──────────────────────────────────────────────────────────────

// Kinds must match bootstrap's: they are on the wire.
const (
	kindLogin   byte = 1
	kindNetmap  byte = 2
	kindBedrock byte = 3
)

type router struct {
	login   *control.LoginHandler
	netmap  *control.NetmapHandler
	bedrock *control.BedrockHandler
	// bedrockFixture countersigns nodes as they register, when Bedrock is on.
	bedrockFixture *bedrockFixture
	// coverPreloaded is how many of the preloaded peers get countersigned. The
	// rest stay uncovered on purpose, so a test has something to be excluded.
	coverPreloaded int
	// account is consulted directly for registration, because the fixture
	// stands in for the account manager the LoginHandler would call.
	account *memoryAccount
	nodes   *node.Store
}

func (r *router) Handle(ctx context.Context, nodeID, identityPub, payload []byte) ([]byte, error) {
	if len(payload) == 0 {
		return nil, errors.New("empty request")
	}
	kind, body := payload[0], payload[1:]
	switch kind {
	case kindLogin:
		return r.handleLogin(ctx, identityPub, body)
	case kindNetmap:
		return r.netmap.Handle(ctx, nodeID, identityPub, body)
	case kindBedrock:
		if r.bedrock == nil {
			return nil, errors.New("bedrock is not configured on this fixture")
		}
		return r.bedrock.Handle(ctx, nodeID, identityPub, body)
	default:
		return nil, fmt.Errorf("unknown request kind %d", kind)
	}
}

// buildNetmapServer assembles the fixture. `preload` peers are registered up
// front so a node's first netmap is not empty.
// relayEntries builds the Phase 4 relay registry this server advertises.
//
// By default it is a single placeholder with the right *shape*: the identity
// need only have the ML-DSA-87 public-key width, because what the default
// exercises is that the registry crosses the authenticated control channel and
// that the node re-derives the relay id while decoding it.
//
// `--relay <addr> <hex-identity-pk>` replaces it with a real one, which is what
// an end-to-end test needs: a node cannot connect to a relay whose advertised
// key is a pattern of 0x91, and the relay id is *derived* from the key (§5.2)
// so it cannot be supplied separately without inviting a mismatch.
//
// The flag may be repeated, and **order is meaningful**: a node with nothing
// measured yet holds the first entry, so a test that wants two nodes to start
// on the same relay lists that one first.
func relayEntries() []*proto.KarstRelay {
	var relays []*proto.KarstRelay

	args := os.Args[1:]
	for i, a := range args {
		if a != "--relay" || i+2 >= len(args) {
			continue
		}
		key, err := hex.DecodeString(args[i+2])
		if err != nil {
			// A misspelled key would otherwise surface as a node that cannot
			// connect to a relay that is running perfectly.
			panic(fmt.Sprintf("--relay identity key is not hex: %v", err))
		}
		relays = append(relays, relayRow(args[i+1], key))
	}
	if len(relays) == 0 {
		relays = append(relays, relayRow("127.0.0.1:443", pattern(2592, 0x91)))
	}
	return relays
}

func relayRow(address string, key []byte) *proto.KarstRelay {
	h := sha256.New()
	_, _ = h.Write([]byte("karst-relay-id-v1"))
	_, _ = h.Write(key)
	return &proto.KarstRelay{
		Address:       address,
		TlsServerName: "relay.test",
		RelayId:       h.Sum(nil),
		IdentityKey:   key,
		Region:        "test",
	}
}

func buildNetmapServer(preload int, dnsZone string) (*router, error) {
	db, err := gorm.Open(sqlite.Open("file:karst-testserver?mode=memory&cache=shared"),
		&gorm.Config{Logger: logger.Discard})
	if err != nil {
		return nil, fmt.Errorf("db: %w", err)
	}
	nodes, err := node.NewStore(db)
	if err != nil {
		return nil, fmt.Errorf("node store: %w", err)
	}

	master, err := psk.GenerateSoftwareMaster()
	if err != nil {
		return nil, fmt.Errorf("psk master: %w", err)
	}
	deriver, err := psk.NewDeriver(master)
	if err != nil {
		return nil, fmt.Errorf("psk deriver: %w", err)
	}

	account := newMemoryAccount()

	// A policy the Rust side can check it received: the preloaded peers may
	// reach this node on 22, and nothing else may reach it at all.
	doc, err := policy.Parse([]byte(`{
	  "acls": [ { "action": "accept", "src": ["*"], "dst": ["*:22"] } ]
	}`))
	if err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}

	r := &router{
		netmap: &control.NetmapHandler{
			Nodes: nodes, Peers: account, PSK: deriver, Epoch: 7, Policy: doc,
			DNSZone: dnsZone,
		},
		account: account,
		nodes:   nodes,
	}
	r.netmap.Relays = relayEntries()

	// A prebuilt Bedrock log is the cross-implementation path: Rust produces
	// the bytes an offline ceremony would import and this Go server only
	// distributes them.  In particular, it must not quietly re-sign a node at
	// registration time, or an enforcement test would be exercising a fixture
	// privilege production deliberately does not have.
	if path, mode, ok := externalBedrockLog(); ok {
		if _, _, _, fixtureOK := bedrockMode(); fixtureOK {
			return nil, errors.New("--bedrock and --bedrock-log cannot be combined")
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read --bedrock-log: %w", err)
		}
		entries, err := bedrock.DecodeLog(raw)
		if err != nil {
			return nil, fmt.Errorf("decode --bedrock-log: %w", err)
		}
		state, err := bedrock.VerifyLog(entries)
		if err != nil {
			return nil, fmt.Errorf("verify --bedrock-log: %w", err)
		}
		log := &memoryBedrockLog{
			entries: entries,
			head:    state.Head,
			headSeq: state.HeadSeq,
			mode:    mode,
		}
		r.netmap.Bedrock = log
		r.netmap.BedrockMode = log
		r.bedrock = &control.BedrockHandler{Log: log, Peers: account}
	} else if cover, mode, coverEnrolling, ok := bedrockMode(); ok {
		// The generated fixture remains useful for focused control tests. The
		// aquifer enforcement test uses --bedrock-log above instead.
		// Both paths are wired into the netmap handler (which publishes the
		// head) and fetch handler (which serves entries).
		fixture, err := newBedrockFixture(mode)
		if err != nil {
			return nil, fmt.Errorf("bedrock fixture: %w", err)
		}
		r.netmap.Bedrock = fixture.log
		r.netmap.BedrockMode = fixture.log
		// Whether the enrolling node gets countersigned. Off lets a test see
		// the server's disclosure gate refuse a node that never was.
		fixture.coverEnrolling = coverEnrolling
		r.bedrock = &control.BedrockHandler{Log: fixture.log, Peers: account}
		r.bedrockFixture = fixture
		r.coverPreloaded = cover
	}

	// Preloaded peers, so the netmap has content on the first fetch.
	for i := 0; i < preload; i++ {
		k, err := generateIdentity()
		if err != nil {
			return nil, err
		}
		handle, err := nodes.Register(k, node.DataPlaneKeys{
			KemPublicKey: kemKey(byte(0x40 + i)),
			DhPublicKey:  pattern(32, byte(0x50+i)),
		})
		if err != nil {
			return nil, fmt.Errorf("preload peer: %w", err)
		}
		account.register(handle, fmt.Sprintf("preloaded-%d", i))

		if r.bedrockFixture != nil && i < r.coverPreloaded {
			if err := r.bedrockFixture.countersign(handle, k, kemKey(byte(0x40+i)), pattern(32, byte(0x50+i))); err != nil {
				return nil, fmt.Errorf("countersign preloaded peer: %w", err)
			}
		}
	}
	return r, nil
}

// externalBedrockLog reads `--bedrock-log PATH --bedrock-mode MODE`.
//
// The bytes use Bedrock's compact `EncodeLog` representation, not a Go-only
// fixture format. This is deliberately enough configuration for an
// integration test: a production server obtains the same bytes through the
// bootstrap and signed-response import APIs.
func externalBedrockLog() (string, proto.KarstBedrockMode, bool) {
	args := os.Args[1:]
	var path string
	mode := proto.KarstBedrockMode_KARST_BEDROCK_MODE_OFF
	for i, arg := range args {
		switch arg {
		case "--bedrock-log":
			if i+1 >= len(args) {
				fail("--bedrock-log needs a path")
			}
			path = args[i+1]
		case "--bedrock-mode":
			if i+1 >= len(args) {
				fail("--bedrock-mode needs off, advisory or enforcing")
			}
			switch args[i+1] {
			case "off":
			case "advisory":
				mode = proto.KarstBedrockMode_KARST_BEDROCK_MODE_ADVISORY
			case "enforcing":
				mode = proto.KarstBedrockMode_KARST_BEDROCK_MODE_ENFORCING
			default:
				fail("--bedrock-mode must be off, advisory or enforcing")
			}
		}
	}
	return path, mode, path != ""
}

// handleLogin mirrors control.LoginHandler with the account manager stood in
// for. The parts that matter to the node are identical: the node's data-plane
// keys are registered through the real node.Store, and the handle it gets back
// is derived from the identity it proved possession of during the handshake —
// never from anything the request body claims.
func (r *router) handleLogin(_ context.Context, identityPub, body []byte) ([]byte, error) {
	req := &proto.KarstLoginRequest{}
	if err := pb.Unmarshal(body, req); err != nil {
		return nil, errors.New("malformed login request")
	}
	if req.GetMeta() == nil {
		return nil, errors.New("peer system meta is required")
	}

	handle, err := r.nodes.Register(identityPub, node.DataPlaneKeys{
		KemPublicKey: req.GetKemPublicKey(),
		DhPublicKey:  req.GetDhPublicKey(),
	})
	// Countersign the enrolling node, when Bedrock is on. Its handle is not
	// known until this moment, which is exactly the situation the offline
	// workflow exists to handle in production; here it stands in for an admin
	// who signed promptly. A node whose own key is uncovered cannot come up
	// under enforcement, so without this every enforcing test would fail on the
	// node itself rather than on the peer it is meant to be about.
	if err == nil && r.bedrockFixture != nil && r.bedrockFixture.coverEnrolling {
		if err := r.bedrockFixture.countersign(handle, identityPub,
			req.GetKemPublicKey(), req.GetDhPublicKey()); err != nil {
			return nil, fmt.Errorf("countersign enrolling node: %w", err)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("register identity: %w", err)
	}

	hostname := req.GetMeta().GetHostname()
	if hostname == "" {
		hostname = "karst-node"
	}
	peer := r.account.register(handle, hostname)

	return pb.Marshal(&proto.KarstLoginResponse{
		NodeId:  []byte(handle),
		PeerIp:  peer.IP.String(),
		DnsName: peer.DNSLabel,
	})
}

func generateIdentity() ([]byte, error) {
	k, err := identity.Generate()
	if err != nil {
		return nil, fmt.Errorf("identity: %w", err)
	}
	return k.Public(), nil
}

// kemKey makes a real ML-KEM-768 encapsulation key. A 1184-byte pattern is not
// one, and node.Register rejects it — deliberately, since a key that does not
// parse is shipped to every peer and none of them can handshake with it.
func kemKey(seed byte) []byte {
	var s [64]byte
	for i := range s {
		s[i] = seed + byte(i)
	}
	dk, err := mlkem.NewDecapsulationKey768(s[:])
	if err != nil {
		fail("mlkem seed: %v", err)
	}
	return dk.EncapsulationKey().Bytes()
}

func pattern(n int, seed byte) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = seed + byte(i)
	}
	return out
}

// ── the Bedrock fixture ─────────────────────────────────────────────────────

// memoryBedrockLog is an in-memory bedrock.Log for the interop fixture.
//
// It serves one account's chain to every caller, because the fixture's account
// manager is a single account. The production store is per-account and scoped
// by the authenticated identity; that scoping is tested in logstore_test.go
// rather than here, where there is only one account to confuse.
type memoryBedrockLog struct {
	mu      sync.Mutex
	entries []bedrock.Entry
	head    []byte
	headSeq uint64
	mode    proto.KarstBedrockMode
}

// Mode implements control.NetmapHandler's BedrockMode.
func (m *memoryBedrockLog) Mode(context.Context, string) proto.KarstBedrockMode { return m.mode }

// State verifies the fixture's chain, exactly as the production store does.
// Re-verifying rather than caching a State keeps the fixture honest about the
// cost the real path pays.
func (m *memoryBedrockLog) State(context.Context, string) (*bedrock.State, error) {
	m.mu.Lock()
	entries := append([]bedrock.Entry(nil), m.entries...)
	m.mu.Unlock()
	if len(entries) == 0 {
		return nil, bedrock.ErrNoLog
	}
	return bedrock.VerifyLog(entries)
}

func patternBytes(n int, seed byte) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = seed + byte(i)
	}
	return out
}

func (m *memoryBedrockLog) Entries(_ context.Context, _ string, sinceSeq uint64, limit int) ([]bedrock.Entry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if limit <= 0 || limit > bedrock.MaxEntriesPerResponse {
		limit = bedrock.MaxEntriesPerResponse
	}
	out := make([]bedrock.Entry, 0, limit)
	for _, e := range m.entries {
		if e.Seq > sinceSeq && len(out) < limit {
			out = append(out, e)
		}
	}
	return out, nil
}

func (m *memoryBedrockLog) Head(context.Context, string) ([]byte, uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.headSeq == 0 {
		return nil, 0, bedrock.ErrNoLog
	}
	return m.head, m.headSeq, nil
}

// bedrockFixture builds and extends a chain at runtime.
//
// Countersignatures are issued as nodes register, which is what lets the test
// cover the node under test — it enrolls dynamically and its handle is not known
// until it does. That models an admin who countersigns promptly; the
// interesting cases are the ones where they have not, which the fixture
// produces by leaving `cover` false.
type bedrockFixture struct {
	mu        sync.Mutex
	builder   *bedrock.Builder
	authority *bedrock.AuthorityKey
	log       *memoryBedrockLog
	at        int64
	covered   map[string]struct{}
	// coverEnrolling countersigns nodes as they enroll. False leaves them
	// uncovered, which is what a test needs to see a refusal.
	coverEnrolling bool
}

func newBedrockFixture(mode proto.KarstBedrockMode) (*bedrockFixture, error) {
	root, err := bedrock.GenerateRoot()
	if err != nil {
		return nil, fmt.Errorf("root: %w", err)
	}
	rootPub := root.Public()
	authority, err := bedrock.GenerateAuthority()
	if err != nil {
		return nil, fmt.Errorf("authority: %w", err)
	}

	b := bedrock.NewBuilder()
	entry, input := b.Prepare(1000, bedrock.OpGenesis, bedrock.GenesisBody(
		"fixture.karst.", [][]byte{rootPub}, 1, [][]byte{authority.Public()}, 1))
	sigs, err := bedrock.SignRoots(input, bedrock.RootSigner{Index: 0, Key: root})
	if err != nil {
		return nil, fmt.Errorf("sign genesis: %w", err)
	}
	if err := b.Commit(entry, sigs); err != nil {
		return nil, fmt.Errorf("commit genesis: %w", err)
	}

	f := &bedrockFixture{
		builder:   b,
		authority: authority,
		log:       &memoryBedrockLog{mode: mode},
		at:        1000,
	}
	return f, f.refresh()
}

// countersign appends a node-sign for a handle and its real keys.
//
// The handle is passed rather than derived because the caller already has it
// from node.Store.Register, and the two must agree — verifyNodeSign checks that
// the handle is the one the identity key derives to, so a disagreement here
// fails loudly rather than producing a chain nobody can use.
func (f *bedrockFixture) countersign(handle string, identity, kem, dh []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if _, done := f.covered[handle]; done {
		return nil
	}
	f.at++
	entry, input := f.builder.Prepare(f.at, bedrock.OpNodeSign,
		bedrock.NodeSignBody(handle, identity, kem, dh, 0, 0))
	sigs, err := bedrock.SignAuthorities(input,
		bedrock.AuthoritySigner{Index: 0, Key: f.authority})
	if err != nil {
		return fmt.Errorf("sign %s: %w", handle, err)
	}
	if err := f.builder.Commit(entry, sigs); err != nil {
		return fmt.Errorf("commit %s: %w", handle, err)
	}
	if f.covered == nil {
		f.covered = map[string]struct{}{}
	}
	f.covered[handle] = struct{}{}
	return f.refresh()
}

// refresh re-verifies and republishes. Callers hold the lock, except the
// constructor, which has no concurrent reader yet.
func (f *bedrockFixture) refresh() error {
	state, err := f.builder.Verify()
	if err != nil {
		return fmt.Errorf("fixture chain does not verify: %w", err)
	}
	entries := f.builder.Entries()
	f.log.mu.Lock()
	f.log.entries = append([]bedrock.Entry(nil), entries...)
	f.log.head = state.Head
	f.log.headSeq = state.HeadSeq
	f.log.mu.Unlock()
	return nil
}
