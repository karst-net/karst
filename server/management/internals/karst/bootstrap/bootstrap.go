// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// Package bootstrap wires KarstControlService into the management daemon.
//
// It attaches through two seams the fork already provides — `SetNewServer` and
// `RegisterGRPCExtension`, the latter documented as "a generic extension point
// with no knowledge of any specific service" — so **no forked file is
// modified**. That matters for the reason Spike 0001 §5.3 measured: 28% of
// upstream commits land on the files we would otherwise diverge on, and every
// line changed there is a future cherry-pick conflict on a security fix.
package bootstrap

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"gorm.io/gorm"

	karstapi "github.com/netbirdio/netbird/management/internals/karst/api"
	"github.com/netbirdio/netbird/management/internals/karst/audit"
	"github.com/netbirdio/netbird/management/internals/karst/bedrock"
	"github.com/netbirdio/netbird/management/internals/karst/channel"
	"github.com/netbirdio/netbird/management/internals/karst/control"
	"github.com/netbirdio/netbird/management/internals/karst/identity"
	"github.com/netbirdio/netbird/management/internals/karst/node"
	"github.com/netbirdio/netbird/management/internals/karst/policy"
	"github.com/netbirdio/netbird/management/internals/karst/psk"
	"github.com/netbirdio/netbird/management/internals/karst/relayreg"
	"github.com/netbirdio/netbird/management/internals/karst/turncred"
	nbserver "github.com/netbirdio/netbird/management/internals/server"
	"github.com/netbirdio/netbird/management/server/account"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// EpochSeconds is the PSK rotation period (PLAN.md §2.6: "epochs rotate every
// 86400 s").
const EpochSeconds = 86400

// CurrentEpoch is a pure function of the clock.
//
// Deriving it rather than storing it means every server instance computes the
// same value, rotation happens on schedule with nothing to run, and a restart
// cannot lose track of where it was. Two servers behind a load balancer agree
// without coordinating.
//
// The cost is that the epoch is only as good as the clock. A server whose time
// is badly wrong hands out PSKs from a different generation than its peers,
// and because §7.3 accepts n and n-1, a skew beyond one epoch is what breaks
// it — 24 hours of slack, which NTP failure would have to be severe to exceed.
func CurrentEpoch(now time.Time) uint32 {
	return uint32(now.UTC().Unix() / EpochSeconds)
}

// ServerKeys is the singleton row holding the server's long-lived secrets.
//
// These MUST persist. Nodes **pin** the public halves at enrollment, so
// regenerating them on restart does not degrade gracefully — it breaks every
// enrolled node at once, with each one reporting that the server failed to
// authenticate. Losing this row is an outage that looks like an attack.
type ServerKeys struct {
	ID uint `gorm:"primaryKey"`
	// 64-byte ML-KEM-768 seed. Secret.
	KemSeed []byte `gorm:"not null"`
	// 32-byte ML-DSA-65 seed. Secret.
	IdentitySeed []byte `gorm:"not null"`
	// 32-byte per-pair PSK master (§2.6). Secret, and the most valuable byte
	// string in the deployment: it derives every PSK in the network.
	PSKMaster []byte    `gorm:"not null"`
	CreatedAt time.Time `json:"-"`
}

func (ServerKeys) TableName() string { return "karst_server_keys" }

// Karst is the assembled service and the material a node must be given.
type Karst struct {
	Service   *control.Service
	StaticKEM []byte
	VerifyKey []byte
	Epoch     uint32
	// Nodes is the enrolled-identity store, exposed so a co-located relay's
	// roster can be rendered from it (PLAN.md §5, GitHub issue [#47](https://github.com/karst-net/karst/issues/47)). Read-only
	// as far as that caller is concerned; the handlers above own the writes.
	Nodes *node.Store
	// Chain and Audit are exposed so an optional bedrock.Scheduler can be
	// wired up outside this package — ADR-0016, GitHub issue [#61](https://github.com/karst-net/karst/issues/61). Env-var
	// parsing belongs in main.go alongside every other KARST_* variable, not
	// in this package, which stays agnostic of how it is configured.
	Chain *bedrock.Log
	Audit *audit.Log
}

// Install registers KarstControlService on the daemon's gRPC server.
//
// Returns the pins an operator must distribute with auth keys. Handing out
// only the KEM half silently downgrades forward secrecy, so both are returned
// together and logged together.
// The relay registry is passed in rather than discovered because a relay's
// identity key is a pin: §4.2 has a node trust the key this server vouches for
// and nothing else, which is only meaningful if a human decided what it is.
// Nil means no relays, and therefore no relaying — see karst/relayreg.
//
// turnServers and turnMinter are ADR-0008 §4's TURN fallback, in the same
// spirit as relays: operator-configured input rather than something this
// package discovers. Either nil means no TURN configured — see
// karst/turncred — and produces netmaps with no turn_servers field at all,
// exactly as before this parameter existed.
func Install(s *nbserver.BaseServer, pol *policy.Document, relays []*proto.KarstRelay, turnServers []turncred.Entry, turnMinter *turncred.Minter) (*Karst, error) {
	sql, ok := s.Store().(*store.SqlStore)
	if !ok {
		// Karst owns three tables of its own and reaches the database through
		// the store's GORM handle. A non-SQL store would need its own
		// implementation rather than a silent degradation.
		return nil, errors.New("karst: the store is not SQL-backed")
	}
	db := sql.GetDB()

	keys, err := loadOrCreateKeys(db)
	if err != nil {
		return nil, err
	}

	static, err := channel.NewStaticFromSeed(keys.KemSeed)
	if err != nil {
		return nil, fmt.Errorf("karst: restore static key: %w", err)
	}
	srvIdentity, err := identity.FromSeed(keys.IdentitySeed)
	if err != nil {
		return nil, fmt.Errorf("karst: restore server identity: %w", err)
	}
	master, err := psk.NewSoftwareMaster(keys.PSKMaster)
	if err != nil {
		return nil, fmt.Errorf("karst: psk master: %w", err)
	}
	deriver, err := psk.NewDeriver(master)
	if err != nil {
		return nil, fmt.Errorf("karst: psk deriver: %w", err)
	}

	nodes, err := node.NewStore(db)
	if err != nil {
		return nil, fmt.Errorf("karst: node store: %w", err)
	}
	// Sessions a previous process was serving are still open in the table: its
	// streams' deferred closes did not run, because the process is gone. Close
	// them at the last request each one was seen making, and drop history past
	// the retention window, before anything can read the table back.
	recovered, pruned, err := nodes.RecoverSessions(time.Now())
	if err != nil {
		return nil, fmt.Errorf("karst: recover device sessions: %w", err)
	}
	if recovered > 0 || pruned > 0 {
		log.Infof("karst: device sessions: closed %d left open by a previous run, pruned %d past %s",
			recovered, pruned, node.SessionRetention)
	}
	auditLog, err := audit.New(db)
	if err != nil {
		return nil, fmt.Errorf("karst: audit log: %w", err)
	}
	// Delivery is outbox-backed: startup immediately retries events that were
	// queued before a restart, while receiver failures never block a control
	// mutation or alter the append-only chain.
	auditLog.StartDeliveryWorker(context.Background(), audit.NewTransport(), 5*time.Second, 100)
	policyStore, err := policy.NewStore(db)
	if err != nil {
		return nil, fmt.Errorf("karst: policy store: %w", err)
	}
	relayStore, err := relayreg.NewStore(db)
	if err != nil {
		return nil, fmt.Errorf("karst: relay store: %w", err)
	}
	bedrockStore, err := bedrock.NewStore(db)
	if err != nil {
		return nil, fmt.Errorf("karst: bedrock store: %w", err)
	}
	bedrockLog, err := bedrock.NewLog(db)
	if err != nil {
		return nil, fmt.Errorf("karst: bedrock log: %w", err)
	}
	// Static relays remain a fallback for accounts that have not created an
	// account-scoped registry. They are not copied into a global table at boot.
	// The configured document remains a read-only fallback for accounts that
	// have not yet written their own policy. Persisting it here would turn one
	// operator file into a global, cross-account policy revision.

	// Register after NewAPIHandler has installed the shared auth, CORS, and
	// metrics middleware and its built-in routes. Karst therefore has no second
	// authentication path, while the route ordering stays mechanically clear.
	if err := s.RegisterAPIExtension(nbserver.APIExtension{Register: func(router *mux.Router) {
		karstapi.RegisterEndpoints(nodes, s.AccountManager(), s.AccountManager(), auditLog, policyStore, relayStore, bedrockStore, bedrockLog, s.PermissionsManager(), router)
	}}); err != nil {
		return nil, fmt.Errorf("karst: register API extension: %w", err)
	}

	accounts := s.AccountManager()
	peers := &storePeers{store: sql, accounts: accounts}
	oidc := &control.OIDC{
		Tokens:   s.AuthManager(),
		Accounts: accounts,
		Claimer:  s.SessionStore(),
	}

	epoch := CurrentEpoch(time.Now())
	router := &handler{
		login: &control.LoginHandler{Nodes: nodes, Accounts: accounts, OIDC: oidc},
		netmap: &control.NetmapHandler{
			Nodes:       nodes,
			Peers:       peers,
			PSK:         deriver,
			Epoch:       epoch,
			DNS:         accounts,
			Policy:      pol,
			PolicyStore: policyStore,
			Relays:      relays,
			RelayStore:  relayStore,
			TurnServers: turnServers,
			TurnMinter:  turnMinter,
			Bedrock:     bedrockLog,
		},
		bedrock: &control.BedrockHandler{Log: bedrockLog, Peers: peers},
	}

	svc := control.New(static, identity.ControlSigner{Key: srvIdentity},
		nodes.LookupFunc(), identity.ControlVerifier{}, router)
	// What makes `/me/sessions` a session history rather than a list of audit
	// rows with a null end time and a null address.
	svc.RecordSessionsWith(sessionRecorder{nodes: nodes})
	// GitHub issues [#72](https://github.com/karst-net/karst/issues/72) and [#73](https://github.com/karst-net/karst/issues/73): a subscribed node hears about a deprovisioning event
	// on its already-open stream instead of waiting up to REFRESH's 60 s poll.
	// The manager's lightweight notification registry is driven beside its
	// inherited SyncResponse channels, so Karst does not cause construction of
	// a full upstream network map that it would discard.
	svc.SubscribeToUpdatesWith(peers, s.PeersUpdateManager())

	s.RegisterGRPCExtension(nbserver.GRPCExtension{
		Register: func(reg grpc.ServiceRegistrar) {
			proto.RegisterKarstControlServiceServer(reg, svc)
			log.Info("KarstControlService registered on gRPC server")
		},
	})

	k := &Karst{
		Service:   svc,
		StaticKEM: svc.Pins().StaticKEM,
		VerifyKey: svc.Pins().VerifyKey,
		Epoch:     epoch,
		Nodes:     nodes,
		Chain:     bedrockLog,
		Audit:     auditLog,
	}

	// The pins are public and must reach operators; the seeds never appear.
	log.Infof("karst: server KEM pin  %s", base64.StdEncoding.EncodeToString(k.StaticKEM))
	log.Infof("karst: server sign pin %s", base64.StdEncoding.EncodeToString(k.VerifyKey))
	log.Infof("karst: psk epoch %d (rotates every %ds)", k.Epoch, EpochSeconds)

	// Said out loud because its absence is invisible from every other vantage
	// point: a relay with a valid config and a current roster still sees no
	// connections, since a node dials only relays its netmap named (GitHub issue
	// [#48](https://github.com/karst-net/karst/issues/48)). A warning here is the one place that reads as a cause.
	if len(relays) == 0 {
		log.Warnf("karst: no relay registry; nodes will be told of no relays and " +
			"cannot relay, so a pair that fails to connect directly cannot connect at all")
	} else {
		for _, r := range relays {
			log.Infof("karst: relay %s (%s) region %s",
				r.GetAddress(), r.GetTlsServerName(), r.GetRegion())
		}
	}

	return k, nil
}

// migrateMu serializes first-start within a single process.
//
// Concurrent callers contend on the schema, and on SQLite that surfaces as
// "database table is locked: sqlite_master" rather than as anything the
// original "table already exists" tolerance recognized. Inside one process
// there is no reason to race at all, so this removes the contention outright
// instead of recovering from it. Cross-process contention — two replicas
// against one database, the case the tolerance below was written for — a mutex
// cannot help with, which is what the retry is for.
var migrateMu sync.Mutex

// loadOrCreateKeys reads the singleton row, creating it on first start.
//
// Retries because first-start contention is transient: the losing caller sees
// a locked schema, and a moment later the winner has finished and the row is
// simply there to be read. Bounded, and the last error is returned unchanged,
// so a genuinely broken store still fails rather than hanging. Idempotent by
// construction — every attempt either reads the winner's row or creates the
// only one.
func loadOrCreateKeys(db *gorm.DB) (*ServerKeys, error) {
	migrateMu.Lock()
	defer migrateMu.Unlock()

	const attempts = 10
	var err error
	for i := range attempts {
		var keys *ServerKeys
		if keys, err = tryLoadOrCreateKeys(db); err == nil {
			return keys, nil
		}
		if i == attempts-1 {
			break
		}
		// Jittered backoff. Without the jitter, contending callers retry in
		// lockstep and collide again on exactly the same schedule. The byte is
		// scaled across the jitter window rather than used as a duration —
		// a raw byte is nanoseconds, which would be no jitter at all.
		var j [1]byte
		_, _ = rand.Read(j[:])
		jitter := time.Duration(j[0]) * (3 * time.Millisecond) / 256
		time.Sleep(time.Duration(i+1)*5*time.Millisecond + jitter)
	}
	return nil, err
}

func tryLoadOrCreateKeys(db *gorm.DB) (*ServerKeys, error) {
	// Two replicas starting against a fresh database race here, and AutoMigrate
	// is not safe against itself: the loser gets "table already exists". That
	// is benign — the winner created exactly the table we wanted — so the
	// error is only fatal if the table is *still* unusable afterwards, which
	// the read below establishes. Treating it as fatal outright would mean a
	// deployment with replicas crash-looping on first start.
	migrateErr := db.AutoMigrate(&ServerKeys{})

	var keys ServerKeys
	err := db.Where("id = ?", 1).First(&keys).Error
	switch {
	case err == nil:
		return &keys, nil
	case !errors.Is(err, gorm.ErrRecordNotFound):
		if migrateErr != nil {
			// The table is genuinely unusable, and the migration is why.
			return nil, fmt.Errorf("karst: migrate server keys: %w", migrateErr)
		}
		return nil, fmt.Errorf("karst: read server keys: %w", err)
	}

	kemSeed := make([]byte, 64)
	idSeed := make([]byte, identity.SeedSize)
	master := make([]byte, psk.MasterSize)
	for _, b := range [][]byte{kemSeed, idSeed, master} {
		if _, err := rand.Read(b); err != nil {
			return nil, fmt.Errorf("karst: generate server keys: %w", err)
		}
	}

	keys = ServerKeys{
		ID:           1,
		KemSeed:      kemSeed,
		IdentitySeed: idSeed,
		PSKMaster:    master,
		CreatedAt:    time.Now().UTC(),
	}
	// A plain Create, not an upsert: two processes racing to initialize a
	// fresh database must not both succeed with different keys, which would
	// give half the nodes an unusable pin. The loser re-reads the winner's row.
	if err := db.Create(&keys).Error; err != nil {
		var existing ServerKeys
		if reread := db.Where("id = ?", 1).First(&existing).Error; reread == nil {
			return &existing, nil
		}
		return nil, fmt.Errorf("karst: create server keys: %w", err)
	}
	log.Warn("karst: generated new server keys; nodes must be given the pins below")
	return &keys, nil
}

// storePeers adapts the fork's store and account manager to control.PeerLister.
//
// The peer listing lives on the *store*, not on the account manager — an
// assumption control.PeerLister originally got wrong, and which its fake
// happily satisfied because the fake was written against the invented
// interface rather than the real one. The same class of gap that
// TestRegistrationAgainstTheRealAccountManager exists to close for LoginPeer.
type storePeers struct {
	store    store.Store
	accounts account.Manager
}

func (s *storePeers) GetAccountIDForPeerKey(ctx context.Context, key string) (string, error) {
	return s.accounts.GetAccountIDForPeerKey(ctx, key)
}

func (s *storePeers) GetPeerByPeerPubKey(ctx context.Context, key string) (*nbpeer.Peer, error) {
	return s.store.GetPeerByPeerPubKey(ctx, store.LockingStrengthShare, key)
}

// GetPeersFromAccount returns every peer in the account.
//
// Not filtered by what the requester may reach: §4.3 makes the server a
// distributor of policy rather than an enforcement point, so reachability is
// decided by the compiled packet filter in the datapath. Filtering here as
// well would mean two places that must agree about access, which is one more
// than can be kept correct.
func (s *storePeers) GetPeersFromAccount(ctx context.Context, accountID, _, _ string) ([]*nbpeer.Peer, error) {
	return s.store.GetAccountPeers(ctx, store.LockingStrengthShare, accountID, "", "")
}

// AccountPrefixes reports the prefix lengths of the account's overlay networks.
//
// Read from the account rather than assumed. The fork allocates a /16 out of
// 100.64.0.0/10 and a /64 ULA today, and hard-coding those would be right until
// the day an account is allocated differently — at which point every node would
// come up with an interface whose prefix does not cover its peers, and the
// symptom would be a network where nothing routes.
func (s *storePeers) AccountPrefixes(ctx context.Context, accountID string) (uint8, uint8, error) {
	network, err := s.store.GetAccountNetwork(ctx, store.LockingStrengthShare, accountID)
	if err != nil {
		return 0, 0, fmt.Errorf("account network: %w", err)
	}
	v4, _ := network.Net.Mask.Size()
	if v4 <= 0 {
		// A zero-length mask would put every address in the world on-link. That
		// is not a network to fall back to; it is one to refuse.
		return 0, 0, fmt.Errorf("account %s has no usable IPv4 prefix", accountID)
	}
	// IPv6 is optional: an account allocated before ULA support has none, and a
	// node with no IPv6 address does not need one.
	v6, _ := network.NetV6.Mask.Size()
	if v6 < 0 {
		v6 = 0
	}
	return uint8(v4), uint8(v6), nil
}

// handler routes a decrypted request to the right sub-handler.
//
// The wire carries one opaque payload per request, so the first byte selects.
// A oneof in the proto would be tidier and is the obvious later change; this
// keeps the envelope free of message-type knowledge for now.
type handler struct {
	login   *control.LoginHandler
	netmap  *control.NetmapHandler
	bedrock *control.BedrockHandler
}

// Request kinds. Values are on the wire, so they may not be reordered.
const (
	KindLogin   byte = 1
	KindNetmap  byte = 2
	KindBedrock byte = 3
)

func (h *handler) Handle(ctx context.Context, nodeID, identityPub, payload []byte) ([]byte, error) {
	if len(payload) == 0 {
		return nil, errors.New("karst: empty request")
	}
	kind, body := payload[0], payload[1:]
	switch kind {
	case KindLogin:
		return h.login.Handle(ctx, nodeID, identityPub, body)
	case KindNetmap:
		return h.netmap.Handle(ctx, nodeID, identityPub, body)
	case KindBedrock:
		if h.bedrock == nil {
			return nil, errors.New("karst: bedrock is not configured on this server")
		}
		return h.bedrock.Handle(ctx, nodeID, identityPub, body)
	default:
		return nil, fmt.Errorf("karst: unknown request kind %d", kind)
	}
}
