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
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"gorm.io/gorm"

	"github.com/netbirdio/netbird/management/internals/controllers/network_map/update_channel"
	karstapi "github.com/netbirdio/netbird/management/internals/karst/api"
	"github.com/netbirdio/netbird/management/internals/karst/audit"
	"github.com/netbirdio/netbird/management/internals/karst/bedrock"
	karstbilling "github.com/netbirdio/netbird/management/internals/karst/billing"
	"github.com/netbirdio/netbird/management/internals/karst/channel"
	"github.com/netbirdio/netbird/management/internals/karst/compliance"
	"github.com/netbirdio/netbird/management/internals/karst/control"
	"github.com/netbirdio/netbird/management/internals/karst/cplocation"
	"github.com/netbirdio/netbird/management/internals/karst/ephemeralanchor"
	"github.com/netbirdio/netbird/management/internals/karst/firstrun"
	"github.com/netbirdio/netbird/management/internals/karst/grouplocation"
	"github.com/netbirdio/netbird/management/internals/karst/ha"
	"github.com/netbirdio/netbird/management/internals/karst/identity"
	"github.com/netbirdio/netbird/management/internals/karst/infraconnections"
	"github.com/netbirdio/netbird/management/internals/karst/knownevents"
	"github.com/netbirdio/netbird/management/internals/karst/locationreg"
	"github.com/netbirdio/netbird/management/internals/karst/node"
	"github.com/netbirdio/netbird/management/internals/karst/policy"
	"github.com/netbirdio/netbird/management/internals/karst/psk"
	"github.com/netbirdio/netbird/management/internals/karst/regionallow"
	"github.com/netbirdio/netbird/management/internals/karst/relayreg"
	"github.com/netbirdio/netbird/management/internals/karst/relayservice"
	"github.com/netbirdio/netbird/management/internals/karst/relaytelemetry"
	"github.com/netbirdio/netbird/management/internals/karst/relayusage"
	"github.com/netbirdio/netbird/management/internals/karst/routetelemetry"
	"github.com/netbirdio/netbird/management/internals/karst/scalingmode"
	"github.com/netbirdio/netbird/management/internals/karst/tenancy"
	"github.com/netbirdio/netbird/management/internals/karst/turncred"
	"github.com/netbirdio/netbird/management/internals/karst/tutorialmode"
	"github.com/netbirdio/netbird/management/internals/karst/usage"
	meshdomainmanager "github.com/netbirdio/netbird/management/internals/modules/meshdomain/manager"
	nbserver "github.com/netbirdio/netbird/management/internals/server"
	"github.com/netbirdio/netbird/management/server/account"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/proto"
	"github.com/netbirdio/netbird/util/crypt"
)

// EpochSeconds and CurrentEpoch used to live here; both moved to
// control.EpochSeconds/control.CurrentEpoch so control.EpochScheduler (which
// keeps the epoch live for the life of the process — see its doc comment for
// why deriving the value once at startup was not enough on its own) can call
// CurrentEpoch without a circular import back into this package.
//
// The cost this package's comment used to note here still applies unchanged:
// the epoch is only as good as the clock. A server whose time is badly wrong
// hands out PSKs from a different generation than its peers, and because
// §7.3 accepts n and n-1, a skew beyond one epoch is what breaks it — 24
// hours of slack, which NTP failure would have to be severe to exceed.

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
	// Chain, Audit, and Store are exposed so an optional bedrock.Fleet can be
	// wired up outside this package — ADR-0016, ADR-0033 §2, GitHub issues
	// [#61](https://github.com/karst-net/karst/issues/61) and #166. Env-var
	// parsing belongs in main.go alongside every other KARST_* variable, not
	// in this package, which stays agnostic of how it is configured.
	Chain *bedrock.Log
	Audit *audit.Log
	// Store is the account-scoped Bedrock configuration store (mode, quorum)
	// — Fleet.Reconcile reads which accounts have Bedrock enabled from it.
	Store *bedrock.Store
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
//
// scalerAdvisorURL is ADR-0045 §7 Phase 1 PR 5's own operator-configured
// address (KARST_SCALER_ADVISOR_URL): where karst-scaler advise's own
// loopback /recommendations endpoint is reachable from this server's host.
// Empty means the GET /karst/v1/scaler/recommendations endpoint is
// configured-but-absent — see RegisterEndpoints' own doc comment.
func Install(s *nbserver.BaseServer, pol *policy.Document, relays []*proto.KarstRelay, turnServers []turncred.Entry, turnMinter *turncred.Minter, tenancyGrants []tenancy.Grant, allowedRegions regionallow.Document, ephemeralAnchors ephemeralanchor.Document, scalerAdvisorURL string, demandHistoryInterval, demandHistoryRetention time.Duration) (*Karst, error) {
	sql, ok := s.Store().(*store.SqlStore)
	if !ok {
		// Karst owns three tables of its own and reaches the database through
		// the store's GORM handle. A non-SQL store would need its own
		// implementation rather than a silent degradation.
		return nil, errors.New("karst: the store is not SQL-backed")
	}
	db := sql.GetDB()
	if err := sql.InitializeDeviceUsage(); err != nil {
		return nil, fmt.Errorf("karst: device usage: %w", err)
	}

	// BaseServer.Metrics() is lazily memoized and fatal-on-error at
	// construction, so it is always non-nil here — no nil check needed before
	// handing karstMetrics to the constructors below.
	karstMetrics := s.Metrics().KarstMetrics()

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
	var paddleWebhookVerifier *karstbilling.PaddleWebhookVerifier
	if secret := os.Getenv("KARST_PADDLE_WEBHOOK_SECRET"); secret != "" {
		paddleWebhookVerifier, err = karstbilling.NewPaddleWebhookVerifier(secret)
		if err != nil {
			return nil, fmt.Errorf("karst: configure Paddle webhook: %w", err)
		}
	}
	paddleEnabled := false
	if configured := os.Getenv("KARST_PADDLE_ENABLED"); configured != "" {
		paddleEnabled, err = strconv.ParseBool(configured)
		if err != nil {
			return nil, fmt.Errorf("karst: KARST_PADDLE_ENABLED must be a boolean: %w", err)
		}
	}
	if paddleEnabled && paddleWebhookVerifier == nil {
		return nil, fmt.Errorf("karst: Paddle collection requires KARST_PADDLE_WEBHOOK_SECRET")
	}
	// Enabled collection defaults to Paddle sandbox. Production charging needs
	// an independent operator approval flag so a missing/typoed environment
	// setting cannot turn pilot traffic into live transactions.
	paddleSandbox := paddleEnabled
	if configured := os.Getenv("KARST_PADDLE_SANDBOX"); configured != "" {
		paddleSandbox, err = strconv.ParseBool(configured)
		if err != nil {
			return nil, fmt.Errorf("karst: KARST_PADDLE_SANDBOX must be a boolean: %w", err)
		}
	}
	paddleLiveApproved := false
	if configured := os.Getenv("KARST_PADDLE_LIVE_APPROVED"); configured != "" {
		paddleLiveApproved, err = strconv.ParseBool(configured)
		if err != nil {
			return nil, fmt.Errorf("karst: KARST_PADDLE_LIVE_APPROVED must be a boolean: %w", err)
		}
	}
	if err := validatePaddleMode(paddleEnabled, paddleSandbox, paddleLiveApproved); err != nil {
		return nil, err
	}
	paddleClient, err := karstbilling.NewPaddleClient(paddleEnabled, paddleSandbox, os.Getenv("KARST_PADDLE_API_KEY"), nil)
	if err != nil {
		return nil, fmt.Errorf("karst: configure Paddle client: %w", err)
	}
	// Old portal grants bypassed consumption and can no longer be trusted.
	// Invalidate them on upgrade, including grants whose ownership row was
	// deleted by the old redemption path. Newly issued grants carry ownership
	// atomically in the setup-key row and are unaffected on later starts.
	if err := invalidateLegacyEnrollmentGrants(db); err != nil {
		return nil, err
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
	complianceStore, err := compliance.NewStore(db)
	if err != nil {
		return nil, fmt.Errorf("karst: compliance store: %w", err)
	}
	complianceStore.StartRetentionWorker(context.Background(), func(err error) { log.WithError(err).Error("karst: prune compliance evidence") })
	policyStore, err := policy.NewStore(db)
	if err != nil {
		return nil, fmt.Errorf("karst: policy store: %w", err)
	}
	relayStore, err := relayreg.NewStore(db)
	if err != nil {
		return nil, fmt.Errorf("karst: relay store: %w", err)
	}
	relayStore.Metrics = karstMetrics
	usageRelayStore, err := relayusage.NewStore(db)
	if err != nil {
		return nil, fmt.Errorf("karst: relay usage store: %w", err)
	}
	billingStore, err := karstbilling.NewStore(db)
	if err != nil {
		return nil, fmt.Errorf("karst: billing store: %w", err)
	}
	billingStore.StartRetentionWorker(context.Background(), 24*time.Hour, func(err error) {
		log.WithError(err).Error("karst: prune billing history")
	})
	billingStore.StartPaymentWorker(context.Background(), paddleClient, time.Minute, func(err error) {
		log.WithError(err).Error("karst: process Paddle payment outbox")
	})
	billingStore.StartWebhookWorker(context.Background(), 5*time.Second, func(err error) {
		log.WithError(err).Error("karst: process Paddle webhook inbox")
	})
	go karstbilling.RunRelayAlertWorker(context.Background(), billingStore, usageRelayStore, 5*time.Minute, func(err error) {
		log.WithError(err).Error("karst: relay billing alert evaluation failed")
	})
	// ADR-0045 §8 (Phase 3): retains demand history on an interval so a
	// future forecaster (and the NOC view's own time-series panels) have
	// data to train/chart against -- see relayreg.Store's own doc comment
	// on RegionDemandSample for why this did not already exist.
	relayStore.StartDemandHistoryWorker(context.Background(), demandHistoryInterval, demandHistoryRetention)
	turnStore, err := turncred.NewStore(db)
	if err != nil {
		return nil, fmt.Errorf("karst: turn store: %w", err)
	}
	relayServiceStore, err := relayservice.NewStore(db)
	if err != nil {
		return nil, fmt.Errorf("karst: relay service store: %w", err)
	}
	knownEventsStore, err := knownevents.NewStore(db)
	if err != nil {
		return nil, fmt.Errorf("karst: known events store: %w", err)
	}
	// ADR-0046 §1 extension: the NOC map's admin-authorized "possible
	// locations" registry, and the location each route gateway group and
	// the control plane itself declare -- see each package's own doc
	// comment.
	locationStore, err := locationreg.NewStore(db)
	if err != nil {
		return nil, fmt.Errorf("karst: location registry: %w", err)
	}
	groupLocationStore, err := grouplocation.NewStore(db)
	if err != nil {
		return nil, fmt.Errorf("karst: group location store: %w", err)
	}
	controlPlaneLocationStore, err := cplocation.NewStore(db)
	if err != nil {
		return nil, fmt.Errorf("karst: control plane location store: %w", err)
	}
	bedrockStore, err := bedrock.NewStore(db)
	if err != nil {
		return nil, fmt.Errorf("karst: bedrock store: %w", err)
	}
	bedrockLog, err := bedrock.NewLog(db)
	if err != nil {
		return nil, fmt.Errorf("karst: bedrock log: %w", err)
	}
	bedrockLog.Metrics = karstMetrics
	// ADR-0037: operator-granted cross-tenant account access. Reconciled
	// declaratively against tenancyGrants on every boot -- an empty/nil
	// slice (KARST_TENANCY_GRANTS_FILE unset) clears any grants a previous
	// run left, the same "the file is the whole truth" convention the relay
	// and TURN registries already use. Injected into s's container so
	// BaseServer.IsValidChildAccount (internals/server/modules.go) can reach
	// it without this package depending back on that one.
	tenancyStore, err := tenancy.NewStore(db)
	if err != nil {
		return nil, fmt.Errorf("karst: tenancy store: %w", err)
	}
	if err := tenancyStore.Reconcile(context.Background(), tenancyGrants); err != nil {
		return nil, fmt.Errorf("karst: tenancy: reconcile grants: %w", err)
	}
	nbserver.Inject(s, tenancyStore)
	// ADR-0045 §4c: the deployment-wide region allowlist. Reconciled
	// declaratively against allowedRegions on every boot, the identical
	// convention tenancyStore just above uses -- an empty/nil map
	// (KARST_ALLOWED_REGIONS_FILE unset) clears any allowlist a previous run
	// left, which is the ADR's own fail-closed default rather than a special
	// case. Handed directly to the NetmapHandler constructed below, not
	// injected via nbserver.Inject -- unlike tenancy, nothing outside this
	// package's own netmap projection needs to reach it.
	regionAllowStore, err := regionallow.NewStore(db)
	if err != nil {
		return nil, fmt.Errorf("karst: region allowlist store: %w", err)
	}
	if err := regionAllowStore.Reconcile(context.Background(), allowedRegions); err != nil {
		return nil, fmt.Errorf("karst: region allowlist: reconcile: %w", err)
	}
	// ADR-0045 §4d: the ephemeral-anchor list and duty-cycle schedule.
	// Reconciled declaratively against ephemeralAnchors on every boot, the
	// identical convention regionAllowStore just above uses -- a zero
	// Document (KARST_EPHEMERAL_ANCHORS_FILE unset) clears any anchors a
	// previous run left and zeroes the schedule, this package's own
	// fail-closed default rather than a special case.
	ephemeralAnchorStore, err := ephemeralanchor.NewStore(db)
	if err != nil {
		return nil, fmt.Errorf("karst: ephemeral anchor store: %w", err)
	}
	if err := ephemeralAnchorStore.Reconcile(context.Background(), ephemeralAnchors); err != nil {
		return nil, fmt.Errorf("karst: ephemeral anchors: reconcile: %w", err)
	}
	// Issue #281: per-route egress telemetry, self-reported by each route's
	// current gateway over the control channel's own existing session --
	// handed to NetmapHandler the same way regionAllowStore is above, and
	// to karstapi the same way groupLocationStore is, for the NOC view's
	// read side.
	routeTelemetryStore, err := routetelemetry.NewStore(db)
	if err != nil {
		return nil, fmt.Errorf("karst: route telemetry store: %w", err)
	}
	// Issue #356/#379: the deployment-wide ADR-0045 §7 Phase 1 (manual)/
	// Phase 2 (automated) actuation switch. No boot-time reconcile against
	// a config file, unlike regionAllowStore/ephemeralAnchorStore above --
	// this is an admin-editable live setting (#380), not something a
	// deploy-time document should overwrite on every restart.
	scalingModeStore, err := scalingmode.NewStore(db)
	if err != nil {
		return nil, fmt.Errorf("karst: scaling mode store: %w", err)
	}
	// The console's first-run onboarding gate (default domain + initial
	// groups) -- see package firstrun's own doc comment for why NewStore's
	// backfill, not a hook into account creation, is what makes a missing
	// row safe to default to "incomplete".
	firstRunStore, err := firstrun.NewStore(db)
	if err != nil {
		return nil, fmt.Errorf("karst: first-run store: %w", err)
	}
	// The console's per-page guidance-text on/off switch, default-on.
	tutorialModeStore, err := tutorialmode.NewStore(db)
	if err != nil {
		return nil, fmt.Errorf("karst: tutorial mode store: %w", err)
	}
	// ADR-0045 §6 addenda: admin-entered AWS/Azure/GCP/Kubernetes
	// infrastructure connections for the Authorized Locations picker.
	// Requires the same data-store encryption key boot.go already threads
	// into the main SQL store (s.Store()) -- infraconnections.NewStore
	// refuses to store a credential unencrypted, so a deployment with no
	// key configured simply cannot create one (Create returns
	// ErrEncryptionRequired); List/Discover/Delete still work against
	// anything created while a key was configured.
	var infraConnectionEncrypt *crypt.FieldEncrypt
	if s.Config.DataStoreEncryptionKey != "" {
		infraConnectionEncrypt, err = crypt.NewFieldEncrypt(s.Config.DataStoreEncryptionKey)
		if err != nil {
			return nil, fmt.Errorf("karst: infrastructure connection field encryption: %w", err)
		}
	}
	infraConnectionStore, err := infraconnections.NewStore(db, infraConnectionEncrypt)
	if err != nil {
		return nil, fmt.Errorf("karst: infrastructure connection store: %w", err)
	}
	// Static relays remain a fallback for accounts that have not created an
	// account-scoped registry. They are not copied into a global table at boot.
	// The configured document remains a read-only fallback for accounts that
	// have not yet written their own policy. Persisting it here would turn one
	// operator file into a global, cross-account policy revision.

	// Register after NewAPIHandler has installed the shared auth, CORS, and
	// metrics middleware and its built-in routes, so the route ordering stays
	// mechanically clear. Every route here rides that shared user-session
	// path except relaytelemetry's, which is deliberately outside it —
	// ADR-0021: a relay authenticates itself by an ML-DSA-87 signature, not a
	// user session, the same reason RegisterEnrollmentMetadata already sits
	// outside karstapi's own `/karst/v1` subrouter for its own auth check.
	if err := s.RegisterAPIExtension(nbserver.APIExtension{Register: func(router *mux.Router) {
		// This endpoint is intentionally outside account-session auth; Paddle's
		// signature and freshness check is its sole authentication mechanism.
		router.Handle("/karst/v1/webhooks/paddle", karstbilling.NewPaddleWebhookHandler(paddleWebhookVerifier, billingStore)).Methods(http.MethodPost)
		karstapi.RegisterEnrollmentMetadata(router, static.PublicKey(), srvIdentity.Public())
		karstapi.RegisterUsageEndpoints(router, s.PermissionsManager(), usage.Reporter{DB: db}, auditLog)
		karstapi.RegisterRelayUsageEndpoints(router, s.PermissionsManager(), usageRelayStore, auditLog)
		karstapi.RegisterRelayAlertEndpoints(router, s.PermissionsManager(), usageRelayStore, billingStore, auditLog)
		karstapi.RegisterRelayCapEndpoints(router, s.PermissionsManager(), billingStore, auditLog)
		karstapi.RegisterPaymentEndpoints(router, s.PermissionsManager(), db, billingStore, auditLog, paddleClient != nil)
		domainManager := meshdomainmanager.NewManager(s.Store(), s.AccountManager(), s.PermissionsManager())
		karstapi.RegisterEndpoints(nodes, s.AccountManager(), s.AccountManager(), auditLog, policyStore, relayStore, turnStore, bedrockStore, bedrockLog, s.AccountManager(), s.PermissionsManager(), domainManager, tenancyStore, regionAllowStore, scalerAdvisorURL, knownEventsStore, locationStore, groupLocationStore, controlPlaneLocationStore, s.AccountManager(), regionAllowStore, ephemeralAnchorStore, routeTelemetryStore, scalingModeStore, firstRunStore, tutorialModeStore, infraConnectionStore, router)
		karstapi.RegisterRelayServiceEndpoints(router, s.PermissionsManager(), relayServiceStore)
		relaytelemetry.RegisterEndpoints(router, relayStore)
		relayusage.RegisterUploadEndpoint(router, usageRelayStore)
		karstapi.RegisterRelayCreditEndpoint(router, usageRelayStore, billingStore)
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

	// account.Manager (the fork's own, hundred-method interface) does not
	// declare GetDNSDomain -- control.PeerLoginer deliberately does not
	// depend on that wide interface (see its own doc comment), so this
	// asserts down to the narrow one instead of widening account.Manager
	// itself, which every production AccountManager already satisfies
	// (DefaultAccountManager.GetDNSDomain).
	peerLoginer, ok := accounts.(control.PeerLoginer)
	if !ok {
		return nil, fmt.Errorf("karst: account manager does not implement control.PeerLoginer")
	}

	epoch := control.CurrentEpoch(time.Now())
	router := &handler{
		login:      &control.LoginHandler{Nodes: nodes, Accounts: peerLoginer, OIDC: oidc},
		compliance: &control.ComplianceHandler{Store: complianceStore, Peers: peers},
		netmap: &control.NetmapHandler{
			ComplianceIngestion: true,
			Nodes:               nodes,
			Peers:               peers,
			PSK:                 deriver,
			DNS:                 accounts,
			Routes:              accounts,
			Policy:              pol,
			PolicyStore:         policyStore,
			Relays:              relays,
			RelayStore:          relayStore,
			TurnServers:         turnServers,
			TurnMinter:          turnMinter,
			TurnStore:           turnStore,
			Bedrock:             bedrockLog,
			RegionAllow:         regionAllowStore,
			EphemeralAnchors:    ephemeralAnchorStore,
			RouteTelemetry:      routeTelemetryStore,
		},
		bedrock: &control.BedrockHandler{Log: bedrockLog, Peers: peers},
	}
	// Set directly, synchronously, before anything can possibly serve a
	// request off router.netmap — the EpochScheduler goroutine started below
	// would eventually converge on the same value via its own first tick, but
	// only this guarantees no request in the window between here and that
	// goroutine actually running ever reads the zero value.
	router.netmap.Epoch.Store(epoch)

	svc := control.New(static, identity.ControlSigner{Key: srvIdentity},
		nodes.LookupFunc(), identity.ControlVerifier{}, router)
	// What makes `/me/sessions` a session history rather than a list of audit
	// rows with a null end time and a null address.
	svc.RecordSessionsWith(sessionRecorder{nodes: nodes})
	// Drives management.karst.netmap.push.duration.ms (plans/phase-6
	// /08-observability.md §5 W5).
	svc.RecordMetricsWith(karstMetrics)
	// GitHub issues [#72](https://github.com/karst-net/karst/issues/72) and [#73](https://github.com/karst-net/karst/issues/73): a subscribed node hears about a deprovisioning event
	// on its already-open stream instead of waiting up to REFRESH's 60 s poll.
	// The manager's lightweight notification registry is driven beside its
	// inherited SyncResponse channels, so Karst does not cause construction of
	// a full upstream network map that it would discard.
	svc.SubscribeToUpdatesWith(peers, s.PeersUpdateManager())
	// Keeps router.netmap.Epoch live for the rest of the process's life —
	// without this, the value set above is correct at startup and silently
	// wrong the moment real time crosses an epoch boundary (control/epoch.go's
	// doc comment has the full account of why this was a real bug, found
	// while building the PSK-epoch-age metric for the observability
	// workstream). Unconditional, the same way auditLog's delivery worker
	// above is: this is not an optional feature an operator turns on, so it
	// is not gated behind anything bedrock.Scheduler's own wiring is (that one
	// needs an operator-supplied AnchorKey; this one does not need any
	// configuration to be correct).
	go (&control.EpochScheduler{Handler: router.netmap, Updates: s.PeersUpdateManager(), Metrics: karstMetrics}).
		Run(context.Background(), time.Minute)

	// The compliance outbox needs an error-returning publisher so a failed HA
	// publish remains pending. Local delivery uses the same lightweight channel.
	notifyCompliancePeer := func(ctx context.Context, peerID string) error {
		s.PeersUpdateManager().SendNotification(ctx, peerID)
		return nil
	}
	// HA is active only for Postgres. A SQLite deployment remains deliberately
	// single-replica rather than pretending its local file can coordinate one.
	if sql.GetStoreEngine() == "postgres" {
		replica := os.Getenv("KARST_REPLICA_ID")
		if replica == "" {
			replica, _ = os.Hostname()
		}
		hub, err := ha.New(context.Background(), db, sql.PostgresPool(), replica, os.Getenv("KARST_HA_NOTIFY_CHANNEL"))
		if err != nil {
			return nil, err
		}
		if err := svc.CoordinateSessionsWith(hub); err != nil {
			return nil, fmt.Errorf("karst: reconcile HA sessions: %w", err)
		}
		if updates, ok := s.PeersUpdateManager().(*update_channel.PeersUpdateManager); ok {
			notifyCompliancePeer = func(ctx context.Context, peerID string) error {
				updates.DeliverNotification(ctx, peerID)
				return hub.PublishPeer(ctx, peerID)
			}
			updates.PublishNotificationsWith(func(ctx context.Context, peerID string) {
				if err := hub.PublishPeer(ctx, peerID); err != nil {
					log.WithError(err).Warn("karst: publish HA peer notification")
				}
			})
			hub.OnPeer(func(peerID string) { updates.DeliverNotification(context.Background(), peerID) })
			// GitHub issue #155: a PublishPeer fired while this replica's
			// LISTEN connection was down or reconnecting is gone for good —
			// see ResyncAllNotifiedPeers's own doc comment for why nothing
			// can single out just the peers actually affected, so every
			// (re)connect wakes every locally subscribed peer instead.
			hub.OnListenEstablished(func() { updates.ResyncAllNotifiedPeers(context.Background()) })
		}
	}

	complianceStore.StartInvalidationWorker(context.Background(), notifyCompliancePeer, func(err error) { log.WithError(err).Warn("karst: compliance invalidation retry pending") })

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
		Store:     bedrockStore,
	}

	// The pins are public and must reach operators; the seeds never appear.
	log.Infof("karst: server KEM pin  %s", base64.StdEncoding.EncodeToString(k.StaticKEM))
	log.Infof("karst: server sign pin %s", base64.StdEncoding.EncodeToString(k.VerifyKey))
	log.Infof("karst: psk epoch %d (rotates every %ds)", k.Epoch, control.EpochSeconds)

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
	compliance *control.ComplianceHandler
	login      *control.LoginHandler
	netmap     *control.NetmapHandler
	bedrock    *control.BedrockHandler
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
	case control.KindCompliance:
		if h.compliance == nil {
			return nil, errors.New("karst: compliance is not configured on this server")
		}
		return h.compliance.Handle(ctx, nodeID, identityPub, body)
	case KindBedrock:
		if h.bedrock == nil {
			return nil, errors.New("karst: bedrock is not configured on this server")
		}
		return h.bedrock.Handle(ctx, nodeID, identityPub, body)
	default:
		return nil, fmt.Errorf("karst: unknown request kind %d", kind)
	}
}

func invalidateLegacyEnrollmentGrants(db *gorm.DB) error {
	if err := db.Model(&types.SetupKey{}).Where("name = ? AND (owner_user_id = ? OR owner_user_id IS NULL) AND (invitation_issuer_id = ? OR invitation_issuer_id IS NULL)", "portal device", "", "").Update("revoked", true).Error; err != nil {
		return fmt.Errorf("karst: invalidate legacy enrollment grants: %w", err)
	}
	if err := db.Model(&types.SetupKey{}).Where("name = ? AND (expires_at IS NULL OR usage_limit = 0)", BootstrapKeyName).Update("revoked", true).Error; err != nil {
		return fmt.Errorf("karst: invalidate unbounded bootstrap grants: %w", err)
	}
	return nil
}
