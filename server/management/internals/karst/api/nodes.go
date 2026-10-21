// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// Package api serves Karst-owned administrative endpoints on the management
// router. It deliberately consumes the router's existing authentication
// middleware rather than parsing credentials itself, with one exception:
// relaysEnroll (ADR-0045 §6) authenticates a not-yet-registered relay's own
// one-off enrollment token directly, because that caller has no
// router-level session to hold in the first place — see its own doc
// comment.
package api

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/internals/karst/audit"
	"github.com/netbirdio/netbird/management/internals/karst/bedrock"
	"github.com/netbirdio/netbird/management/internals/karst/cplocation"
	"github.com/netbirdio/netbird/management/internals/karst/ephemeralanchor"
	"github.com/netbirdio/netbird/management/internals/karst/firstrun"
	"github.com/netbirdio/netbird/management/internals/karst/geo"
	"github.com/netbirdio/netbird/management/internals/karst/grouplocation"
	"github.com/netbirdio/netbird/management/internals/karst/infraconnections"
	"github.com/netbirdio/netbird/management/internals/karst/knownevents"
	"github.com/netbirdio/netbird/management/internals/karst/locationreg"
	"github.com/netbirdio/netbird/management/internals/karst/node"
	karstpolicy "github.com/netbirdio/netbird/management/internals/karst/policy"
	"github.com/netbirdio/netbird/management/internals/karst/regionallow"
	"github.com/netbirdio/netbird/management/internals/karst/relayreg"
	"github.com/netbirdio/netbird/management/internals/karst/routetelemetry"
	"github.com/netbirdio/netbird/management/internals/karst/scalingmode"
	"github.com/netbirdio/netbird/management/internals/karst/turncred"
	"github.com/netbirdio/netbird/management/internals/karst/tutorialmode"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/route"
	karstcontract "github.com/netbirdio/netbird/shared/management/http/api/karst"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

// nodeReader is intentionally the read-only portion of node.Store used by the
// control API. It keeps the HTTP tests independent of GORM and prevents this
// administrative read surface from growing a write capability by accident.
type nodeReader interface {
	Get(handle string) (*node.Identity, error)
	SessionObservations(reporter string) ([]node.SessionObservation, error)
	AllSessionObservations() ([]node.SessionObservation, error)
	All() ([]node.Identity, error)
}

type nodeDeleter interface {
	Delete(handle string) error
}

// sessionReader is the portal's session history. Optional, like the other
// capability interfaces here: a deployment whose node store does not provide
// it gets a precondition error rather than a page of silently empty rows.
type sessionReader interface {
	SessionsForHandles(handles []string, limit int) ([]node.DeviceSession, error)
}

// sessionCloser ends a revoked device's live sessions. See
// node.CloseSessionsForHandle for why revocation does not rely on the stream
// teardown alone.
type sessionCloser interface {
	CloseSessionsForHandle(handle string, at time.Time) error
}

// peerReader is the existing, permission-aware peer listing. Its result is
// already scoped to the authenticated caller, so it is the authorization
// boundary for the peer half of the join.
type peerReader interface {
	GetPeers(ctx context.Context, accountID, userID, nameFilter, ipFilter string) ([]*peer.Peer, error)
	GetAdminPeers(ctx context.Context, accountID, userID, nameFilter, ipFilter string) ([]*peer.Peer, error)
}

// accountUpdater triggers a netmap push. Karst's own policy writes are the
// one Karst-specific account mutation that does not already go through the
// inherited route/group handlers' own affected-peers dispatch (GitHub issue
// #109): this is that dispatch, narrowed to the one method policyWrite and
// policyRollback need.
type accountUpdater interface {
	UpdateAccountPeers(ctx context.Context, accountID string, reason types.UpdateReason)
}

type handler struct {
	nodes      nodeReader
	peers      peerReader
	audit      auditReader
	policy     policyReader
	relays     relayReader
	turns      turnReader
	bedrock    bedrockReader
	chain      bedrockLogReader
	peerWriter peerWriter
	accounts   accountUpdater
	domainMgr  domainManager
	tenancy    tenancyReader
	// anchors is ADR-0045 §7 Phase 1's second demand-side input (§4b's
	// histogram), nil in a deployment that has not configured a region
	// allowlist store — see demandAnchors.
	anchors demandReader
	// scalerAdvisorURL is ADR-0045 §7 Phase 1 PR 5's own server-to-server
	// dial target (KARST_SCALER_ADVISOR_URL) -- empty in a deployment that
	// has not configured one, see scalerRecommendations.
	scalerAdvisorURL string
	// knownEvents is ADR-0045 §8 (Phase 3)'s operator-entered calendar --
	// nil in a deployment that has not configured one, see
	// knownEventsList/knownEventsCreate/knownEventsDelete.
	knownEvents knownEventReader
	// locations is the NOC map's admin-authorized "possible locations"
	// registry -- nil in a deployment that has not configured one, see
	// locationsList/locationsCreate/locationsDelete.
	locations locationReader
	// groupLocations declares where a route's gateway groups are, for NOC
	// map exit-node/subnet-router markers -- see package grouplocation's
	// own doc comment for why this is keyed by group, not by route.
	groupLocations groupLocationReader
	// controlPlaneLocation is this account's declared NOC-map position for
	// the control plane -- see package cplocation's own doc comment.
	controlPlaneLocation cpLocationReader
	// routes backs the "route" kind in nocComponents: which gateway groups
	// are actually in use by an enabled exit or subnet route, and what to
	// call that route. A narrow slice of the fork's own AccountManager, the
	// same "depend on behavior, not the concrete store" convention
	// tenancyReader/domainManager/accountUpdater already use in this file.
	routes routeLister
	// regions is the console's region-allowlist editor (issue #349) -- nil
	// in a deployment that has not configured a region allowlist store, see
	// regionsList/regionsCreate/regionsDelete. The same *regionallow.Store
	// as h.anchors, under the wider regionAllowReadWriter interface.
	regions regionAllowReadWriter
	// ephemeralAnchors is ADR-0045 §4d's ephemeral-anchor list and
	// duty-cycle schedule editor -- nil in a deployment that has not
	// configured KARST_EPHEMERAL_ANCHORS_FILE, see
	// ephemeralAnchorsList/Create/Delete/Schedule/ScheduleSet. Named
	// distinctly from h.anchors/h.regions above (an unrelated collision:
	// h.anchors is demandReader, a different table in a different
	// package) rather than reusing either.
	ephemeralAnchors ephemeralAnchorReadWriter
	// routeTelemetry is issue #281's per-route egress byte/packet counts,
	// self-reported by each route's current gateway -- nil in a deployment
	// that has not configured a route telemetry store, see
	// routeGroupComponents.
	routeTelemetry routeTelemetryReader
	// scalingMode is issue #356/#379's deployment-wide ADR-0045 §7
	// Phase 1 (manual)/Phase 2 (automated) actuation switch -- nil in a
	// deployment that has not configured a scaling-mode store, see
	// scalingModeGet/scalingModeSet. Not consumed by anything in this
	// package itself; drive_loop.rs reads it over this same API
	// (issue #382), the same way karst-scaler already reads
	// scalerRecommendations' sibling data.
	scalingMode scalingModeReadWriter
	// firstRun gates the console's nav on completing the first-run wizard
	// (default domain + initial groups) -- nil in a deployment that has
	// not configured one, see firstRunGet/firstRunComplete. See package
	// firstrun's own doc comment for why a missing row, not a flag flip,
	// is what new accounts default to.
	firstRun firstRunReadWriter
	// tutorialMode is the account-scoped on/off switch for per-page
	// guidance text -- nil in a deployment that has not configured one,
	// see tutorialModeGet/tutorialModeSet.
	tutorialMode tutorialModeReadWriter
	// infraConnections is the console's admin-entered AWS/Azure/GCP/
	// Kubernetes connection store (ADR-0045 §6 addenda) -- nil in a
	// deployment that has not configured a data-store encryption key, see
	// cloudAccountsList/cloudAccountsCreate/cloudAccountsDelete/
	// cloudAccountRegions (the preserved legacy surface) and
	// infraConnectionsList/infraConnectionsCreate/infraConnectionsDelete/
	// infraConnectionResources (the generalized one). See package
	// infraconnections's own doc comment for the trust-boundary reasoning
	// and why Mode is stored but never actuated here.
	infraConnections infraConnectionReadWriter
}

// locationReader is the admin-authorized-locations registry's read/write
// surface this package depends on -- see package locationreg.
type locationReader interface {
	Create(ctx context.Context, entry locationreg.Entry) (*locationreg.StoredLocation, error)
	List(ctx context.Context) ([]locationreg.StoredLocation, error)
	Delete(ctx context.Context, id string) error
}

// groupLocationReader is a route gateway group's declared-location store --
// see package grouplocation.
type groupLocationReader interface {
	Set(ctx context.Context, entry grouplocation.Entry) (*grouplocation.StoredGroupLocation, error)
	List(ctx context.Context) ([]grouplocation.StoredGroupLocation, error)
	Delete(ctx context.Context, groupID string) error
}

// cpLocationReader is the control plane's declared-location store -- see
// package cplocation.
type cpLocationReader interface {
	Set(ctx context.Context, lat, lon float64, label string) (*cplocation.StoredLocation, error)
	Get(ctx context.Context) (*cplocation.StoredLocation, error)
	Delete(ctx context.Context) error
}

// routeLister is the fork's own route listing, narrowed the same way
// peerReader/tenancyReader already narrow the rest of AccountManager this
// package depends on.
type routeLister interface {
	ListRoutes(ctx context.Context, accountID, userID string) ([]*route.Route, error)
}

// routeTelemetryReader is issue #281's per-route egress telemetry read
// side -- see package routetelemetry. Write-side (RecordRouteBytes) is
// control.NetmapHandler's own concern, not exposed through this console
// API at all: a route's gateway reports it over the control channel, an
// admin never writes it directly.
type routeTelemetryReader interface {
	LatestByRoute(ctx context.Context, accountID string) (map[string]routetelemetry.StoredRouteBytes, error)
}

// scalingModeReadWriter is issue #356/#379's deployment-wide scaling-mode
// setting -- see package scalingmode.
type scalingModeReadWriter interface {
	Mode(ctx context.Context) (scalingmode.Mode, error)
	SetMode(ctx context.Context, mode scalingmode.Mode) error
}

// firstRunReadWriter is the first-run wizard's completion flag -- see
// package firstrun.
type firstRunReadWriter interface {
	Get(ctx context.Context) (*firstrun.StoredState, error)
	Complete(ctx context.Context) (*firstrun.StoredState, error)
}

// tutorialModeReadWriter is the per-page guidance-text on/off switch -- see
// package tutorialmode.
type tutorialModeReadWriter interface {
	Get(ctx context.Context) (bool, error)
	Set(ctx context.Context, enabled bool) error
}

// infraConnectionReadWriter is the console's admin-entered infrastructure-
// connection store -- see package infraconnections. CreateLegacy/
// DiscoverLegacy back the preserved /cloud-accounts surface; Create/List/
// Delete/Discover back /infrastructure-connections.
type infraConnectionReadWriter interface {
	Create(ctx context.Context, req infraconnections.CreateRequest) (*infraconnections.Account, error)
	CreateLegacy(ctx context.Context, req infraconnections.LegacyCreateRequest) (*infraconnections.Account, error)
	List(ctx context.Context) ([]infraconnections.Account, error)
	Delete(ctx context.Context, id string) error
	Discover(ctx context.Context, id string) ([]infraconnections.DiscoveredResource, error)
	DiscoverLegacy(ctx context.Context, id string) ([]infraconnections.DiscoveredRegion, error)
	EnableLocalZone(ctx context.Context, id, code, parentRegion string) (infraconnections.DiscoveredRegion, error)
}

// tenancyReader is ADR-0037's read side: which other accounts the
// authenticated caller has been operator-granted access to. Deliberately
// narrower than tenancy.Store -- this package depends on behavior, not on
// the concrete store, the same convention as domainManager/accountUpdater.
type tenancyReader interface {
	AccessibleAccounts(ctx context.Context, userID string) ([]string, error)
}

// relayHealth is deliberately separate from relayreg.StoredRelay. Registry
// records describe what nodes may dial; admission telemetry belongs to a
// relay. ADR-0021: populated from a relay's own signed reports
// (relayreg.Store.LatestTelemetry) when any have arrived; unknown remains the
// only truthful value for a relay that has never reported.
type relayHealth struct {
	Source          string     `json:"source"`
	LastConfirmedAt *time.Time `json:"last_confirmed_at"`
	Sessions        *int       `json:"sessions"`
	Bytes           *int       `json:"bytes"`
	AdmissionState  string     `json:"admission_state"`
}

type relayResponse struct {
	relayreg.StoredRelay
	Health relayHealth `json:"health"`
	// Location is the relay's NOC-map position -- declared (ADR-0046 §1) or
	// detected via cloud instance metadata (ADR-0048), whichever locationFor
	// resolves. Nil means neither source has one.
	Location *relayreg.Location `json:"location,omitempty"`
	// LocationSource says which of the two it came from, mirroring
	// relayHealth.Source's existing "roster_mtime"/"relay_telemetry"
	// provenance-tagging shape rather than inventing a new one. Omitted
	// along with Location when neither source has a value.
	LocationSource string `json:"location_source,omitempty"`
}

// turnResponse adds a TURN server's declared location to the stored record
// -- StoredTurnServer's own LocationLat/Lon/Label columns are json:"-" for
// the same reason relayreg.StoredRelay's are, so every read path needs this
// wrapper rather than encoding the store row directly.
type turnResponse struct {
	turncred.StoredTurnServer
	Location *geo.Location `json:"location,omitempty"`
}

func turnResponseFor(turn turncred.StoredTurnServer) turnResponse {
	return turnResponse{StoredTurnServer: turn, Location: turn.LocationFor()}
}

// nocComponent is the NOC map's discriminated union (ADR-0046 §1's full
// component list) -- one shape every kind reshapes into, so the console's
// map rendering does not need five different response types to draw five
// kinds of marker.
type nocComponent struct {
	Kind string `json:"kind"` // "relay" | "turn" | "route" | "control_plane" | "bedrock"
	ID   string `json:"id"`
	// Label is a human-readable name for the marker/legend: a relay's
	// location label or region, a TURN server's URI, the route
	// identifier(s) a gateway group serves, or a fixed name for the
	// account-scoped singletons.
	Label string `json:"label"`
	// Health is relayHealth.AdmissionState's own vocabulary
	// (confirmed/stale/unknown), empty for every kind that has no
	// telemetry-derived health to report.
	Health   string        `json:"health,omitempty"`
	Location *geo.Location `json:"location,omitempty"`
	// Bytes/Packets/IngressBytes/IngressPackets are issues #281 and #371's
	// aggregate egress and ingress throughput, populated only for Kind:
	// "route" (summed across every route the group serves) -- nil wherever
	// no gateway for this group has yet self-reported any, the same "nil,
	// not zero, until something real has arrived" posture relayHealth.Bytes
	// already has for relays. Never a destination breakdown -- see
	// routetelemetry's own doc comment on why.
	Bytes          *int64 `json:"bytes,omitempty"`
	Packets        *int64 `json:"packets,omitempty"`
	IngressBytes   *int64 `json:"ingress_bytes,omitempty"`
	IngressPackets *int64 `json:"ingress_packets,omitempty"`
}

func unknownRelayHealth() relayHealth {
	return relayHealth{Source: "roster_mtime", AdmissionState: "unknown"}
}

// relayTelemetryFreshWindow bounds how old a relay's last confirmed report
// may be before its health is reported as "stale" rather than "confirmed" —
// ADR-0021. Generous relative to the relay's own default report interval
// (60s, bins/karst-relay/src/config.rs) to tolerate a missed tick or two
// without flapping between states.
const relayTelemetryFreshWindow = 3 * time.Minute

// healthFor derives a relay's health from its latest self-report, if any —
// ADR-0021. A read error is treated the same as no report: this is a display
// concern, not a reason to fail the surrounding list/get request.
func (h *handler) healthFor(ctx context.Context, id string) relayHealth {
	if h.relays == nil {
		return unknownRelayHealth()
	}
	record, err := h.relays.LatestTelemetry(ctx, id)
	if err != nil || record == nil {
		return unknownRelayHealth()
	}
	state := "stale"
	if time.Since(record.ReportedAt) <= relayTelemetryFreshWindow {
		state = "confirmed"
	}
	reportedAt := record.ReportedAt
	// Sessions counts client connections specifically — mesh peers are
	// infrastructure this relay dials or is dialled by, not sessions an
	// admin reading this field would recognize as one.
	sessions := record.LocalClients
	bytes := int(record.BytesTotal)
	return relayHealth{
		Source:          "relay_telemetry",
		LastConfirmedAt: &reportedAt,
		Sessions:        &sessions,
		Bytes:           &bytes,
		AdmissionState:  state,
	}
}

func (h *handler) relayResponseFor(ctx context.Context, relay relayreg.StoredRelay) relayResponse {
	resp := relayResponse{StoredRelay: relay, Health: h.healthFor(ctx, relay.ID)}
	resp.Location, resp.LocationSource = h.locationFor(ctx, relay)
	return resp
}

// locationFor resolves a relay's NOC-map position -- detected (ADR-0048)
// overrides declared (ADR-0046 §1) when present, declared is the fallback,
// neither is "unknown". A read error is treated the same as no detected
// location, the same posture healthFor already takes for telemetry reads.
func (h *handler) locationFor(ctx context.Context, relay relayreg.StoredRelay) (*relayreg.Location, string) {
	if h.relays != nil {
		if record, err := h.relays.LatestTelemetry(ctx, relay.ID); err == nil && record != nil && record.DetectedLat != nil {
			return &relayreg.Location{Lat: *record.DetectedLat, Lon: *record.DetectedLon}, "detected"
		}
	}
	if relay.LocationLat != nil {
		return &relayreg.Location{Lat: *relay.LocationLat, Lon: *relay.LocationLon, Label: relay.LocationLabel}, "declared"
	}
	return nil, ""
}

type peerWriter interface {
	UpdatePeer(context.Context, string, string, *peer.Peer) (*peer.Peer, error)
	DeletePeer(context.Context, string, string, string) error
}

// setupKeyIssuer is deliberately optional. The normal daemon's AccountManager
// implements it; keeping it separate preserves the read-only test seam and
// ensures this small portal surface cannot acquire arbitrary account writes.
type setupKeyIssuer interface {
	CreateEnrollmentKey(context.Context, string, string) (*types.SetupKey, error)
}

type ownDeviceWriter interface {
	RenameOwnPeer(context.Context, string, string, string, string) (*peer.Peer, error)
	DeleteOwnPeer(context.Context, string, string, string) error
}

// portalPeerReader is intentionally narrower than a general list API. It is
// used only to compile a caller's policy, then the handler returns the subset
// the caller can already reach.
type portalPeerReader interface {
	PortalPeers(context.Context, string) ([]*peer.Peer, error)
}

type policyReader interface {
	Current(context.Context) (*karstpolicy.Version, error)
	Write(context.Context, string, string, uint64) (*karstpolicy.Version, error)
	Get(context.Context, uint64) (*karstpolicy.Version, error)
	List(context.Context, int, int) ([]karstpolicy.Version, error)
}

type auditReader interface {
	Append(context.Context, string, string, string, string) (*audit.Entry, error)
	AccountHead(context.Context, string) (uint64, string, error)
	Verify(context.Context) (uint64, error)
	ListFilteredForAccount(context.Context, string, string, string, int, int) ([]audit.Entry, error)
	ListBeforeForAccount(context.Context, string, uint64, int) ([]audit.Entry, error)
	CountSince(context.Context, string, uint64) (uint64, error)
	AddSink(context.Context, string, string) (*audit.Sink, error)
	ListSinks(context.Context) ([]audit.Sink, error)
	RemoveSink(context.Context, string) error
}
type auditAnchorReader interface {
	AccountHead(context.Context, string) (uint64, string, error)
	VerifyFrom(context.Context, uint64, string) (uint64, error)
}
type relayReader interface {
	List(context.Context) ([]relayreg.StoredRelay, error)
	Create(context.Context, relayreg.Entry) (*relayreg.StoredRelay, error)
	Delete(context.Context, string) error
	// DeleteByAddress is ADR-0045 §7's own driver-initiated teardown path
	// (issue #319) — see relayDeenroll and relayreg.Store.DeleteByAddress's
	// own doc comment for why this is keyed by address, not id, unlike
	// turnReader.DeleteByURI.
	DeleteByAddress(context.Context, string) error
	// DeleteByTLSServerName is DeleteByAddress's own counterpart for the
	// AWS driver (issue #329) — see relayreg.Store.DeleteByTLSServerName's
	// own doc comment for why that driver needs a different key than the
	// Kubernetes driver does.
	DeleteByTLSServerName(context.Context, string) error
	// LatestTelemetry is ADR-0021's read side: a relay's most recent
	// self-report, or nil if it has never reported.
	LatestTelemetry(context.Context, string) (*relayreg.RelayTelemetryRecord, error)
	// DemandByRegion is ADR-0045 §7 Phase 1's demand-side input — see its
	// own doc comment on relayreg.Store for why it is deliberately not
	// account-scoped the way every other method here is.
	DemandByRegion(context.Context) ([]relayreg.RegionDemand, error)
	// DemandHistory is ADR-0045 §8 (Phase 3)'s retained time series over
	// the same signal DemandByRegion reads live — see relayreg.Store's own
	// doc comment on RegionDemandSample for why this exists at all.
	DemandHistory(context.Context, time.Time, time.Time) ([]relayreg.RegionDemandSample, error)
}

// demandReader is ADR-0045 §4b/§7's deployment-wide anchor-RTT histogram —
// narrower than regionallow.Store, the same "depend on behavior, not the
// concrete store" convention tenancyReader/domainManager already use.
type demandReader interface {
	AnchorHistogram(context.Context) ([]regionallow.AnchorHistogramEntry, error)
}

// regionAllowReadWriter is the console's region-allowlist editor surface
// (issue #349) — the same *regionallow.Store concrete value as demandReader
// above, but under a wider interface. Kept separate rather than widening
// demandReader itself: that route is Advisor-role-gated read access to the
// RTT histogram, this one is an admin CRUD surface over a different table
// in the same package, and blurring the two would blur their RBAC posture.
type regionAllowReadWriter interface {
	AllowedRegions(ctx context.Context) (regionallow.Document, error)
	AddRegion(ctx context.Context, provider, region string) error
	RemoveRegion(ctx context.Context, provider, region string) error
}

// ephemeralAnchorReadWriter is the ADR-0045 §4d ephemeral-anchor editor
// surface -- a future console editor's CRUD, and the surface
// bins/karst-anchor-scheduler polls (a UserRoleAdvisor-scoped PAT reaches
// this cleanly: like /regions above, this route carries only the blanket
// KarstControl auth check below, no extra per-handler role check).
type ephemeralAnchorReadWriter interface {
	Anchors(ctx context.Context) ([]ephemeralanchor.AnchorEntry, error)
	AddAnchor(ctx context.Context, entry ephemeralanchor.AnchorEntry) error
	RemoveAnchor(ctx context.Context, label string) error
	Schedule(ctx context.Context) (windowPeriodSeconds, dutyCycleSeconds uint32, err error)
	SetSchedule(ctx context.Context, windowPeriodSeconds, dutyCycleSeconds uint32) error
}

type turnReader interface {
	List(context.Context) ([]turncred.StoredTurnServer, error)
	Create(context.Context, turncred.Entry) (*turncred.StoredTurnServer, error)
	Delete(context.Context, string) error
	DeleteByURI(context.Context, string) error
}

// knownEventReader is ADR-0045 §8 (Phase 3)'s operator-entered calendar --
// account-scoped, the same shape turnReader already has, not deployment-
// wide or cross-account the way relayReader.DemandHistory is: when an
// organization's own traffic is expected to change is that organization's
// own calendar.
type knownEventReader interface {
	List(context.Context) ([]knownevents.StoredKnownEvent, error)
	Create(context.Context, knownevents.Entry) (*knownevents.StoredKnownEvent, error)
	Delete(context.Context, string) error
}

// bedrockLogReader is the verified chain. Separate from bedrockReader because
// the two answer different questions: the store holds operator configuration,
// the log holds what the authorities signed. Coverage comes from the log and
// only from the log — a second source would be free to disagree with the one
// the nodes themselves enforce against.
type bedrockLogReader interface {
	All(ctx context.Context, accountID string) ([]bedrock.Entry, error)
	State(ctx context.Context, accountID string) (*bedrock.State, error)
}

type bedrockPendingStore interface {
	bedrockLogReader
	Pending(context.Context, string) (*bedrock.PendingSigningRequest, error)
	CreatePending(context.Context, string, []bedrock.Entry) (*bedrock.PendingSigningRequest, error)
	CommitPending(context.Context, string, map[uint64][]bedrock.Signature) error
	PrepareAnchor(context.Context, string, bedrock.AuditHead, time.Time) (*bedrock.Entry, []byte, error)
}

type bedrockImportStore interface {
	bedrockLogReader
	Import(context.Context, string, []bedrock.Entry) error
}

type bedrockReader interface {
	Configuration(context.Context, string) (*bedrock.Configuration, error)
	SetMode(ctx context.Context, accountID, mode string, acknowledged []string,
		state *bedrock.State, enrolled map[string]bedrock.PeerKeys, at int64) (*bedrock.Configuration, error)
	// SetLocation declares this account's Bedrock position on the NOC map
	// (ADR-0046 §1) -- see bedrock.Store.SetLocation.
	SetLocation(ctx context.Context, accountID string, lat, lon float64, label string) (*bedrock.Configuration, error)
}

const maxRequestBodyBytes = 1 << 20

// RegisterEndpoints registers the portion of the Karst contract backed by
// persisted state today. It is called on the management server's shared router
// before that router is served, so its routes receive the same auth, CORS, and
// metrics middleware as every /api endpoint.
//
// scalerAdvisorURL is ADR-0045 §7 Phase 1 PR 5's own addition: an
// operator-configured address (KARST_SCALER_ADVISOR_URL) where
// karst-scaler advise's own loopback /recommendations endpoint is
// reachable from this server's host. The browser never dials karst-scaler
// directly -- that listener is loopback-only by design (same posture as
// karstd's own metrics listener), and letting it bypass this server's own
// auth would be a second, uncontrolled trust path into deployment-wide
// demand data. Empty means scalerRecommendations below answers
// precondition-failed, not a 404 -- the same "optional capability, not a
// missing route" posture h.relays/h.anchors being nil already has.
func RegisterEndpoints(nodes nodeReader, peers peerReader, peerWriter peerWriter, log auditReader, policies policyReader, relays relayReader, turns turnReader, bedrockStore bedrockReader, bedrockLog bedrockLogReader, accounts accountUpdater, permissionsManager permissions.Manager, domains domainManager, tenancyStore tenancyReader, anchors demandReader, scalerAdvisorURL string, knownEventsStore knownEventReader, locations locationReader, groupLocations groupLocationReader, controlPlaneLocation cpLocationReader, routes routeLister, regions regionAllowReadWriter, ephemeralAnchors ephemeralAnchorReadWriter, routeTelemetry routeTelemetryReader, scalingMode scalingModeReadWriter, firstRun firstRunReadWriter, tutorialMode tutorialModeReadWriter, infraConnections infraConnectionReadWriter, router *mux.Router) {
	h := &handler{nodes: nodes, peers: peers, peerWriter: peerWriter, audit: log, policy: policies, relays: relays, turns: turns, bedrock: bedrockStore, chain: bedrockLog, accounts: accounts, domainMgr: domains, tenancy: tenancyStore, anchors: anchors, scalerAdvisorURL: scalerAdvisorURL, knownEvents: knownEventsStore, locations: locations, groupLocations: groupLocations, controlPlaneLocation: controlPlaneLocation, routes: routes, regions: regions, ephemeralAnchors: ephemeralAnchors, routeTelemetry: routeTelemetry, scalingMode: scalingMode, firstRun: firstRun, tutorialMode: tutorialMode, infraConnections: infraConnections}
	karstRouter := router.PathPrefix("/karst/v1").Subrouter()
	karstRouter.UseEncodedPath()
	karstRouter.Use(limitRequestBody)
	karstRouter.Use(h.auditMutations)
	if permissionsManager == nil {
		karstRouter.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				util.WriteError(r.Context(), status.Errorf(status.PermissionDenied, "Karst control authorization is not configured"), w)
			})
		})
	} else {
		karstRouter.Use(karstAuthorization(permissionsManager))
	}
	karstRouter.HandleFunc("/invitations", h.invitations).Methods(http.MethodGet, http.MethodPost, http.MethodOptions)
	karstRouter.HandleFunc("/invitations/{id}/revoke", h.revokeInvitation).Methods(http.MethodPost, http.MethodOptions)
	// Mesh domains (ADR-0032). Deliberately exempted from the blanket
	// KarstControl gate below (see karstAuthorization) -- a domain-scoped
	// delegated admin has no account-wide grant, and each handler's
	// underlying manager call re-derives and enforces its own permission.
	karstRouter.HandleFunc("/domains/root/rename/preview", h.rootRename).Methods(http.MethodPost, http.MethodOptions)
	karstRouter.HandleFunc("/domains/root/rename/commit", h.rootRename).Methods(http.MethodPost, http.MethodOptions)
	karstRouter.HandleFunc("/domains", h.domains).Methods(http.MethodGet, http.MethodPost, http.MethodOptions)
	karstRouter.HandleFunc("/domains/{id}", h.getDomain).Methods(http.MethodGet, http.MethodOptions)
	karstRouter.HandleFunc("/domains/{id}", h.deleteDomain).Methods(http.MethodDelete, http.MethodOptions)
	karstRouter.HandleFunc("/domains/{id}/delegations", h.domainDelegations).Methods(http.MethodGet, http.MethodPost, http.MethodOptions)
	karstRouter.HandleFunc("/domains/delegations/{bindingId}", h.revokeDomainDelegation).Methods(http.MethodDelete, http.MethodOptions)
	karstRouter.HandleFunc("/nodes", h.listNodes).Methods(http.MethodGet, http.MethodOptions)
	karstRouter.HandleFunc("/nodes/{handle}", h.getNode).Methods(http.MethodGet, http.MethodOptions)
	karstRouter.HandleFunc("/nodes/{handle}", h.updateNode).Methods(http.MethodPatch, http.MethodOptions)
	karstRouter.HandleFunc("/nodes/{handle}", h.deleteNode).Methods(http.MethodDelete, http.MethodOptions)
	karstRouter.HandleFunc("/nodes/{handle}/paths", h.getNodePaths).Methods(http.MethodGet, http.MethodOptions)
	karstRouter.HandleFunc("/nodes/{handle}/posture", h.getNodePosture).Methods(http.MethodGet, http.MethodOptions)
	karstRouter.HandleFunc("/posture", h.getPosture).Methods(http.MethodGet, http.MethodOptions)
	karstRouter.HandleFunc("/posture/sessions", h.listPostureSessions).Methods(http.MethodGet, http.MethodOptions)
	karstRouter.HandleFunc("/audit/head", h.auditHead).Methods(http.MethodGet, http.MethodOptions)
	karstRouter.HandleFunc("/audit/verify", h.auditVerify).Methods(http.MethodGet, http.MethodOptions)
	karstRouter.HandleFunc("/audit", h.auditList).Methods(http.MethodGet, http.MethodOptions)
	karstRouter.HandleFunc("/audit/export", h.auditExport).Methods(http.MethodGet, http.MethodOptions)
	karstRouter.HandleFunc("/audit/sinks", h.auditSink).Methods(http.MethodPost, http.MethodOptions)
	karstRouter.HandleFunc("/audit/sinks", h.auditSinkList).Methods(http.MethodGet, http.MethodOptions)
	karstRouter.HandleFunc("/audit/sinks/{sinkId}", h.auditSinkDelete).Methods(http.MethodDelete, http.MethodOptions)
	karstRouter.HandleFunc("/policy", h.policyCurrent).Methods(http.MethodGet, http.MethodOptions)
	karstRouter.HandleFunc("/policy/schema", h.policySchema).Methods(http.MethodGet, http.MethodOptions)
	karstRouter.HandleFunc("/policy/validate", h.policyValidate).Methods(http.MethodPost, http.MethodOptions)
	karstRouter.HandleFunc("/policy/preview", h.policyPreview).Methods(http.MethodPost, http.MethodOptions)
	karstRouter.HandleFunc("/policy/test", h.policyTest).Methods(http.MethodPost, http.MethodOptions)
	karstRouter.HandleFunc("/policy", h.policyWrite).Methods(http.MethodPut, http.MethodOptions)
	karstRouter.HandleFunc("/policy/versions", h.policyVersions).Methods(http.MethodGet, http.MethodOptions)
	karstRouter.HandleFunc("/policy/versions/{version}", h.policyVersion).Methods(http.MethodGet, http.MethodOptions)
	karstRouter.HandleFunc("/policy/rollback/{version}", h.policyRollback).Methods(http.MethodPost, http.MethodOptions)
	karstRouter.HandleFunc("/relays", h.relaysList).Methods(http.MethodGet, http.MethodOptions)
	karstRouter.HandleFunc("/relays", h.relaysCreate).Methods(http.MethodPost, http.MethodOptions)
	karstRouter.HandleFunc("/relays/{relayId}", h.relaysDelete).Methods(http.MethodDelete, http.MethodOptions)
	karstRouter.HandleFunc("/relays/{relayId}/health", h.relayHealth).Methods(http.MethodGet, http.MethodOptions)
	karstRouter.HandleFunc("/relays/enroll-tokens", h.relayEnrollTokensCreate).Methods(http.MethodPost, http.MethodOptions)
	karstRouter.HandleFunc("/relays/deenroll", h.relayDeenroll).Methods(http.MethodPost, http.MethodOptions)
	// Deliberately on the parent router, not karstRouter -- see
	// relaysEnroll's own doc comment for why. limitRequestBody is applied
	// explicitly since this route does not inherit karstRouter's own
	// middleware stack.
	router.Handle("/karst/v1/relays/enroll", limitRequestBody(http.HandlerFunc(h.relaysEnroll))).Methods(http.MethodPost, http.MethodOptions)
	karstRouter.HandleFunc("/versions", h.versions).Methods(http.MethodGet, http.MethodOptions)
	karstRouter.HandleFunc("/noc/components", h.nocComponents).Methods(http.MethodGet, http.MethodOptions)
	karstRouter.HandleFunc("/noc/relays/{relayId}", h.nocRelay).Methods(http.MethodGet, http.MethodOptions)
	karstRouter.HandleFunc("/demand/regions", h.demandRegions).Methods(http.MethodGet, http.MethodOptions)
	karstRouter.HandleFunc("/demand/regions/history", h.demandRegionsHistory).Methods(http.MethodGet, http.MethodOptions)
	karstRouter.HandleFunc("/demand/anchors", h.demandAnchors).Methods(http.MethodGet, http.MethodOptions)
	karstRouter.HandleFunc("/scaler/recommendations", h.scalerRecommendations).Methods(http.MethodGet, http.MethodOptions)
	karstRouter.HandleFunc("/scaler/suggestions", h.scalerSuggestions).Methods(http.MethodGet, http.MethodOptions)
	karstRouter.HandleFunc("/scaling/mode", h.scalingModeGet).Methods(http.MethodGet, http.MethodOptions)
	karstRouter.HandleFunc("/scaling/mode", h.scalingModeSet).Methods(http.MethodPut, http.MethodOptions)
	karstRouter.HandleFunc("/firstrun", h.firstRunGet).Methods(http.MethodGet, http.MethodOptions)
	karstRouter.HandleFunc("/firstrun/complete", h.firstRunComplete).Methods(http.MethodPost, http.MethodOptions)
	karstRouter.HandleFunc("/tutorial-mode", h.tutorialModeGet).Methods(http.MethodGet, http.MethodOptions)
	karstRouter.HandleFunc("/tutorial-mode", h.tutorialModeSet).Methods(http.MethodPut, http.MethodOptions)
	karstRouter.HandleFunc("/cloud-accounts", h.cloudAccountsList).Methods(http.MethodGet, http.MethodOptions)
	karstRouter.HandleFunc("/cloud-accounts", h.cloudAccountsCreate).Methods(http.MethodPost, http.MethodOptions)
	karstRouter.HandleFunc("/cloud-accounts/{cloudAccountId}", h.cloudAccountsDelete).Methods(http.MethodDelete, http.MethodOptions)
	karstRouter.HandleFunc("/cloud-accounts/{cloudAccountId}/regions", h.cloudAccountRegions).Methods(http.MethodGet, http.MethodOptions)
	karstRouter.HandleFunc("/cloud-accounts/{cloudAccountId}/regions/{code}/enable", h.cloudAccountEnableRegion).Methods(http.MethodPost, http.MethodOptions)
	karstRouter.HandleFunc("/infrastructure-connections", h.infraConnectionsList).Methods(http.MethodGet, http.MethodOptions)
	karstRouter.HandleFunc("/infrastructure-connections", h.infraConnectionsCreate).Methods(http.MethodPost, http.MethodOptions)
	karstRouter.HandleFunc("/infrastructure-connections/{connectionId}", h.infraConnectionsDelete).Methods(http.MethodDelete, http.MethodOptions)
	karstRouter.HandleFunc("/infrastructure-connections/{connectionId}/resources", h.infraConnectionResources).Methods(http.MethodGet, http.MethodOptions)
	karstRouter.HandleFunc("/regions", h.regionsList).Methods(http.MethodGet, http.MethodOptions)
	karstRouter.HandleFunc("/regions", h.regionsCreate).Methods(http.MethodPost, http.MethodOptions)
	karstRouter.HandleFunc("/regions/{provider}/{region}", h.regionsDelete).Methods(http.MethodDelete, http.MethodOptions)
	karstRouter.HandleFunc("/ephemeral-anchors", h.ephemeralAnchorsList).Methods(http.MethodGet, http.MethodOptions)
	karstRouter.HandleFunc("/ephemeral-anchors", h.ephemeralAnchorsCreate).Methods(http.MethodPost, http.MethodOptions)
	karstRouter.HandleFunc("/ephemeral-anchors/schedule", h.ephemeralAnchorsSchedule).Methods(http.MethodGet, http.MethodOptions)
	karstRouter.HandleFunc("/ephemeral-anchors/schedule", h.ephemeralAnchorsScheduleSet).Methods(http.MethodPut, http.MethodOptions)
	karstRouter.HandleFunc("/ephemeral-anchors/{label}", h.ephemeralAnchorsDelete).Methods(http.MethodDelete, http.MethodOptions)
	karstRouter.HandleFunc("/turns", h.turnsList).Methods(http.MethodGet, http.MethodOptions)
	karstRouter.HandleFunc("/turns", h.turnsCreate).Methods(http.MethodPost, http.MethodOptions)
	karstRouter.HandleFunc("/turns/{turnId}", h.turnsDelete).Methods(http.MethodDelete, http.MethodOptions)
	karstRouter.HandleFunc("/locations", h.locationsList).Methods(http.MethodGet, http.MethodOptions)
	karstRouter.HandleFunc("/locations", h.locationsCreate).Methods(http.MethodPost, http.MethodOptions)
	karstRouter.HandleFunc("/locations/{locationId}", h.locationsDelete).Methods(http.MethodDelete, http.MethodOptions)
	karstRouter.HandleFunc("/group-locations", h.groupLocationsList).Methods(http.MethodGet, http.MethodOptions)
	karstRouter.HandleFunc("/group-locations/{groupId}", h.groupLocationsSet).Methods(http.MethodPut, http.MethodOptions)
	karstRouter.HandleFunc("/group-locations/{groupId}", h.groupLocationsDelete).Methods(http.MethodDelete, http.MethodOptions)
	karstRouter.HandleFunc("/control-plane/location", h.controlPlaneLocationGet).Methods(http.MethodGet, http.MethodOptions)
	karstRouter.HandleFunc("/control-plane/location", h.controlPlaneLocationSet).Methods(http.MethodPut, http.MethodOptions)
	karstRouter.HandleFunc("/bedrock/location", h.bedrockLocationSet).Methods(http.MethodPut, http.MethodOptions)
	karstRouter.HandleFunc("/turn/enroll-tokens", h.turnEnrollTokensCreate).Methods(http.MethodPost, http.MethodOptions)
	karstRouter.HandleFunc("/turn/deenroll", h.turnDeenroll).Methods(http.MethodPost, http.MethodOptions)
	// Deliberately on the parent router, not karstRouter -- see
	// relaysEnroll's own doc comment (and turnEnroll's own, below) for why.
	// limitRequestBody is applied explicitly since this route does not
	// inherit karstRouter's own middleware stack.
	router.Handle("/karst/v1/turn/enroll", limitRequestBody(http.HandlerFunc(h.turnEnroll))).Methods(http.MethodPost, http.MethodOptions)
	karstRouter.HandleFunc("/known-events", h.knownEventsList).Methods(http.MethodGet, http.MethodOptions)
	karstRouter.HandleFunc("/known-events", h.knownEventsCreate).Methods(http.MethodPost, http.MethodOptions)
	karstRouter.HandleFunc("/known-events/{eventId}", h.knownEventsDelete).Methods(http.MethodDelete, http.MethodOptions)
	karstRouter.HandleFunc("/bedrock", h.bedrockStatus).Methods(http.MethodGet, http.MethodOptions)
	karstRouter.HandleFunc("/bedrock/log", h.bedrockLog).Methods(http.MethodGet, http.MethodOptions)
	karstRouter.HandleFunc("/bedrock/log/verify", h.bedrockLogVerify).Methods(http.MethodGet, http.MethodOptions)
	karstRouter.HandleFunc("/bedrock/requests", h.bedrockRequests).Methods(http.MethodGet, http.MethodOptions)
	karstRouter.HandleFunc("/bedrock/requests/export", h.bedrockRequestsExport).Methods(http.MethodPost, http.MethodOptions)
	karstRouter.HandleFunc("/bedrock/audit-anchor/export", h.bedrockAuditAnchorExport).Methods(http.MethodPost, http.MethodOptions)
	karstRouter.HandleFunc("/bedrock/responses/import", h.bedrockResponsesImport).Methods(http.MethodPost, http.MethodOptions)
	karstRouter.HandleFunc("/bedrock/bootstrap/import", h.bedrockBootstrapImport).Methods(http.MethodPost, http.MethodOptions)
	karstRouter.HandleFunc("/bedrock/mode", h.bedrockMode).Methods(http.MethodPut, http.MethodOptions)
	// /me deliberately does not share the administrative authorization
	// middleware. Its subject is always taken from the authenticated context;
	// no route accepts a user id, so an IDOR cannot be expressed.
	me := karstRouter.PathPrefix("/me").Subrouter()
	me.HandleFunc("/devices", h.meDevices).Methods(http.MethodGet, http.MethodOptions)
	me.HandleFunc("/devices/enroll", h.meenroll).Methods(http.MethodPost, http.MethodOptions)
	me.HandleFunc("/devices/{handle}", h.meRenameDevice).Methods(http.MethodPatch, http.MethodOptions)
	me.HandleFunc("/devices/{handle}", h.meRevokeDevice).Methods(http.MethodDelete, http.MethodOptions)
	me.HandleFunc("/sessions", h.meSessions).Methods(http.MethodGet, http.MethodOptions)
	me.HandleFunc("/access", h.meAccess).Methods(http.MethodGet, http.MethodOptions)
	// ADR-0037: which accounts the caller may switch into via the fork's
	// existing ?account= override, regardless of which account is in
	// effect for *this* request -- subject-derived, same reasoning as
	// every other /me route above.
	me.HandleFunc("/tenancy-accounts", h.meTenancyAccounts).Methods(http.MethodGet, http.MethodOptions)
}

type tenancyAccountResponse struct {
	AccountID string `json:"account_id"`
}

func (h *handler) meTenancyAccounts(w http.ResponseWriter, r *http.Request) {
	user, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if h.tenancy == nil {
		util.WriteJSONObject(r.Context(), w, []tenancyAccountResponse{})
		return
	}
	ids, err := h.tenancy.AccessibleAccounts(r.Context(), user.UserId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	resp := make([]tenancyAccountResponse, len(ids))
	for i, id := range ids {
		resp[i] = tenancyAccountResponse{AccountID: id}
	}
	util.WriteJSONObject(r.Context(), w, resp)
}

// auditMutations records successful state changes after their handler has
// committed. It deliberately does not make an otherwise successful control
// operation fail when audit storage is temporarily unavailable: an audit
// outage must be visible in server logs, but must not turn a recovery action
// such as node revocation into an impossible operation.
func (h *handler) auditMutations(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.audit == nil || r.Method == http.MethodGet || r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}
		tracked := &auditResponseWriter{ResponseWriter: w}
		next.ServeHTTP(tracked, r)
		if tracked.statusCode() < http.StatusOK || tracked.statusCode() >= http.StatusMultipleChoices {
			return
		}
		user, err := nbcontext.GetUserAuthFromContext(r.Context())
		if err != nil {
			return
		}
		path := strings.TrimPrefix(strings.TrimPrefix(r.URL.EscapedPath(), "/api"), "/karst/v1/")
		ctx := audit.WithAccount(r.Context(), user.AccountId)
		if _, err := h.audit.Append(ctx, user.UserId, "karst."+strings.ToLower(r.Method), path, ""); err != nil {
			log.WithContext(r.Context()).Errorf("append Karst audit event: %v", err)
		}
	})
}

type auditResponseWriter struct {
	http.ResponseWriter
	status int
}

func (w *auditResponseWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *auditResponseWriter) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(data)
}

func (w *auditResponseWriter) statusCode() int {
	if w.status == 0 {
		return http.StatusOK
	}
	return w.status
}

// limitRequestBody bounds every mutating request before a JSON decoder reads
// it. A control-plane request should never need megabytes of input, and a
// common middleware limit avoids one overlooked endpoint becoming a memory or
// disk-pressure path.
func limitRequestBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost, http.MethodPut, http.MethodPatch:
			r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
		}
		next.ServeHTTP(w, r)
	})
}

func karstAuthorization(manager permissions.Manager) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, err := nbcontext.GetUserAuthFromContext(r.Context())
			if err != nil {
				util.WriteError(r.Context(), err, w)
				return
			}
			// Member portal routes have their own, subject-derived scope. They
			// must not be checked against KarstControl: that module intentionally
			// denies Members every administrative operation.
			//
			// Mesh-domain routes (ADR-0032), device invitations, and node
			// management for delegated domains are exceptions: a delegated
			// admin has no account-wide KarstControl grant, so this blanket
			// gate would reject them before their scoped authorization runs.
			// The domain and invitation managers each re-derive their own
			// permission; /nodes does so through GetAdminPeers, which never
			// grants access merely because a member owns a device. Skipping
			// this gate is therefore skipping only the wrong account-wide
			// authorization for these resource-scoped surfaces.
			path := strings.TrimPrefix(r.URL.Path, "/api")
			if strings.HasPrefix(path, "/karst/v1/me/") || strings.HasPrefix(path, "/karst/v1/domains") || strings.HasPrefix(path, "/karst/v1/invitations") || strings.HasPrefix(path, "/karst/v1/nodes") {
				next.ServeHTTP(w, r.WithContext(scopeToAccount(r.Context(), user.AccountId)))
				return
			}
			op := operationForRequest(r.Method, r.URL.Path)
			allowed, ctx, err := manager.ValidateUserPermissions(r.Context(), user.AccountId, user.UserId, modules.KarstControl, op)
			if err != nil {
				util.WriteError(r.Context(), err, w)
				return
			}
			if !allowed {
				util.WriteError(r.Context(), status.Errorf(status.PermissionDenied, "Karst control permission denied"), w)
				return
			}
			// ADR-0045 §6/§7b: the Scaler role exists to mint relay-enroll
			// and turn-enroll tokens, and to ask for a relay or TURN server
			// it enrolled to be de-enrolled, nothing else. roles.Scaler's
			// own Create grant on modules.KarstControl is coarser than that
			// (this RBAC model's only module granularity covers every
			// mutation under /karst/v1, not just these four routes — see
			// roles.Scaler's own doc comment), so this hard allowlist is
			// what actually keeps the role narrow, independent of whatever
			// a future endpoint added under this same module gate would
			// otherwise permit it to reach. turnDeenroll/relayDeenroll are
			// deliberately POSTs (operations.Create), not the DELETE
			// turnsDelete/relaysDelete already are -- roles.Scaler's own
			// Delete grant stays false; see turnDeenroll's own doc comment
			// (and relayDeenroll's, issue #319) for why these are requests
			// shaped like a Create rather than a widened Delete grant.
			if role, ok := nbcontext.RoleFromContext(ctx); ok && types.UserRole(role) == types.UserRoleScaler {
				path := strings.TrimPrefix(r.URL.Path, "/api")
				if path != relayEnrollTokensPath && path != turnEnrollTokensPath && path != turnDeenrollPath && path != relayDeenrollPath {
					util.WriteError(r.Context(), status.Errorf(status.PermissionDenied, "the scaler role may only mint relay-enroll or turn-enroll tokens, or request relay or turn de-enrollment"), w)
					return
				}
			}
			next.ServeHTTP(w, r.WithContext(scopeToAccount(ctx, user.AccountId)))
		})
	}
}

// scopeToAccount applies every Karst-owned package's own WithAccount to one
// context, once -- karstAuthorization's two call sites previously nested
// these by hand, which is exactly the kind of chain a new registry's
// WithAccount is easy to forget to add to one site but not the other.
func scopeToAccount(ctx context.Context, accountID string) context.Context {
	ctx = knownevents.WithAccount(ctx, accountID)
	ctx = karstpolicy.WithAccount(ctx, accountID)
	ctx = relayreg.WithAccount(ctx, accountID)
	ctx = turncred.WithAccount(ctx, accountID)
	ctx = locationreg.WithAccount(ctx, accountID)
	ctx = grouplocation.WithAccount(ctx, accountID)
	ctx = cplocation.WithAccount(ctx, accountID)
	ctx = audit.WithAccount(ctx, accountID)
	ctx = firstrun.WithAccount(ctx, accountID)
	ctx = tutorialmode.WithAccount(ctx, accountID)
	ctx = infraconnections.WithAccount(ctx, accountID)
	return ctx
}

func operationForRequest(method, path string) operations.Operation {
	path = strings.TrimPrefix(path, "/api")
	if method == http.MethodPost {
		switch path {
		case "/karst/v1/policy/validate", "/karst/v1/policy/preview", "/karst/v1/policy/test":
			return operations.Read
		}
		return operations.Create
	}
	if method == http.MethodPut || method == http.MethodPatch {
		return operations.Update
	}
	if method == http.MethodDelete {
		return operations.Delete
	}
	return operations.Read
}

// bedrockAuditAnchorExport prepares an authority-signable commitment to the
// current audit head. It shares the one pending-request slot and the normal
// response-import path with node signing, so the server still cannot forge an
// anchor and operators use the same offline karst-bedrock ceremony.
func (h *handler) bedrockAuditAnchorExport(w http.ResponseWriter, r *http.Request) {
	user, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	store, ok := h.chain.(bedrockPendingStore)
	if !ok {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "Bedrock request store is not configured"), w)
		return
	}
	if h.audit == nil {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "audit log is not configured"), w)
		return
	}
	auditHead, ok := h.audit.(auditAnchorReader)
	if !ok {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "audit anchor verification is not configured"), w)
		return
	}
	if pending, err := store.Pending(r.Context(), user.AccountId); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	} else if pending != nil {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "a Bedrock signing request is already pending"), w)
		return
	}
	entry, _, err := store.PrepareAnchor(r.Context(), user.AccountId, auditHead, time.Now().UTC())
	// An account with no Bedrock log has nothing to anchor *into*. This is the
	// state every account is in before the genesis ceremony, so it is the
	// first thing an administrator who clicks this hits — and without this
	// branch it arrived as a bare 500, while the sibling export three
	// handlers up answered the same missing genesis with a 412 and a sentence
	// saying what to do (GitHub issue [#71](https://github.com/karst-net/karst/issues/71)).
	if errors.Is(err, bedrock.ErrNoLog) {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed,
			"Bedrock genesis must be imported before an audit anchor can be exported"), w)
		return
	}
	if errors.Is(err, audit.ErrEmpty) {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "cannot anchor an empty audit log"), w)
		return
	}
	if errors.Is(err, bedrock.ErrNothingToAnchor) {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "the current audit head is already anchored"), w)
		return
	}
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	pending, err := store.CreatePending(r.Context(), user.AccountId, []bedrock.Entry{*entry})
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	log, err := h.chain.All(r.Context(), user.AccountId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	pendingEntries, err := bedrock.DecodeLog(pending.Entries)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	payload := renderBedrockRequest(log, pendingEntries)
	util.WriteJSONObject(r.Context(), w, map[string]any{"format": "bedrock-signed-bundle-v1", "payload": base64.StdEncoding.EncodeToString([]byte(payload))})
}

func requireUser(w http.ResponseWriter, r *http.Request) bool {
	if _, err := nbcontext.GetUserAuthFromContext(r.Context()); err != nil {
		util.WriteError(r.Context(), err, w)
		return false
	}
	return true
}

// meDevices is intentionally separate from listNodes. The latter is an
// administrator view; this one has no pagination or cross-user filter because
// every value is derived from the authenticated subject.
func (h *handler) meDevices(w http.ResponseWriter, r *http.Request) {
	user, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	nodes, err := h.authorizedNodes(r.Context(), user.AccountId, user.UserId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	items := make([]map[string]any, 0, len(nodes))
	for _, n := range nodes {
		items = append(items, map[string]any{"handle": n.Handle, "name": n.Name, "platform": n.Platform, "last_seen_at": n.LastSeenAt})
	}
	util.WriteJSONObject(r.Context(), w, items)
}

func (h *handler) meRenameDevice(w http.ResponseWriter, r *http.Request) {
	user, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	var request struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}
	peerRecord, err := h.lookupAuthorizedPeer(r.Context(), user.AccountId, user.UserId, mux.Vars(r)["handle"])
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	writer, ok := h.peerWriter.(ownDeviceWriter)
	if !ok {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "self-service device management is not configured"), w)
		return
	}
	updated, err := writer.RenameOwnPeer(r.Context(), user.AccountId, user.UserId, peerRecord.ID, request.Name)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	identity, err := h.nodes.Get(updated.Key)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	observations, err := h.nodes.SessionObservations(updated.Key)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, toNodeResponse(updated, identity, postureFromObservations(observations)))
}

func (h *handler) meRevokeDevice(w http.ResponseWriter, r *http.Request) {
	user, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	peerRecord, err := h.lookupAuthorizedPeer(r.Context(), user.AccountId, user.UserId, mux.Vars(r)["handle"])
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	writer, ok := h.peerWriter.(ownDeviceWriter)
	if !ok {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "self-service device management is not configured"), w)
		return
	}
	// DeleteOwnPeer removes the peer then sends an affected-peer update, which
	// closes its control session rather than merely hiding it from this view.
	if err := writer.DeleteOwnPeer(r.Context(), user.AccountId, peerRecord.ID, user.UserId); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	// Before the identity goes. Session rows outlive the device on purpose — a
	// user who revokes a stolen laptop still wants to see where it was — so
	// they must be closed while the handle is still known to belong to this
	// subject, and a device deleted mid-session must not be left looking
	// connected forever.
	if closer, ok := h.nodes.(sessionCloser); ok {
		if err := closer.CloseSessionsForHandle(peerRecord.Key, time.Now()); err != nil {
			util.WriteError(r.Context(), err, w)
			return
		}
	}
	if deleter, ok := h.nodes.(nodeDeleter); ok {
		if err := deleter.Delete(peerRecord.Key); err != nil && !errors.Is(err, node.ErrUnknownNode) {
			util.WriteError(r.Context(), err, w)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) meenroll(w http.ResponseWriter, r *http.Request) {
	user, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	issuer, ok := h.peerWriter.(setupKeyIssuer)
	if !ok {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "device enrollment is not configured"), w)
		return
	}
	key, err := issuer.CreateEnrollmentKey(r.Context(), user.AccountId, user.UserId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	expires := time.Now().UTC().Add(15 * time.Minute)
	if key.ExpiresAt != nil {
		expires = key.ExpiresAt.UTC()
	}
	w.Header().Set("Cache-Control", "no-store")
	util.WriteJSONObject(r.Context(), w, map[string]any{"key": key.Key, "expires_at": expires})
}

func (h *handler) meSessions(w http.ResponseWriter, r *http.Request) {
	user, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	// The caller's own devices, resolved the same way /me/devices resolves
	// them. The handles that reach the store are therefore always ones this
	// subject is authorized for; no handle is ever taken from the request
	// (plans/phase-5/05-user-portal.md §2).
	nodes, err := h.authorizedNodes(r.Context(), user.AccountId, user.UserId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	reader, ok := h.nodes.(sessionReader)
	if !ok {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "session history is not configured"), w)
		return
	}
	handles := make([]string, 0, len(nodes))
	names := make(map[string]string, len(nodes))
	for _, n := range nodes {
		handles = append(handles, n.Handle)
		// The device's name, not its handle: the portal is showing a person
		// their own laptop, and a 64-character handle names nothing to them.
		names[n.Handle] = n.Name
	}
	sessions, err := reader.SessionsForHandles(handles, 0)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	items := make([]map[string]any, 0, len(sessions))
	for _, session := range sessions {
		name := names[session.Handle]
		if name == "" {
			name = session.Handle
		}
		// ended_at stays null for a session that is still live, which is what
		// lets the portal say "now" rather than inventing an end.
		var ended any
		if session.EndedAt != nil {
			ended = *session.EndedAt
		}
		var ip any
		if session.ClientAddr != "" {
			ip = session.ClientAddr
		}
		items = append(items, map[string]any{
			"started_at": session.StartedAt,
			"ended_at":   ended,
			"device":     name,
			"ip":         ip,
		})
	}
	util.WriteJSONObject(r.Context(), w, items)
}

func (h *handler) meAccess(w http.ResponseWriter, r *http.Request) {
	user, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if h.policy == nil {
		util.WriteJSONObject(r.Context(), w, []any{})
		return
	}
	version, err := h.policy.Current(r.Context())
	if errors.Is(err, karstpolicy.ErrNoVersion) {
		util.WriteJSONObject(r.Context(), w, []any{})
		return
	}
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	document, err := karstpolicy.Parse([]byte(version.Document))
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	reader, ok := h.peerWriter.(portalPeerReader)
	if !ok {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "access explanation is not configured"), w)
		return
	}
	allPeers, err := reader.PortalPeers(r.Context(), user.AccountId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	all := make([]karstpolicy.Node, 0, len(allPeers))
	names := make(map[string]string, len(allPeers))
	var own []karstpolicy.Node
	for _, item := range allPeers {
		n := karstpolicy.Node{Handle: item.Key, User: item.UserID}
		all = append(all, n)
		names[item.Key] = item.Name
		if item.UserID == user.UserId {
			own = append(own, n)
		}
	}
	type explanation struct {
		Destination string    `json:"destination"`
		Rule        int       `json:"rule"`
		Group       string    `json:"group"`
		ChangedAt   time.Time `json:"changed_at"`
		ChangedBy   string    `json:"changed_by"`
	}
	seen := make(map[string]struct{})
	items := make([]explanation, 0)
	for _, source := range own {
		filter, compileErr := document.CompileEgress(source, all)
		if compileErr != nil {
			util.WriteError(r.Context(), compileErr, w)
			return
		}
		for _, rule := range filter.Rules {
			for _, destination := range rule.Dsts {
				for _, port := range rule.Ports {
					label := names[destination]
					if label == "" {
						label = destination
					}
					portText := strconv.FormatUint(uint64(port.First), 10)
					if port.Last != port.First {
						portText += "-" + strconv.FormatUint(uint64(port.Last), 10)
					}
					key := destination + "\x00" + portText + "\x00" + strconv.Itoa(rule.Provenance.Rule)
					if _, duplicate := seen[key]; duplicate {
						continue
					}
					seen[key] = struct{}{}
					group := rule.Provenance.SourceTerm
					if !strings.HasPrefix(group, "group:") {
						group = "direct membership: " + group
					}
					items = append(items, explanation{Destination: label + ":" + portText, Rule: rule.Provenance.Rule, Group: group, ChangedAt: version.CreatedAt, ChangedBy: version.Author})
				}
			}
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Destination < items[j].Destination })
	util.WriteJSONObject(r.Context(), w, items)
}

// fingerprints renders a key list the way a human compares one — SHA-256, as
// spec §8 asks for. An ML-DSA-65 key is 3 904 hex characters and nobody checks
// one by eye, so the console is given the digest and never the key.
func fingerprints(keys [][]byte) []string {
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		sum := sha256.Sum256(k)
		out = append(out, "SHA-256:"+hex.EncodeToString(sum[:]))
	}
	return out
}

// bedrockLog renders the verified chain for the console's log viewer.
//
// Every entry is rendered from the body that was actually signed, never from a
// stored summary: the log is the state, and a display derived from anything
// else could show an operator something the network is not enforcing.
func (h *handler) bedrockLog(w http.ResponseWriter, r *http.Request) {
	user, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if h.chain == nil {
		util.WriteJSONObject(r.Context(), w, map[string]any{"items": []any{}, "next_cursor": nil})
		return
	}
	entries, err := h.chain.All(r.Context(), user.AccountId)
	if err != nil && !errors.Is(err, bedrock.ErrNoLog) {
		util.WriteError(r.Context(), err, w)
		return
	}
	// Verified before rendering. An unverified chain is not a log to show; it
	// is an incident, and the verify endpoint is where that is reported.
	if _, verifyErr := bedrock.VerifyLog(entries); verifyErr != nil && len(entries) > 0 {
		util.WriteError(r.Context(), status.Errorf(status.Internal,
			"the stored Bedrock chain does not verify: %s", verifyErr), w)
		return
	}
	items := make([]any, 0, len(entries))
	for i := range entries {
		items = append(items, describeEntry(&entries[i]))
	}
	util.WriteJSONObject(r.Context(), w, map[string]any{"items": items, "next_cursor": nil})
}

// describeEntry renders one entry for display, parsing the signed body rather
// than trusting any column beside it.
func describeEntry(e *bedrock.Entry) map[string]any {
	out := map[string]any{
		"seq": e.Seq, "time": e.Time, "op": string(e.Op),
		"signatures": len(e.Sigs), "hash": hex.EncodeToString(e.Hash),
	}
	switch e.Op {
	case bedrock.OpGenesis:
		if g, err := bedrock.ParseGenesis(e.Body); err == nil {
			out["zone"] = g.Zone
			out["roots"] = fingerprints(g.Roots)
			out["root_threshold"] = g.K
			out["authorities"] = fingerprints(g.Authorities)
			out["quorum"] = g.Q
			// ADR-0016: nil/empty until an operator opts in, which is itself
			// meaningful — an authority quorum still anchors either way.
			out["anchor_keys"] = fingerprints(g.AnchorKeys)
		}
	case bedrock.OpAuthorityList:
		if a, err := bedrock.ParseAuthorityList(e.Body); err == nil {
			out["authorities"] = fingerprints(a.Authorities)
			out["quorum"] = a.Q
			out["anchor_keys"] = fingerprints(a.AnchorKeys)
		}
	case bedrock.OpNodeSign:
		if n, err := bedrock.ParseNodeSign(e.Body); err == nil {
			out["handle"] = n.Handle
			out["identity"] = fingerprints([][]byte{n.IdentityKey})[0]
			out["kem"] = fingerprints([][]byte{n.KemPublicKey})[0]

			out["not_before"] = n.NotBefore
			out["expiry"] = n.Expiry
		}
	case bedrock.OpNodeRevoke:
		if rv, err := bedrock.ParseNodeRevoke(e.Body); err == nil {
			out["handle"] = rv.Handle
			out["reason"] = rv.Reason
			out["effective"] = rv.Effective
		}
	case bedrock.OpQuorumChange:
		if q, err := bedrock.ParseQuorumChange(e.Body); err == nil {
			out["quorum"] = q
		}
	case bedrock.OpAnchor:
		if a, err := bedrock.ParseAnchor(e.Body); err == nil {
			out["audit_seq"] = a.AuditSeq
			out["audit_head"] = string(a.AuditHead)
		}
	case bedrock.OpDisable:
		if reason, err := bedrock.ParseDisable(e.Body); err == nil {
			out["reason"] = reason
		}
	}
	return out
}

// bedrockLogVerify re-verifies the stored chain on demand.
//
// The server verifies on every import and every read, so this endpoint exists
// for the operator who wants to ask rather than assume — and it reports the
// failing sequence, because "the chain is broken" without a position is not
// something anyone can act on.
func (h *handler) bedrockLogVerify(w http.ResponseWriter, r *http.Request) {
	user, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if h.chain == nil {
		util.WriteJSONObject(r.Context(), w, map[string]any{"verified": false, "reason": "no Bedrock log"})
		return
	}
	entries, err := h.chain.All(r.Context(), user.AccountId)
	if err != nil && !errors.Is(err, bedrock.ErrNoLog) {
		util.WriteError(r.Context(), err, w)
		return
	}
	if len(entries) == 0 {
		util.WriteJSONObject(r.Context(), w, map[string]any{"verified": false, "reason": "no Bedrock log"})
		return
	}
	state, verifyErr := bedrock.VerifyLog(entries)
	if verifyErr != nil {
		util.WriteJSONObject(r.Context(), w, map[string]any{
			"verified": false, "entries": len(entries), "reason": verifyErr.Error(),
		})
		return
	}
	util.WriteJSONObject(r.Context(), w, map[string]any{
		"verified": true, "entries": len(entries),
		"head": hex.EncodeToString(state.Head), "head_seq": state.HeadSeq,
		"covered_count": len(state.Covered), "disabled": state.Disabled,
	})
}
func (h *handler) bedrockRequests(w http.ResponseWriter, r *http.Request) {
	user, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	store, ok := h.chain.(bedrockPendingStore)
	if !ok {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "Bedrock request store is not configured"), w)
		return
	}
	request, err := store.Pending(r.Context(), user.AccountId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if request == nil {
		util.WriteJSONObject(r.Context(), w, []any{})
		return
	}
	util.WriteJSONObject(r.Context(), w, []any{map[string]any{"id": request.ID, "created_at": request.CreatedAt, "payload_hash": request.PayloadHash}})
}
func (h *handler) bedrockRequestsExport(w http.ResponseWriter, r *http.Request) {
	user, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	store, ok := h.chain.(bedrockPendingStore)
	if !ok {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "Bedrock request store is not configured"), w)
		return
	}
	request, err := store.Pending(r.Context(), user.AccountId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if request == nil {
		state, err := h.bedrockState(r.Context(), user.AccountId)
		if err != nil {
			util.WriteError(r.Context(), err, w)
			return
		}
		if state == nil {
			util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "Bedrock genesis must be imported before node signing requests can be created"), w)
			return
		}
		keys, err := h.enrolledKeys(r.Context(), user.AccountId, user.UserId)
		if err != nil {
			util.WriteError(r.Context(), err, w)
			return
		}
		entries := make([]bedrock.Entry, 0)
		for _, handle := range bedrock.UncoveredAt(state, keys, time.Now().UTC().Unix()) {
			identity, err := h.nodes.Get(handle)
			if err != nil {
				util.WriteError(r.Context(), err, w)
				return
			}
			entries = append(entries, bedrock.Entry{Seq: state.HeadSeq + uint64(len(entries)) + 1, Time: time.Now().UTC().Unix(), Op: bedrock.OpNodeSign, Body: bedrock.NodeSignBody(handle, identity.PublicKey, identity.KemPublicKey, 0, 0)})
		}
		if len(entries) == 0 {
			util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "all enrolled nodes are already covered"), w)
			return
		}
		request, err = store.CreatePending(r.Context(), user.AccountId, entries)
		if err != nil {
			util.WriteError(r.Context(), err, w)
			return
		}
	}
	log, err := h.chain.All(r.Context(), user.AccountId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	entries, err := bedrock.DecodeLog(request.Entries)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	payload := renderBedrockRequest(log, entries)
	util.WriteJSONObject(r.Context(), w, map[string]any{"format": "bedrock-signed-bundle-v1", "payload": base64.StdEncoding.EncodeToString([]byte(payload))})
}
func (h *handler) bedrockResponsesImport(w http.ResponseWriter, r *http.Request) {
	user, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	store, ok := h.chain.(bedrockPendingStore)
	if !ok {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "Bedrock request store is not configured"), w)
		return
	}
	var wrapper struct {
		Format  string `json:"format"`
		Payload string `json:"payload"`
	}
	if err := json.NewDecoder(r.Body).Decode(&wrapper); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}
	if wrapper.Format != "bedrock-signed-bundle-v1" {
		util.WriteErrorResponse("unsupported Bedrock bundle format", http.StatusBadRequest, w)
		return
	}
	raw, err := base64.StdEncoding.DecodeString(wrapper.Payload)
	if err != nil {
		util.WriteErrorResponse("Bedrock bundle payload is not base64", http.StatusBadRequest, w)
		return
	}
	var response struct {
		Bundle     string `json:"bundle"`
		Kind       string `json:"kind"`
		Signatures []struct {
			Seq         uint64 `json:"seq"`
			SignerIndex uint32 `json:"signer_index"`
			Sig         string `json:"sig"`
		} `json:"signatures"`
	}
	if err := json.Unmarshal(raw, &response); err != nil || response.Bundle != "bedrock-bundle-v1" || response.Kind != "response" {
		util.WriteErrorResponse("invalid offline signer response", http.StatusBadRequest, w)
		return
	}
	signatures := make(map[uint64][]bedrock.Signature)
	for _, signature := range response.Signatures {
		sig, err := hex.DecodeString(signature.Sig)
		if err != nil {
			util.WriteErrorResponse("invalid offline signature", http.StatusBadRequest, w)
			return
		}
		signatures[signature.Seq] = append(signatures[signature.Seq], bedrock.Signature{SignerIndex: signature.SignerIndex, Sig: sig})
	}
	if err := store.CommitPending(r.Context(), user.AccountId, signatures); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// bedrockBootstrapImport accepts the one root-signed genesis entry that starts
// an account's log. It is deliberately separate from authority-response import:
// bootstrap is a root ceremony, and accepting an arbitrary historical log here
// would make a recovery path indistinguishable from an account takeover path.
func (h *handler) bedrockBootstrapImport(w http.ResponseWriter, r *http.Request) {
	user, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	store, ok := h.chain.(bedrockImportStore)
	if !ok {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "Bedrock log store is not configured"), w)
		return
	}
	var bundle struct {
		Format  string `json:"format"`
		Payload string `json:"payload"`
	}
	if err := json.NewDecoder(r.Body).Decode(&bundle); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}
	if bundle.Format != "bedrock-log-v1" {
		util.WriteErrorResponse("unsupported Bedrock bootstrap format", http.StatusBadRequest, w)
		return
	}
	raw, err := base64.StdEncoding.DecodeString(bundle.Payload)
	if err != nil {
		util.WriteErrorResponse("Bedrock bootstrap payload is not base64", http.StatusBadRequest, w)
		return
	}
	entries, err := bedrock.DecodeLog(raw)
	if err != nil || len(entries) != 1 || entries[0].Op != bedrock.OpGenesis {
		util.WriteErrorResponse("Bedrock bootstrap must contain exactly one genesis entry", http.StatusBadRequest, w)
		return
	}
	if _, err := store.State(r.Context(), user.AccountId); err == nil {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "Bedrock is already bootstrapped for this account"), w)
		return
	} else if !errors.Is(err, bedrock.ErrNoLog) {
		util.WriteError(r.Context(), err, w)
		return
	}
	if err := store.Import(r.Context(), user.AccountId, entries); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// renderBedrockRequest deliberately matches karst-bedrock's small offline JSON
// grammar. The signing input is absent: the offline tool recomputes it from
// this log and these pending entries, which prevents a compromised server from
// asking an authority to sign arbitrary bytes.
func renderBedrockRequest(log, pending []bedrock.Entry) string {
	// This is intentionally the exact stable formatting emitted by
	// karst-bedrock's hand-written encoder. The offline parser is deliberately
	// dependency-free and recognizes pending entries by that shape.
	var out strings.Builder
	fmt.Fprintf(&out, "{\n  \"bundle\": \"bedrock-bundle-v1\",\n  \"kind\": \"request\",\n  \"log\": \"%s\",\n  \"pending\": [\n", hex.EncodeToString(bedrock.EncodeLog(log)))
	for index, value := range pending {
		fmt.Fprintf(&out, "    { \"seq\": %d, \"time\": %d, \"op\": \"%s\", \"body\": \"%s\" }", value.Seq, value.Time, value.Op, hex.EncodeToString(value.Body))
		if index+1 < len(pending) {
			out.WriteByte(',')
		}
		out.WriteByte('\n')
	}
	out.WriteString("  ]\n}\n")
	return out.String()
}

func (h *handler) relayHealth(w http.ResponseWriter, r *http.Request) {
	if !requireUser(w, r) {
		return
	}
	if h.relays == nil {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "relay registry is not configured"), w)
		return
	}
	relays, err := h.relays.List(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	for _, relay := range relays {
		if relay.ID == mux.Vars(r)["relayId"] {
			util.WriteJSONObject(r.Context(), w, h.healthFor(r.Context(), relay.ID))
			return
		}
	}
	util.WriteError(r.Context(), status.Errorf(status.NotFound, "relay not found"), w)
}

// enrolledKeys returns the caller's authorized nodes as the coverage query
// needs them: handle to the datapath keys the netmap presents for that node.
//
// The keys, not just the handles. Coverage binds a handle to its ML-KEM
// static key (spec §6.1), so a check that passed only handles would
// report a node as covered while the log covers a *different* key under that
// name — which is the substitution the mechanism exists to catch.
func (h *handler) enrolledKeys(ctx context.Context, accountID, userID string) (map[string]bedrock.PeerKeys, error) {
	peers, err := h.peers.GetPeers(ctx, accountID, userID, "", "")
	if err != nil {
		return nil, err
	}
	out := make(map[string]bedrock.PeerKeys, len(peers))
	for _, p := range peers {
		identity, err := h.nodes.Get(p.Key)
		if errors.Is(err, node.ErrUnknownNode) {
			continue // A fork peer is not necessarily an enrolled Karst node.
		}
		if err != nil {
			return nil, err
		}
		out[identity.Handle] = bedrock.PeerKeys{
			KemPublicKey: identity.KemPublicKey,
		}
	}
	return out, nil
}

// bedrockState returns the verified chain, or nil when the account has no log.
// A missing log is a normal state, not an error: most accounts never turn
// Bedrock on.
func (h *handler) bedrockState(ctx context.Context, accountID string) (*bedrock.State, error) {
	if h.chain == nil {
		return nil, nil
	}
	state, err := h.chain.State(ctx, accountID)
	if errors.Is(err, bedrock.ErrNoLog) {
		return nil, nil
	}
	return state, err
}

func (h *handler) bedrockStatus(w http.ResponseWriter, r *http.Request) {
	user, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if h.bedrock == nil {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "Bedrock is not configured"), w)
		return
	}
	configuration, err := h.bedrock.Configuration(r.Context(), user.AccountId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	enrolled, err := h.enrolledKeys(r.Context(), user.AccountId, user.UserId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	state, err := h.bedrockState(r.Context(), user.AccountId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	uncovered := bedrock.UncoveredAt(state, enrolled, time.Now().UTC().Unix())

	body := map[string]any{
		"mode": configuration.Mode, "quorum": configuration.Quorum,
		"roots": []any{}, "authorities": []any{}, "uncovered_handles": uncovered,
	}
	if configuration.LocationLat != nil {
		body["location"] = geo.Location{Lat: *configuration.LocationLat, Lon: *configuration.LocationLon, Label: configuration.LocationLabel}
	}
	if state != nil {
		body["quorum"] = state.Q
		body["zone"] = state.Zone
		body["head"] = hex.EncodeToString(state.Head)
		body["head_seq"] = state.HeadSeq
		body["disabled"] = state.Disabled
		body["roots"] = fingerprints(state.Roots)
		body["authorities"] = fingerprints(state.Authorities)
		body["covered_count"] = len(state.Covered)
	}
	util.WriteJSONObject(r.Context(), w, body)
}

func (h *handler) bedrockMode(w http.ResponseWriter, r *http.Request) {
	user, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if h.bedrock == nil {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "Bedrock is not configured"), w)
		return
	}
	var request struct {
		Mode         string   `json:"mode"`
		Acknowledged []string `json:"acknowledged_cut_off_handles"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}
	enrolled, err := h.enrolledKeys(r.Context(), user.AccountId, user.UserId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	state, err := h.bedrockState(r.Context(), user.AccountId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	at := time.Now().UTC().Unix()
	configuration, err := h.bedrock.SetMode(r.Context(), user.AccountId, request.Mode, request.Acknowledged, state, enrolled, at)
	if errors.Is(err, bedrock.ErracknowledgmentMismatch) {
		required := bedrock.UncoveredAt(state, enrolled, at)
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]any{"code": "acknowledgment_mismatch", "message": err.Error(), "required_cut_off_handles": required})
		return
	}
	if err != nil {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "%s", err), w)
		return
	}
	util.WriteJSONObject(r.Context(), w, map[string]any{"mode": configuration.Mode, "quorum": configuration.Quorum, "roots": []any{}, "authorities": []any{}})
}

func (h *handler) relaysList(w http.ResponseWriter, r *http.Request) {
	if _, err := nbcontext.GetUserAuthFromContext(r.Context()); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if h.relays == nil {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "relay registry is not configured"), w)
		return
	}
	relays, err := h.relays.List(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	result := make([]relayResponse, 0, len(relays))
	for _, relay := range relays {
		result = append(result, h.relayResponseFor(r.Context(), relay))
	}
	util.WriteJSONObject(r.Context(), w, result)
}
func (h *handler) relaysCreate(w http.ResponseWriter, r *http.Request) {
	if _, err := nbcontext.GetUserAuthFromContext(r.Context()); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if h.relays == nil {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "relay registry is not configured"), w)
		return
	}
	var entry relayreg.Entry
	if err := json.NewDecoder(r.Body).Decode(&entry); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}
	relay, err := h.relays.Create(r.Context(), entry)
	if errors.Is(err, relayreg.ErrExists) {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "relay already exists"), w)
		return
	}
	if err != nil {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "%s", err), w)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(h.relayResponseFor(r.Context(), *relay)); err != nil {
		util.WriteError(r.Context(), err, w)
	}
}
func (h *handler) relaysDelete(w http.ResponseWriter, r *http.Request) {
	if _, err := nbcontext.GetUserAuthFromContext(r.Context()); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if h.relays == nil {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "relay registry is not configured"), w)
		return
	}
	if err := h.relays.Delete(r.Context(), mux.Vars(r)["relayId"]); errors.Is(err, relayreg.ErrNotFound) {
		util.WriteError(r.Context(), status.Errorf(status.NotFound, "relay not found"), w)
		return
	} else if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// relayDeenrollRequest is what a karst-scaler Kubernetes (or AWS) relay
// driver sends to remove the registry entry for a relay instance it has
// destroyed (issue #319). Keyed by address, not id, mirroring
// turnDeenrollRequest's own shape and for the same underlying reason --
// the driver computes a to-be-destroyed instance's own address
// deterministically at create() time and has no reason to List first just
// to recover the id relaysDelete expects. Unlike a TURN instance's uri,
// though, a relay's registry id cannot be derived from its address either
// -- see relayreg.Store.DeleteByAddress's own doc comment for why that
// matters to how this request is handled, not just how it is shaped.
//
// Exactly one of Address/TLSServerName must be set -- the two keys two
// different drivers each already have deterministically at their own
// create() time, never both: the Kubernetes driver's own
// StatefulSet-pod-DNS-name address (#319) is knowable before an EC2
// instance's own registered address is (resolved by the relay itself via
// IMDS, after boot -- never known to that driver), but an EC2 instance's
// own TLSServerName (derived from its enrollment token, see
// bins/karst-scaler-aws's own bundle::tls_server_name) is knowable just as
// early as the Kubernetes driver's address is (#329). One request shape
// serving both, rather than two near-identical routes for the same
// underlying operation.
type relayDeenrollRequest struct {
	Address       string `json:"address,omitempty"`
	TLSServerName string `json:"tls_server_name,omitempty"`
}

// relayDeenroll lets the Scaler role remove a relayreg.Store entry without
// the generic Delete grant relaysDelete needs -- see this route's own
// entry in the Scaler hard-allowlist (above, in karstAuthorization) for
// why this is shaped as a POST/Create request rather than a widened
// Delete permission, the same reasoning turnDeenroll's own doc comment
// gives for TURN. Runs through the ordinary karstRouter/karstAuthorization
// stack: the caller is karst-scaler's own drive loop, which already holds
// a session-bearing Scaler PAT.
func (h *handler) relayDeenroll(w http.ResponseWriter, r *http.Request) {
	if _, err := nbcontext.GetUserAuthFromContext(r.Context()); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if h.relays == nil {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "relay registry is not configured"), w)
		return
	}
	var req relayDeenrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}
	var err error
	switch {
	case req.Address != "" && req.TLSServerName == "":
		err = h.relays.DeleteByAddress(r.Context(), req.Address)
	case req.TLSServerName != "" && req.Address == "":
		err = h.relays.DeleteByTLSServerName(r.Context(), req.TLSServerName)
	default:
		util.WriteErrorResponse("exactly one of address or tls_server_name is required", http.StatusBadRequest, w)
		return
	}
	if errors.Is(err, relayreg.ErrNotFound) {
		util.WriteError(r.Context(), status.Errorf(status.NotFound, "relay not found"), w)
		return
	} else if err != nil {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "%s", err), w)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// relayEnrollTokensPath, turnEnrollTokensPath, turnDeenrollPath and
// relayDeenrollPath are the only four routes the Scaler role's hard
// allowlist in karstAuthorization permits — see that allowlist's own
// comment, relayEnrollTokensCreate below, turnEnrollTokensCreate,
// turnDeenroll, and relayDeenroll.
const relayEnrollTokensPath = "/karst/v1/relays/enroll-tokens"
const turnEnrollTokensPath = "/karst/v1/turn/enroll-tokens"
const turnDeenrollPath = "/karst/v1/turn/deenroll"
const relayDeenrollPath = "/karst/v1/relays/deenroll"

// relayEnrollTokenRequest is what karst-scaler's own drive loop (ADR-0045
// §7 Phase 2) sends when it has just created a relay instance and needs a
// credential for that instance to complete its own roster admission with.
type relayEnrollTokenRequest struct {
	// PoolID names the pool the new instance belongs to, carried into the
	// minted key's own Name only for an operator reading the Auth keys
	// console later — it plays no role in redemption.
	PoolID string `json:"pool_id"`
	// ExpiresInSecs overrides the default expiry (see
	// DefaultAccountManager.MintRelayEnrollKey) — 0 means "use the
	// default," not "never expires": this credential has no unlimited
	// option, the same ADR-0045 §6 posture as the scaling circuit breaker.
	ExpiresInSecs int64 `json:"expires_in_secs,omitempty"`
}

type relayEnrollTokenResponse struct {
	Token string `json:"token"`
}

// relayEnrollTokensCreate mints ADR-0045 §6's "short-lived, single-use
// enrollment token minted for that specific instance" — the credential a
// relay the scaler just created redeems at relaysEnroll below, in place of
// an admin pasting its public key into the console (relaysCreate above).
// Reached only by a caller karstAuthorization has already resolved to the
// Scaler role (or an Admin/Owner, who could already reach relaysCreate
// directly) — never the relay itself, which has no session yet; that is
// exactly the asymmetry this token exists to bridge.
func (h *handler) relayEnrollTokensCreate(w http.ResponseWriter, r *http.Request) {
	user, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	minter, ok := h.accounts.(interface {
		MintRelayEnrollKey(context.Context, string, string, time.Duration) (string, error)
	})
	if !ok {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "relay enrollment is not configured"), w)
		return
	}
	var req relayEnrollTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}
	token, err := minter.MintRelayEnrollKey(r.Context(), user.AccountId, req.PoolID, time.Duration(req.ExpiresInSecs)*time.Second)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(relayEnrollTokenResponse{Token: token}); err != nil {
		util.WriteError(r.Context(), err, w)
	}
}

// bearerToken reads the `Authorization: Bearer <token>` header
// relaysEnroll's own caller — a relay with no session, only its minted
// enroll token — authenticates with. Not reused from anywhere else in this
// tree on purpose: see relaysEnroll's own doc comment for why this endpoint
// is this package's one deliberate exception to parsing a credential
// itself.
func bearerToken(r *http.Request) string {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, prefix) {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(h, prefix))
}

// relaysEnroll lets a relay the scaler just created complete its own
// roster admission with no admin session — ADR-0045 §6's signed-enrollment
// requirement; see relayEnrollTokensCreate above for where its credential
// comes from. Deliberately registered on the parent router, not
// karstRouter (see RegisterEndpoints): every karstRouter route requires an
// authenticated user/PAT context before any handler runs
// (karstAuthorization's own first line), which a relay calling this for
// the very first time does not have. The token itself — short-lived,
// single-use, mintable only by a Scaler-role-gated caller — is this
// endpoint's entire authentication; see the package doc comment's one
// named exception.
//
// Does not add a proof-of-possession challenge for the submitted
// IdentityKey — a relay registering here is no less trusted than one an
// admin registers through relaysCreate today, which has the identical gap
// (the public key is simply asserted, never challenged, at registration
// time either way). Closing that gap for both paths at once is follow-up
// work, not something this endpoint needs to solve alone.
func (h *handler) relaysEnroll(w http.ResponseWriter, r *http.Request) {
	token := bearerToken(r)
	if token == "" {
		util.WriteError(r.Context(), status.Errorf(status.Unauthorized, "relay enrollment requires a bearer token"), w)
		return
	}
	if h.relays == nil {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "relay registry is not configured"), w)
		return
	}
	consumer, ok := h.accounts.(interface {
		ConsumeRelayEnrollKey(context.Context, string) (string, string, error)
	})
	if !ok {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "relay enrollment is not configured"), w)
		return
	}
	accountID, keyID, err := consumer.ConsumeRelayEnrollKey(r.Context(), token)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	var entry relayreg.Entry
	if err := json.NewDecoder(r.Body).Decode(&entry); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}
	ctx := relayreg.WithAccount(r.Context(), accountID)
	relay, err := h.relays.Create(ctx, entry)
	if errors.Is(err, relayreg.ErrExists) {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "relay already exists"), w)
		return
	}
	if err != nil {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "%s", err), w)
		return
	}
	if h.audit != nil {
		if _, err := h.audit.Append(audit.WithAccount(ctx, accountID), keyID, "karst.relays.enroll", "relay", relay.ID); err != nil {
			// Not fatal -- auditMutations' own doc comment gives the same
			// reasoning: an audit outage must not turn a working
			// admission path into an impossible one.
			log.WithContext(r.Context()).Errorf("append relay-enroll audit event: %v", err)
		}
	}
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(h.relayResponseFor(r.Context(), *relay)); err != nil {
		util.WriteError(r.Context(), err, w)
	}
}

// turnEnrollTokenRequest is what provisions a new TURN server (today, an
// operator's own script or console action; ADR-0045 §7b names a future
// karst-scaler driver as the eventual caller, not built yet) sends to get
// a credential that server redeems at turnEnroll below, in place of an
// admin pasting its URI into the console (turnsCreate above). No PoolID
// the way relayEnrollTokenRequest has one: no pool concept exists for
// TURN servers anywhere in this system yet.
type turnEnrollTokenRequest struct {
	// ExpiresInSecs overrides the default expiry (see
	// DefaultAccountManager.MintTurnEnrollKey) — 0 means "use the
	// default," not "never expires," the same posture
	// relayEnrollTokenRequest's own field has.
	ExpiresInSecs int64 `json:"expires_in_secs,omitempty"`
}

type turnEnrollTokenResponse struct {
	Token string `json:"token"`
}

// turnEnrollTokensCreate mints ADR-0045 §7b's TURN counterpart of
// relayEnrollTokensCreate's own "short-lived, single-use enrollment
// token" — see that function's own doc comment for the full reasoning,
// which applies unchanged here.
func (h *handler) turnEnrollTokensCreate(w http.ResponseWriter, r *http.Request) {
	user, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	minter, ok := h.accounts.(interface {
		MintTurnEnrollKey(context.Context, string, time.Duration) (string, error)
	})
	if !ok {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "turn enrollment is not configured"), w)
		return
	}
	var req turnEnrollTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}
	token, err := minter.MintTurnEnrollKey(r.Context(), user.AccountId, time.Duration(req.ExpiresInSecs)*time.Second)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(turnEnrollTokenResponse{Token: token}); err != nil {
		util.WriteError(r.Context(), err, w)
	}
}

// turnEnroll lets a newly-provisioned TURN server register itself with no
// admin session — ADR-0045 §7b's TURN counterpart of relaysEnroll above;
// see that function's own doc comment for why this is registered on the
// parent router rather than karstRouter, and for the token being this
// endpoint's entire authentication. Unlike a relay, a TURN server has no
// identity key to assert at all (RFC 8656 authenticates the client to the
// server, never the reverse — see turncred's own package doc), so there is
// no analogous proof-of-possession gap to note here: the submitted
// [turncred.Entry] (a URI and a region) carries no identity claim in the
// first place.
func (h *handler) turnEnroll(w http.ResponseWriter, r *http.Request) {
	token := bearerToken(r)
	if token == "" {
		util.WriteError(r.Context(), status.Errorf(status.Unauthorized, "turn enrollment requires a bearer token"), w)
		return
	}
	if h.turns == nil {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "turn registry is not configured"), w)
		return
	}
	consumer, ok := h.accounts.(interface {
		ConsumeTurnEnrollKey(context.Context, string) (string, string, error)
	})
	if !ok {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "turn enrollment is not configured"), w)
		return
	}
	accountID, keyID, err := consumer.ConsumeTurnEnrollKey(r.Context(), token)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	var entry turncred.Entry
	if err := json.NewDecoder(r.Body).Decode(&entry); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}
	ctx := turncred.WithAccount(r.Context(), accountID)
	turn, err := h.turns.Create(ctx, entry)
	if errors.Is(err, turncred.ErrExists) {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "turn server already exists"), w)
		return
	}
	if err != nil {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "%s", err), w)
		return
	}
	if h.audit != nil {
		if _, err := h.audit.Append(audit.WithAccount(ctx, accountID), keyID, "karst.turn.enroll", "turn", turn.ID); err != nil {
			// Not fatal -- relaysEnroll's own comment gives the same
			// reasoning: an audit outage must not turn a working
			// admission path into an impossible one.
			log.WithContext(r.Context()).Errorf("append turn-enroll audit event: %v", err)
		}
	}
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(turn); err != nil {
		util.WriteError(r.Context(), err, w)
	}
}

// nocComponents is the NOC view's map data source (#241 Phase 1a,
// ADR-0046/ADR-0047, extended to ADR-0046 §1's full component list): every
// relay, TURN server, exit-node/subnet-router gateway group, and the
// account's control-plane/Bedrock declared locations, reshaped into the one
// nocComponent union the map draws. Shows nothing a console operator with
// read access to each underlying page could not already see there, only
// drawn on a map instead of five separate tables.
//
// Audit logging here is explicit rather than left to auditMutations
// (nodes.go's mutation-logging middleware), because that middleware
// deliberately skips every GET, and ADR-0046 §6 requires every NOC view load
// to be logged regardless of HTTP method.
func (h *handler) nocComponents(w http.ResponseWriter, r *http.Request) {
	user, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	var result []nocComponent

	if h.relays != nil {
		relays, err := h.relays.List(r.Context())
		if err != nil {
			util.WriteError(r.Context(), err, w)
			return
		}
		for _, relay := range relays {
			resp := h.relayResponseFor(r.Context(), relay)
			label := resp.Region
			if resp.Location != nil && resp.Location.Label != "" {
				label = resp.Location.Label
			}
			result = append(result, nocComponent{Kind: "relay", ID: resp.ID, Label: label, Health: resp.Health.AdmissionState, Location: resp.Location})
		}
	}

	if h.turns != nil {
		turns, err := h.turns.List(r.Context())
		if err != nil {
			util.WriteError(r.Context(), err, w)
			return
		}
		for _, turn := range turns {
			location := turn.LocationFor()
			label := turn.URI
			if location != nil && location.Label != "" {
				label = location.Label
			}
			result = append(result, nocComponent{Kind: "turn", ID: turn.ID, Label: label, Location: location})
		}
	}

	if h.groupLocations != nil && h.routes != nil {
		groupComponents, err := h.routeGroupComponents(r.Context(), user.AccountId, user.UserId)
		if err != nil {
			util.WriteError(r.Context(), err, w)
			return
		}
		result = append(result, groupComponents...)
	}

	if h.controlPlaneLocation != nil {
		location, err := h.controlPlaneLocation.Get(r.Context())
		if err != nil && !errors.Is(err, cplocation.ErrNotFound) {
			util.WriteError(r.Context(), err, w)
			return
		}
		component := nocComponent{Kind: "control_plane", ID: "control-plane", Label: "Control plane"}
		if err == nil {
			component.Location = &geo.Location{Lat: location.Lat, Lon: location.Lon, Label: location.Label}
			if location.Label != "" {
				component.Label = location.Label
			}
		}
		result = append(result, component)
	}

	if h.bedrock != nil {
		cfg, err := h.bedrock.Configuration(r.Context(), user.AccountId)
		if err != nil {
			util.WriteError(r.Context(), err, w)
			return
		}
		component := nocComponent{Kind: "bedrock", ID: "bedrock", Label: "Bedrock"}
		if cfg.LocationLat != nil {
			component.Location = &geo.Location{Lat: *cfg.LocationLat, Lon: *cfg.LocationLon, Label: cfg.LocationLabel}
			if cfg.LocationLabel != "" {
				component.Label = cfg.LocationLabel
			}
		}
		result = append(result, component)
	}

	if h.audit != nil {
		if _, err := h.audit.Append(r.Context(), user.UserId, "karst.noc.view", "components", ""); err != nil {
			util.WriteError(r.Context(), err, w)
			return
		}
	}
	util.WriteJSONObject(r.Context(), w, result)
}

// routeGroupComponents resolves the "route" kind: one marker per gateway
// group that both has a declared location and is actually named in
// peer_groups by at least one enabled exit or subnet route. A group with a
// declared location that no enabled route currently uses is not placed --
// it is still visible wherever groups are listed, just not asserted here to
// be an active gateway.
func (h *handler) routeGroupComponents(ctx context.Context, accountID, userID string) ([]nocComponent, error) {
	groupLocations, err := h.groupLocations.List(ctx)
	if err != nil {
		return nil, err
	}
	if len(groupLocations) == 0 {
		return nil, nil
	}
	locationByGroup := make(map[string]grouplocation.StoredGroupLocation, len(groupLocations))
	for _, gl := range groupLocations {
		locationByGroup[gl.GroupID] = gl
	}

	routes, err := h.routes.ListRoutes(ctx, accountID, userID)
	if err != nil {
		return nil, err
	}
	// Issues #281, #371: looked up once, by route_id, then summed per group
	// below -- a group can serve more than one route, and a route's
	// throughput is reported keyed by route_id (the unit a gateway is
	// actually authorized for), never by group directly.
	var telemetry map[string]routetelemetry.StoredRouteBytes
	if h.routeTelemetry != nil {
		telemetry, err = h.routeTelemetry.LatestByRoute(ctx, accountID)
		if err != nil {
			return nil, err
		}
	}
	netIDsByGroup := make(map[string][]string)
	bytesByGroup := make(map[string]int64)
	packetsByGroup := make(map[string]int64)
	ingressBytesByGroup := make(map[string]int64)
	ingressPacketsByGroup := make(map[string]int64)
	reportedByGroup := make(map[string]bool)
	for _, r := range routes {
		if !r.Enabled {
			continue
		}
		for _, groupID := range r.PeerGroups {
			if _, declared := locationByGroup[groupID]; !declared {
				continue
			}
			netIDsByGroup[groupID] = append(netIDsByGroup[groupID], string(r.NetID))
			if report, ok := telemetry[string(r.GetResourceID())]; ok {
				bytesByGroup[groupID] += int64(report.Bytes)
				packetsByGroup[groupID] += int64(report.Packets)
				ingressBytesByGroup[groupID] += int64(report.IngressBytes)
				ingressPacketsByGroup[groupID] += int64(report.IngressPackets)
				reportedByGroup[groupID] = true
			}
		}
	}

	result := make([]nocComponent, 0, len(netIDsByGroup))
	for groupID, netIDs := range netIDsByGroup {
		sort.Strings(netIDs)
		gl := locationByGroup[groupID]
		label := strings.Join(netIDs, ", ")
		if gl.Label != "" {
			label = gl.Label
		}
		component := nocComponent{
			Kind:     "route",
			ID:       groupID,
			Label:    label,
			Location: &geo.Location{Lat: gl.Lat, Lon: gl.Lon, Label: gl.Label},
		}
		if reportedByGroup[groupID] {
			bytes, packets := bytesByGroup[groupID], packetsByGroup[groupID]
			ingressBytes, ingressPackets := ingressBytesByGroup[groupID], ingressPacketsByGroup[groupID]
			component.Bytes, component.Packets = &bytes, &packets
			component.IngressBytes, component.IngressPackets = &ingressBytes, &ingressPackets
		}
		result = append(result, component)
	}
	// Deterministic order: every other list in this response is already
	// ordered by its own store (List's own "Order(id)"/"Order(group_id)");
	// this one is built from a map and must not depend on Go's randomized
	// iteration.
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}

// nocRelay is the NOC map's drill-down for one relay — the marker-click
// detail panel. There is no relayReader.Get; relay counts are small enough
// (Phase 1a is relays only, not the wider fleet later phases add) that
// filtering the same List this account already pays for elsewhere is
// simpler than adding a new store method for one caller.
func (h *handler) nocRelay(w http.ResponseWriter, r *http.Request) {
	user, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if h.relays == nil {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "relay registry is not configured"), w)
		return
	}
	relayID := mux.Vars(r)["relayId"]
	relays, err := h.relays.List(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	for _, relay := range relays {
		if relay.ID != relayID {
			continue
		}
		resp := h.relayResponseFor(r.Context(), relay)
		if h.audit != nil {
			if _, err := h.audit.Append(r.Context(), user.UserId, "karst.noc.drilldown", "relay/"+relayID, ""); err != nil {
				util.WriteError(r.Context(), err, w)
				return
			}
		}
		util.WriteJSONObject(r.Context(), w, resp)
		return
	}
	util.WriteError(r.Context(), status.Errorf(status.NotFound, "relay not found"), w)
}

// regionDemandResponse mirrors relayreg.RegionDemand with the JSON spelling
// karst-openapi.yml's RegionDemand schema declares; RegionDemand itself
// carries no JSON tags, since relayreg has no reason to know the API's
// field-naming convention.
type regionDemandResponse struct {
	Region       string `json:"region"`
	AccountID    string `json:"account_id"`
	RTTUnder20ms int64  `json:"rtt_under_20ms"`
	RTT20To50ms  int64  `json:"rtt_20_to_50ms"`
	RTT50To100ms int64  `json:"rtt_50_to_100ms"`
	RTTOver100ms int64  `json:"rtt_over_100ms"`
}

// anchorHistogramResponse mirrors regionallow.AnchorHistogramEntry, for the
// same reason regionDemandResponse mirrors relayreg.RegionDemand.
type anchorHistogramResponse struct {
	Provider string `json:"provider"`
	Region   string `json:"region"`
	Bucket   string `json:"bucket"`
	Count    int64  `json:"count"`
}

// requireAdvisorRole enforces the RBAC boundary ADR-0045 §7 Phase 1 actually
// needs for the two demand endpoints below, which karstAuthorization's
// blanket gate cannot express: that gate only checks module-level Read
// access to modules.KarstControl, which every existing read-capable role
// (NOC, Auditor, NetworkAdmin, Admin, Owner) already holds within their own
// account. Without this check, the module gate alone would let any of them
// see every OTHER tenant's aquifer-level demand the instant this route
// exists — defeating the entire reason UserRoleAdvisor was introduced
// instead of reusing one of those roles (see its own doc comment). The role
// comes from context, not a fresh store lookup: karstAuthorization's
// ValidateUserPermissions call already put it there via nbcontext.WithRole.
func requireAdvisorRole(ctx context.Context) error {
	role, ok := nbcontext.RoleFromContext(ctx)
	if !ok {
		return status.Errorf(status.Internal, "failed to get user role from context")
	}
	if types.UserRole(role) != types.UserRoleAdvisor {
		return status.Errorf(status.PermissionDenied, "this endpoint requires the advisor role")
	}
	return nil
}

// demandRegions is ADR-0045 §7 Phase 1's per-(region, aquifer) demand feed
// — §4a's RTT histogram, aggregated across every account's relays.
// Deliberately cross-account; see relayreg.Store.DemandByRegion's own doc
// comment for why. Audit-logged on every call — more deliberately than
// nocComponents's karst.noc.view above, since every call here sees every
// tenant's data, not just the caller's own account's.
func (h *handler) demandRegions(w http.ResponseWriter, r *http.Request) {
	user, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if err := requireAdvisorRole(r.Context()); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if h.relays == nil {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "relay registry is not configured"), w)
		return
	}
	rows, err := h.relays.DemandByRegion(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	result := make([]regionDemandResponse, 0, len(rows))
	for _, row := range rows {
		result = append(result, regionDemandResponse{
			Region:       row.Region,
			AccountID:    row.AccountID,
			RTTUnder20ms: row.RTTUnder20ms,
			RTT20To50ms:  row.RTT20To50ms,
			RTT50To100ms: row.RTT50To100ms,
			RTTOver100ms: row.RTTOver100ms,
		})
	}
	if h.audit != nil {
		if _, err := h.audit.Append(r.Context(), user.UserId, "karst.demand.regions.view", "regions", ""); err != nil {
			util.WriteError(r.Context(), err, w)
			return
		}
	}
	util.WriteJSONObject(r.Context(), w, result)
}

// regionDemandHistoryResponse mirrors regionDemandResponse plus the one
// field a retained sample has that a live read does not: when it was taken.
type regionDemandHistoryResponse struct {
	Region       string    `json:"region"`
	AccountID    string    `json:"account_id"`
	SampledAt    time.Time `json:"sampled_at"`
	RTTUnder20ms int64     `json:"rtt_under_20ms"`
	RTT20To50ms  int64     `json:"rtt_20_to_50ms"`
	RTT50To100ms int64     `json:"rtt_50_to_100ms"`
	RTTOver100ms int64     `json:"rtt_over_100ms"`
}

// demandRegionsHistory is ADR-0045 §8 (Phase 3)'s retained time series over
// demandRegions' own live signal — see relayreg.Store's own doc comment on
// RegionDemandSample for why this exists (Phases 0-1 did not actually build
// the history §8 says they should have) and what it does and does not
// store. Gated behind the same UserRoleAdvisor role as demandRegions, for
// the identical reason: this is deployment-wide, cross-account data, not
// anything scoped to the caller's own account.
func (h *handler) demandRegionsHistory(w http.ResponseWriter, r *http.Request) {
	user, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if err := requireAdvisorRole(r.Context()); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if h.relays == nil {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "relay registry is not configured"), w)
		return
	}
	since, until, err := parseDemandHistoryRange(r.URL.Query())
	if err != nil {
		util.WriteErrorResponse(err.Error(), http.StatusBadRequest, w)
		return
	}
	rows, err := h.relays.DemandHistory(r.Context(), since, until)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	result := make([]regionDemandHistoryResponse, 0, len(rows))
	for _, row := range rows {
		result = append(result, regionDemandHistoryResponse{
			Region:       row.Region,
			AccountID:    row.AccountID,
			SampledAt:    row.SampledAt,
			RTTUnder20ms: row.RTTUnder20ms,
			RTT20To50ms:  row.RTT20To50ms,
			RTT50To100ms: row.RTT50To100ms,
			RTTOver100ms: row.RTTOver100ms,
		})
	}
	if h.audit != nil {
		if _, err := h.audit.Append(r.Context(), user.UserId, "karst.demand.regions.history.view", "regions", ""); err != nil {
			util.WriteError(r.Context(), err, w)
			return
		}
	}
	util.WriteJSONObject(r.Context(), w, result)
}

// parseDemandHistoryRange reads `since`/`until` (both RFC3339, both
// required — there is no sensible default range for a query whose whole
// point is "a specific window to train or chart against"). `until` must be
// strictly after `since`, the same ordering DemandHistory's own `[since,
// until)` contract assumes.
func parseDemandHistoryRange(query url.Values) (time.Time, time.Time, error) {
	rawSince, rawUntil := query.Get("since"), query.Get("until")
	if rawSince == "" || rawUntil == "" {
		return time.Time{}, time.Time{}, errors.New("since and until (RFC3339) are both required")
	}
	since, err := time.Parse(time.RFC3339, rawSince)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("since: %w", err)
	}
	until, err := time.Parse(time.RFC3339, rawUntil)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("until: %w", err)
	}
	if !until.After(since) {
		return time.Time{}, time.Time{}, errors.New("until must be after since")
	}
	return since, until, nil
}

// demandAnchors is ADR-0045 §7 Phase 1's second demand-side input — §4b's
// deployment-wide, anonymous anchor-RTT histogram. No node or account
// identity appears anywhere in this response, by schema (there is no such
// column on regionallow.AnchorHistogramEntry at all) — unlike
// demandRegions above, this is not a cross-account exposure concern, but it
// is gated behind the same UserRoleAdvisor grant for one reason: keeping
// both of the Advisor's inputs behind one role keeps "who can see what the
// Advisor sees" a single, legible grant rather than two different ones.
func (h *handler) demandAnchors(w http.ResponseWriter, r *http.Request) {
	user, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if err := requireAdvisorRole(r.Context()); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if h.anchors == nil {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "region allowlist store is not configured"), w)
		return
	}
	rows, err := h.anchors.AnchorHistogram(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	result := make([]anchorHistogramResponse, 0, len(rows))
	for _, row := range rows {
		result = append(result, anchorHistogramResponse{Provider: row.Provider, Region: row.Region, Bucket: row.Bucket, Count: row.Count})
	}
	if h.audit != nil {
		if _, err := h.audit.Append(r.Context(), user.UserId, "karst.demand.anchors.view", "anchors", ""); err != nil {
			util.WriteError(r.Context(), err, w)
			return
		}
	}
	util.WriteJSONObject(r.Context(), w, result)
}

// scalerRecommendationsHTTPClient is used for every proxied GET below -- a
// short, fixed timeout so a hung or unreachable karst-scaler process cannot
// hang this handler (and, transitively, the console page polling it)
// indefinitely, the same discipline audit.Transport's own HTTP client uses.
var scalerRecommendationsHTTPClient = &http.Client{Timeout: 5 * time.Second}

// scalerPoolRecommendationResponse mirrors karst-scaler's own
// advise::PoolRecommendation (bins/karst-scaler/src/advise.rs), the same
// "local response struct, not the generated contract type" convention
// regionDemandResponse/anchorHistogramResponse above use.
type scalerPoolRecommendationResponse struct {
	PoolID            string  `json:"pool_id"`
	DesiredNodes      uint32  `json:"desired_nodes"`
	CostDelta         float64 `json:"cost_delta"`
	BindingConstraint string  `json:"binding_constraint"`
}

// scalerRecommendationResponse mirrors advise::Recommendation.
type scalerRecommendationResponse struct {
	Pools          []scalerPoolRecommendationResponse `json:"pools"`
	TotalCostDelta float64                            `json:"total_cost_delta"`
	BaselineCost   float64                            `json:"baseline_cost"`
}

// scalerRecommendationsResponse mirrors karst-scaler's metrics_http::Snapshot
// -- the exact shape its own GET /recommendations serves.
type scalerRecommendationsResponse struct {
	TickUnix        int64                        `json:"tick_unix"`
	Recommendation  scalerRecommendationResponse `json:"recommendation"`
	ConfiguredNodes map[string]uint32            `json:"configured_nodes"`
}

// scalerRecommendations proxies ADR-0045 §7 Phase 1's "recommended vs
// actual" view (§7's own phrase) from karst-scaler advise's own loopback
// /recommendations endpoint -- see RegisterEndpoints' own doc comment for
// why the browser never dials karst-scaler directly. Decoded and
// re-encoded through scalerRecommendationsResponse above, not proxied as
// raw bytes: every other response in this file is a typed, contract-checked
// shape, and a byte-for-byte proxy would be the one response here a schema
// drift in karst-scaler's own JSON could carry straight to the browser
// unnoticed. Gated behind the same UserRoleAdvisor role as
// demandRegions/demandAnchors above, for the identical reason -- this is
// itself a view of the operator's single, deployment-wide cost model, not
// account-scoped data.
func (h *handler) scalerRecommendations(w http.ResponseWriter, r *http.Request) {
	user, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if err := requireAdvisorRole(r.Context()); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if h.scalerAdvisorURL == "" {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "KARST_SCALER_ADVISOR_URL is not configured"), w)
		return
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, h.scalerAdvisorURL+"/recommendations", nil)
	if err != nil {
		util.WriteError(r.Context(), status.Errorf(status.Internal, "building karst-scaler request: %v", err), w)
		return
	}
	resp, err := scalerRecommendationsHTTPClient.Do(req)
	if err != nil {
		util.WriteError(r.Context(), status.Errorf(status.Internal, "reaching karst-scaler advise: %v", err), w)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxRequestBodyBytes))
		util.WriteError(r.Context(), status.Errorf(status.Internal, "karst-scaler advise returned %s: %s", resp.Status, body), w)
		return
	}
	var result scalerRecommendationsResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxRequestBodyBytes)).Decode(&result); err != nil {
		util.WriteError(r.Context(), status.Errorf(status.Internal, "decoding karst-scaler advise response: %v", err), w)
		return
	}
	if h.audit != nil {
		if _, err := h.audit.Append(r.Context(), user.UserId, "karst.scaler.recommendations.view", "recommendations", ""); err != nil {
			util.WriteError(r.Context(), err, w)
			return
		}
	}
	util.WriteJSONObject(r.Context(), w, result)
}

// scalerLatencyBreachResponse mirrors karst-scaler's own
// advise_loop::LatencyBreach (issue #381).
type scalerLatencyBreachResponse struct {
	Region      string  `json:"region"`
	P95RTTMs    float64 `json:"p95_rtt_ms"`
	ThresholdMs float64 `json:"threshold_ms"`
}

// scalerRegionCandidateResponse mirrors advise_loop::RegionCandidate.
type scalerRegionCandidateResponse struct {
	Provider          string  `json:"provider"`
	Region            string  `json:"region"`
	EstimatedP95RTTMs float64 `json:"estimated_p95_rtt_ms"`
	Observations      int64   `json:"observations"`
}

// scalerSuggestionsResponse mirrors karst-scaler's metrics_http::Suggestions
// -- the exact shape its own GET /suggestions serves.
type scalerSuggestionsResponse struct {
	TickUnix         int64                           `json:"tick_unix"`
	LatencyBreaches  []scalerLatencyBreachResponse   `json:"latency_breaches"`
	RegionCandidates []scalerRegionCandidateResponse `json:"region_candidates"`
}

// scalerSuggestions proxies issue #381's manual-mode-shaped "suggested by
// RTT" view from karst-scaler advise's own loopback /suggestions endpoint
// -- the sibling scalerRecommendations above already proxies
// /recommendations from, same role gate, same decode-and-re-encode
// discipline (not a raw-bytes proxy, for the identical reason), same
// reasoning throughout.
func (h *handler) scalerSuggestions(w http.ResponseWriter, r *http.Request) {
	user, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if err := requireAdvisorRole(r.Context()); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if h.scalerAdvisorURL == "" {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "KARST_SCALER_ADVISOR_URL is not configured"), w)
		return
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, h.scalerAdvisorURL+"/suggestions", nil)
	if err != nil {
		util.WriteError(r.Context(), status.Errorf(status.Internal, "building karst-scaler request: %v", err), w)
		return
	}
	resp, err := scalerRecommendationsHTTPClient.Do(req)
	if err != nil {
		util.WriteError(r.Context(), status.Errorf(status.Internal, "reaching karst-scaler advise: %v", err), w)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxRequestBodyBytes))
		util.WriteError(r.Context(), status.Errorf(status.Internal, "karst-scaler advise returned %s: %s", resp.Status, body), w)
		return
	}
	var result scalerSuggestionsResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxRequestBodyBytes)).Decode(&result); err != nil {
		util.WriteError(r.Context(), status.Errorf(status.Internal, "decoding karst-scaler advise response: %v", err), w)
		return
	}
	if h.audit != nil {
		if _, err := h.audit.Append(r.Context(), user.UserId, "karst.scaler.suggestions.view", "suggestions", ""); err != nil {
			util.WriteError(r.Context(), err, w)
			return
		}
	}
	util.WriteJSONObject(r.Context(), w, result)
}

func (h *handler) turnsList(w http.ResponseWriter, r *http.Request) {
	if _, err := nbcontext.GetUserAuthFromContext(r.Context()); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if h.turns == nil {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "turn registry is not configured"), w)
		return
	}
	turns, err := h.turns.List(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	result := make([]turnResponse, 0, len(turns))
	for _, turn := range turns {
		result = append(result, turnResponseFor(turn))
	}
	util.WriteJSONObject(r.Context(), w, result)
}
func (h *handler) turnsCreate(w http.ResponseWriter, r *http.Request) {
	if _, err := nbcontext.GetUserAuthFromContext(r.Context()); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if h.turns == nil {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "turn registry is not configured"), w)
		return
	}
	var entry turncred.Entry
	if err := json.NewDecoder(r.Body).Decode(&entry); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}
	turn, err := h.turns.Create(r.Context(), entry)
	if errors.Is(err, turncred.ErrExists) {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "turn server already exists"), w)
		return
	}
	if err != nil {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "%s", err), w)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(turnResponseFor(*turn)); err != nil {
		util.WriteError(r.Context(), err, w)
	}
}
func (h *handler) turnsDelete(w http.ResponseWriter, r *http.Request) {
	if _, err := nbcontext.GetUserAuthFromContext(r.Context()); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if h.turns == nil {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "turn registry is not configured"), w)
		return
	}
	if err := h.turns.Delete(r.Context(), mux.Vars(r)["turnId"]); errors.Is(err, turncred.ErrNotFound) {
		util.WriteError(r.Context(), status.Errorf(status.NotFound, "turn server not found"), w)
		return
	} else if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// locationsList/locationsCreate/locationsDelete manage the NOC map's
// admin-authorized "possible locations" registry (package locationreg) --
// the same list/create/delete shape as relaysList/relaysCreate/relaysDelete.
func (h *handler) locationsList(w http.ResponseWriter, r *http.Request) {
	if _, err := nbcontext.GetUserAuthFromContext(r.Context()); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if h.locations == nil {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "location registry is not configured"), w)
		return
	}
	locations, err := h.locations.List(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, locations)
}
func (h *handler) locationsCreate(w http.ResponseWriter, r *http.Request) {
	if _, err := nbcontext.GetUserAuthFromContext(r.Context()); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if h.locations == nil {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "location registry is not configured"), w)
		return
	}
	var entry locationreg.Entry
	if err := json.NewDecoder(r.Body).Decode(&entry); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}
	location, err := h.locations.Create(r.Context(), entry)
	if errors.Is(err, locationreg.ErrExists) {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "location already exists"), w)
		return
	}
	if err != nil {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "%s", err), w)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(location); err != nil {
		util.WriteError(r.Context(), err, w)
	}
}
func (h *handler) locationsDelete(w http.ResponseWriter, r *http.Request) {
	if _, err := nbcontext.GetUserAuthFromContext(r.Context()); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if h.locations == nil {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "location registry is not configured"), w)
		return
	}
	if err := h.locations.Delete(r.Context(), mux.Vars(r)["locationId"]); errors.Is(err, locationreg.ErrNotFound) {
		util.WriteError(r.Context(), status.Errorf(status.NotFound, "location not found"), w)
		return
	} else if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// allowedRegion is the wire shape for the console's region-allowlist editor
// (issue #349) -- a flattened, sorted (provider, region) pair rather than
// regionallow.Document's nested map, which is easier for a console table to
// render and easier to key a DELETE path on.
type allowedRegion struct {
	Provider string `json:"provider"`
	Region   string `json:"region"`
}

// ephemeralAnchor is the wire shape for the ephemeral-anchor editor,
// ADR-0045 §4d. Region/InstanceID are operator/scheduler-only fields --
// never projected into the netmap, see ephemeralanchor.AnchorEntry's own
// doc comment -- but are part of this admin-facing shape, since
// bins/karst-anchor-scheduler needs them to call EC2's own APIs.
type ephemeralAnchor struct {
	Label      string `json:"label"`
	Region     string `json:"region,omitempty"`
	InstanceID string `json:"instance_id"`
	Address    string `json:"address"`
	Port       uint32 `json:"port,omitempty"`
}

// ephemeralAnchorSchedule is the wire shape for the one deployment-wide
// duty-cycle schedule.
type ephemeralAnchorSchedule struct {
	WindowPeriodSeconds uint32 `json:"window_period_seconds"`
	DutyCycleSeconds    uint32 `json:"duty_cycle_seconds"`
}

// regionsList/regionsCreate/regionsDelete manage ADR-0045 §4c's
// deployment-wide region allowlist (package regionallow) -- the same
// list/create/delete shape as locationsList/locationsCreate/
// locationsDelete, keyed by the pair's own natural (provider, region) key
// rather than a generated id.
func (h *handler) regionsList(w http.ResponseWriter, r *http.Request) {
	if _, err := nbcontext.GetUserAuthFromContext(r.Context()); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if h.regions == nil {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "region allowlist store is not configured"), w)
		return
	}
	doc, err := h.regions.AllowedRegions(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	providers := make([]string, 0, len(doc))
	for provider := range doc {
		providers = append(providers, provider)
	}
	sort.Strings(providers)
	result := make([]allowedRegion, 0, len(doc))
	for _, provider := range providers {
		regions := append([]string(nil), doc[provider]...)
		sort.Strings(regions)
		for _, region := range regions {
			result = append(result, allowedRegion{Provider: provider, Region: region})
		}
	}
	util.WriteJSONObject(r.Context(), w, result)
}
func (h *handler) regionsCreate(w http.ResponseWriter, r *http.Request) {
	if _, err := nbcontext.GetUserAuthFromContext(r.Context()); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if h.regions == nil {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "region allowlist store is not configured"), w)
		return
	}
	var entry allowedRegion
	if err := json.NewDecoder(r.Body).Decode(&entry); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}
	if err := h.regions.AddRegion(r.Context(), entry.Provider, entry.Region); errors.Is(err, regionallow.ErrExists) {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "region already allowed"), w)
		return
	} else if err != nil {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "%s", err), w)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(entry); err != nil {
		util.WriteError(r.Context(), err, w)
	}
}
func (h *handler) regionsDelete(w http.ResponseWriter, r *http.Request) {
	if _, err := nbcontext.GetUserAuthFromContext(r.Context()); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if h.regions == nil {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "region allowlist store is not configured"), w)
		return
	}
	vars := mux.Vars(r)
	if err := h.regions.RemoveRegion(r.Context(), vars["provider"], vars["region"]); errors.Is(err, regionallow.ErrNotFound) {
		util.WriteError(r.Context(), status.Errorf(status.NotFound, "region not allowed"), w)
		return
	} else if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ephemeralAnchorsList/Create/Delete/Schedule/ScheduleSet manage ADR-0045
// §4d's ephemeral-anchor list and duty-cycle schedule (package
// ephemeralanchor) -- the same list/create/delete shape regionsList/
// regionsCreate/regionsDelete use above, keyed by each anchor's own
// natural label rather than a generated id.
func (h *handler) ephemeralAnchorsList(w http.ResponseWriter, r *http.Request) {
	if _, err := nbcontext.GetUserAuthFromContext(r.Context()); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if h.ephemeralAnchors == nil {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "ephemeral anchor store is not configured"), w)
		return
	}
	entries, err := h.ephemeralAnchors.Anchors(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	result := make([]ephemeralAnchor, 0, len(entries))
	for _, e := range entries {
		result = append(result, ephemeralAnchor{Label: e.Label, Region: e.Region, InstanceID: e.InstanceID, Address: e.Address, Port: e.Port})
	}
	util.WriteJSONObject(r.Context(), w, result)
}
func (h *handler) ephemeralAnchorsCreate(w http.ResponseWriter, r *http.Request) {
	if _, err := nbcontext.GetUserAuthFromContext(r.Context()); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if h.ephemeralAnchors == nil {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "ephemeral anchor store is not configured"), w)
		return
	}
	var entry ephemeralAnchor
	if err := json.NewDecoder(r.Body).Decode(&entry); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}
	add := ephemeralanchor.AnchorEntry{Label: entry.Label, Region: entry.Region, InstanceID: entry.InstanceID, Address: entry.Address, Port: entry.Port}
	if err := h.ephemeralAnchors.AddAnchor(r.Context(), add); errors.Is(err, ephemeralanchor.ErrExists) {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "ephemeral anchor already exists"), w)
		return
	} else if err != nil {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "%s", err), w)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(entry); err != nil {
		util.WriteError(r.Context(), err, w)
	}
}
func (h *handler) ephemeralAnchorsDelete(w http.ResponseWriter, r *http.Request) {
	if _, err := nbcontext.GetUserAuthFromContext(r.Context()); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if h.ephemeralAnchors == nil {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "ephemeral anchor store is not configured"), w)
		return
	}
	vars := mux.Vars(r)
	if err := h.ephemeralAnchors.RemoveAnchor(r.Context(), vars["label"]); errors.Is(err, ephemeralanchor.ErrNotFound) {
		util.WriteError(r.Context(), status.Errorf(status.NotFound, "ephemeral anchor not found"), w)
		return
	} else if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
func (h *handler) ephemeralAnchorsSchedule(w http.ResponseWriter, r *http.Request) {
	if _, err := nbcontext.GetUserAuthFromContext(r.Context()); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if h.ephemeralAnchors == nil {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "ephemeral anchor store is not configured"), w)
		return
	}
	windowPeriodSeconds, dutyCycleSeconds, err := h.ephemeralAnchors.Schedule(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, ephemeralAnchorSchedule{WindowPeriodSeconds: windowPeriodSeconds, DutyCycleSeconds: dutyCycleSeconds})
}
func (h *handler) ephemeralAnchorsScheduleSet(w http.ResponseWriter, r *http.Request) {
	if _, err := nbcontext.GetUserAuthFromContext(r.Context()); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if h.ephemeralAnchors == nil {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "ephemeral anchor store is not configured"), w)
		return
	}
	var schedule ephemeralAnchorSchedule
	if err := json.NewDecoder(r.Body).Decode(&schedule); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}
	if err := h.ephemeralAnchors.SetSchedule(r.Context(), schedule.WindowPeriodSeconds, schedule.DutyCycleSeconds); err != nil {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "%s", err), w)
		return
	}
	util.WriteJSONObject(r.Context(), w, schedule)
}

// scalingModeWire is the wire shape for issue #356/#379's one
// deployment-wide ADR-0045 §7 Phase 1 (manual)/Phase 2 (automated)
// actuation switch.
type scalingModeWire struct {
	Mode string `json:"mode"`
}

// scalingModeGet/scalingModeSet mirror ephemeralAnchorsSchedule/
// ephemeralAnchorsScheduleSet's own GET/PUT singleton shape exactly --
// one value, not a collection, so this is not /regions' list/create/
// delete shape. GET carries no additional role check beyond
// karstAuthorization's blanket module-Read gate: both the console's NOC
// view and karst-scaler's own tick (authenticated as whatever role its
// PAT belongs to) need to read this with no elevated role, the same way
// nocComponents itself needs none. PUT is admin-only purely through that
// same middleware's Update-operation check -- regionsCreate/
// regionsDelete/ephemeralAnchorsScheduleSet rely on it identically, with
// no second handler-level check.
func (h *handler) scalingModeGet(w http.ResponseWriter, r *http.Request) {
	if _, err := nbcontext.GetUserAuthFromContext(r.Context()); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if h.scalingMode == nil {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "scaling mode store is not configured"), w)
		return
	}
	mode, err := h.scalingMode.Mode(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, scalingModeWire{Mode: string(mode)})
}

func (h *handler) scalingModeSet(w http.ResponseWriter, r *http.Request) {
	if _, err := nbcontext.GetUserAuthFromContext(r.Context()); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if h.scalingMode == nil {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "scaling mode store is not configured"), w)
		return
	}
	var wire scalingModeWire
	if err := json.NewDecoder(r.Body).Decode(&wire); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}
	mode := scalingmode.Mode(wire.Mode)
	if mode != scalingmode.ModeAutomated && mode != scalingmode.ModeManual {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "mode must be %q or %q", scalingmode.ModeAutomated, scalingmode.ModeManual), w)
		return
	}
	if err := h.scalingMode.SetMode(r.Context(), mode); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, wire)
}

// firstRunGet/firstRunComplete back the console's onboarding gate (default
// domain + initial groups) -- see package firstrun's own doc comment for
// why a missing row, not an explicit flag, is what a brand-new account
// defaults to. No extra role check beyond karstAuthorization's blanket
// module gate: every role that can reach the console at all needs to know
// whether the wizard still needs completing.
func (h *handler) firstRunGet(w http.ResponseWriter, r *http.Request) {
	if _, err := nbcontext.GetUserAuthFromContext(r.Context()); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if h.firstRun == nil {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "first-run setup is not configured"), w)
		return
	}
	state, err := h.firstRun.Get(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, state)
}

func (h *handler) firstRunComplete(w http.ResponseWriter, r *http.Request) {
	if _, err := nbcontext.GetUserAuthFromContext(r.Context()); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if h.firstRun == nil {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "first-run setup is not configured"), w)
		return
	}
	state, err := h.firstRun.Complete(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, state)
}

// tutorialModeWire is the console's on/off switch for per-page guidance
// text, the same {enabled: bool} shape scalingModeWire uses for its own
// single value.
type tutorialModeWire struct {
	Enabled bool `json:"enabled"`
}

func (h *handler) tutorialModeGet(w http.ResponseWriter, r *http.Request) {
	if _, err := nbcontext.GetUserAuthFromContext(r.Context()); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if h.tutorialMode == nil {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "tutorial mode is not configured"), w)
		return
	}
	enabled, err := h.tutorialMode.Get(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, tutorialModeWire{Enabled: enabled})
}

func (h *handler) tutorialModeSet(w http.ResponseWriter, r *http.Request) {
	if _, err := nbcontext.GetUserAuthFromContext(r.Context()); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if h.tutorialMode == nil {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "tutorial mode is not configured"), w)
		return
	}
	var wire tutorialModeWire
	if err := json.NewDecoder(r.Body).Decode(&wire); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}
	if err := h.tutorialMode.Set(r.Context(), wire.Enabled); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, wire)
}

// requireCloudAccountAdminRole restricts cloud-credential create/delete to
// the account owner/admin roles -- a cloud secret is more sensitive than
// most things behind karstAuthorization's blanket module gate, the same
// reasoning requireAdvisorRole documents for the cross-tenant demand
// endpoints above. List/Discover carry no extra check: they never expose
// the secret itself (see infraconnections.Response), so any role that can
// already reach this API can read them.
func requireCloudAccountAdminRole(ctx context.Context) error {
	role, ok := nbcontext.RoleFromContext(ctx)
	if !ok {
		return status.Errorf(status.Internal, "failed to get user role from context")
	}
	r := types.UserRole(role)
	if r != types.UserRoleOwner && r != types.UserRoleAdmin {
		return status.Errorf(status.PermissionDenied, "managing cloud provider credentials requires the admin or owner role")
	}
	return nil
}

// requireInfraConnectionAdminRole is requireCloudAccountAdminRole's sibling
// for the generalized /infrastructure-connections surface -- same gate,
// wording updated to match the renamed concept.
func requireInfraConnectionAdminRole(ctx context.Context) error {
	role, ok := nbcontext.RoleFromContext(ctx)
	if !ok {
		return status.Errorf(status.Internal, "failed to get user role from context")
	}
	r := types.UserRole(role)
	if r != types.UserRoleOwner && r != types.UserRoleAdmin {
		return status.Errorf(status.PermissionDenied, "managing infrastructure connections requires the admin or owner role")
	}
	return nil
}

// cloudAccountsList/cloudAccountsCreate/cloudAccountsDelete/
// cloudAccountRegions/cloudAccountEnableRegion back the deprecated,
// preserved /cloud-accounts surface -- see package infraconnections's own
// doc comment for the ADR-0045 §6 addenda this implements, and exactly how
// far ModeReadWrite actuation goes (cloudAccountEnableRegion, nothing
// else). infraConnectionsList/infraConnectionsCreate/infraConnectionsDelete/
// infraConnectionResources below are the generalized
// /infrastructure-connections surface both the Settings page and the
// Authorized Locations picker now use; EnableLocalZone itself is not yet
// generalized (see infraconnections.Store.EnableLocalZone's doc comment).
func (h *handler) cloudAccountsList(w http.ResponseWriter, r *http.Request) {
	if _, err := nbcontext.GetUserAuthFromContext(r.Context()); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if h.infraConnections == nil {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "cloud accounts are not configured"), w)
		return
	}
	rows, err := h.infraConnections.List(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	resp := make([]infraconnections.LegacyResponse, 0, len(rows))
	for i := range rows {
		// A kubernetes-typed row can only be created through
		// /infrastructure-connections, but List itself is unfiltered (see
		// Store.List's own doc comment) -- filter here so an old typed
		// client polling this route can never see a provider value outside
		// its known aws/azure/gcp enum.
		if rows[i].Type == infraconnections.TypeKubernetes {
			continue
		}
		resp = append(resp, rows[i].ToLegacyResponse())
	}
	util.WriteJSONObject(r.Context(), w, resp)
}

func (h *handler) cloudAccountsCreate(w http.ResponseWriter, r *http.Request) {
	if _, err := nbcontext.GetUserAuthFromContext(r.Context()); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if h.infraConnections == nil {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "cloud accounts are not configured"), w)
		return
	}
	if err := requireCloudAccountAdminRole(r.Context()); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	var req infraconnections.LegacyCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}
	account, err := h.infraConnections.CreateLegacy(r.Context(), req)
	if errors.Is(err, infraconnections.ErrEncryptionRequired) {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "%s", err), w)
		return
	}
	if err != nil {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "%s", err), w)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(account.ToLegacyResponse()); err != nil {
		util.WriteError(r.Context(), err, w)
	}
}

func (h *handler) cloudAccountsDelete(w http.ResponseWriter, r *http.Request) {
	if _, err := nbcontext.GetUserAuthFromContext(r.Context()); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if h.infraConnections == nil {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "cloud accounts are not configured"), w)
		return
	}
	if err := requireCloudAccountAdminRole(r.Context()); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if err := h.infraConnections.Delete(r.Context(), mux.Vars(r)["cloudAccountId"]); errors.Is(err, infraconnections.ErrNotFound) {
		util.WriteError(r.Context(), status.Errorf(status.NotFound, "cloud account not found"), w)
		return
	} else if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) cloudAccountRegions(w http.ResponseWriter, r *http.Request) {
	if _, err := nbcontext.GetUserAuthFromContext(r.Context()); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if h.infraConnections == nil {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "cloud accounts are not configured"), w)
		return
	}
	regions, err := h.infraConnections.DiscoverLegacy(r.Context(), mux.Vars(r)["cloudAccountId"])
	if errors.Is(err, infraconnections.ErrNotFound) {
		util.WriteError(r.Context(), status.Errorf(status.NotFound, "cloud account not found"), w)
		return
	}
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, regions)
}

// enableRegionRequest carries the region whose EC2 endpoint EnableLocalZone
// must open its client against -- see DiscoveredRegion.ParentRegion's own
// doc comment for why AWS needs it. The console reads it off the same
// DiscoveredRegion this request is enabling.
type enableRegionRequest struct {
	ParentRegion string `json:"parent_region"`
}

// cloudAccountEnableRegion opts an AWS Local Zone into use (ADR-0045 §6's
// second addendum) -- the one real, mutating cloud-provider call this
// codebase makes, gated the same as credential create/delete
// (requireCloudAccountAdminRole) since it is at least as consequential: it
// is a one-way door on the provider side (AWS has no opt-out API) and the
// console must have already warned the operator before sending this
// request, not merely before rendering the button.
func (h *handler) cloudAccountEnableRegion(w http.ResponseWriter, r *http.Request) {
	if _, err := nbcontext.GetUserAuthFromContext(r.Context()); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if h.infraConnections == nil {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "cloud accounts are not configured"), w)
		return
	}
	if err := requireCloudAccountAdminRole(r.Context()); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	var req enableRegionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}
	region, err := h.infraConnections.EnableLocalZone(r.Context(), mux.Vars(r)["cloudAccountId"], mux.Vars(r)["code"], req.ParentRegion)
	if errors.Is(err, infraconnections.ErrNotFound) {
		util.WriteError(r.Context(), status.Errorf(status.NotFound, "cloud account not found"), w)
		return
	}
	if err != nil {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "%s", err), w)
		return
	}
	util.WriteJSONObject(r.Context(), w, region)
}

// infraConnectionsList/infraConnectionsCreate/infraConnectionsDelete/
// infraConnectionResources back the console's Infrastructure Connections
// Settings section and the Authorized Locations picker -- the generalized
// surface covering AWS/Azure/GCP/Kubernetes, see package infraconnections.
func (h *handler) infraConnectionsList(w http.ResponseWriter, r *http.Request) {
	if _, err := nbcontext.GetUserAuthFromContext(r.Context()); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if h.infraConnections == nil {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "infrastructure connections are not configured"), w)
		return
	}
	rows, err := h.infraConnections.List(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	resp := make([]infraconnections.Response, 0, len(rows))
	for i := range rows {
		resp = append(resp, rows[i].ToResponse())
	}
	util.WriteJSONObject(r.Context(), w, resp)
}

func (h *handler) infraConnectionsCreate(w http.ResponseWriter, r *http.Request) {
	if _, err := nbcontext.GetUserAuthFromContext(r.Context()); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if h.infraConnections == nil {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "infrastructure connections are not configured"), w)
		return
	}
	if err := requireInfraConnectionAdminRole(r.Context()); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	var req infraconnections.CreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}
	connection, err := h.infraConnections.Create(r.Context(), req)
	if errors.Is(err, infraconnections.ErrEncryptionRequired) {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "%s", err), w)
		return
	}
	if err != nil {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "%s", err), w)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(connection.ToResponse()); err != nil {
		util.WriteError(r.Context(), err, w)
	}
}

func (h *handler) infraConnectionsDelete(w http.ResponseWriter, r *http.Request) {
	if _, err := nbcontext.GetUserAuthFromContext(r.Context()); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if h.infraConnections == nil {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "infrastructure connections are not configured"), w)
		return
	}
	if err := requireInfraConnectionAdminRole(r.Context()); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if err := h.infraConnections.Delete(r.Context(), mux.Vars(r)["connectionId"]); errors.Is(err, infraconnections.ErrNotFound) {
		util.WriteError(r.Context(), status.Errorf(status.NotFound, "infrastructure connection not found"), w)
		return
	} else if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) infraConnectionResources(w http.ResponseWriter, r *http.Request) {
	if _, err := nbcontext.GetUserAuthFromContext(r.Context()); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if h.infraConnections == nil {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "infrastructure connections are not configured"), w)
		return
	}
	resources, err := h.infraConnections.Discover(r.Context(), mux.Vars(r)["connectionId"])
	if errors.Is(err, infraconnections.ErrNotFound) {
		util.WriteError(r.Context(), status.Errorf(status.NotFound, "infrastructure connection not found"), w)
		return
	}
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, resources)
}

// groupLocationsList/groupLocationsSet/groupLocationsDelete manage a route
// gateway group's declared NOC-map location (package grouplocation).
func (h *handler) groupLocationsList(w http.ResponseWriter, r *http.Request) {
	if _, err := nbcontext.GetUserAuthFromContext(r.Context()); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if h.groupLocations == nil {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "group location store is not configured"), w)
		return
	}
	locations, err := h.groupLocations.List(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, locations)
}
func (h *handler) groupLocationsSet(w http.ResponseWriter, r *http.Request) {
	if _, err := nbcontext.GetUserAuthFromContext(r.Context()); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if h.groupLocations == nil {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "group location store is not configured"), w)
		return
	}
	var entry grouplocation.Entry
	if err := json.NewDecoder(r.Body).Decode(&entry); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}
	entry.GroupID = mux.Vars(r)["groupId"]
	location, err := h.groupLocations.Set(r.Context(), entry)
	if err != nil {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "%s", err), w)
		return
	}
	util.WriteJSONObject(r.Context(), w, location)
}
func (h *handler) groupLocationsDelete(w http.ResponseWriter, r *http.Request) {
	if _, err := nbcontext.GetUserAuthFromContext(r.Context()); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if h.groupLocations == nil {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "group location store is not configured"), w)
		return
	}
	if err := h.groupLocations.Delete(r.Context(), mux.Vars(r)["groupId"]); errors.Is(err, grouplocation.ErrNotFound) {
		util.WriteError(r.Context(), status.Errorf(status.NotFound, "group location not found"), w)
		return
	} else if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// controlPlaneLocationGet/controlPlaneLocationSet manage the control
// plane's own declared NOC-map location (package cplocation).
func (h *handler) controlPlaneLocationGet(w http.ResponseWriter, r *http.Request) {
	if _, err := nbcontext.GetUserAuthFromContext(r.Context()); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if h.controlPlaneLocation == nil {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "control plane location is not configured"), w)
		return
	}
	location, err := h.controlPlaneLocation.Get(r.Context())
	if errors.Is(err, cplocation.ErrNotFound) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, location)
}
func (h *handler) controlPlaneLocationSet(w http.ResponseWriter, r *http.Request) {
	if _, err := nbcontext.GetUserAuthFromContext(r.Context()); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if h.controlPlaneLocation == nil {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "control plane location is not configured"), w)
		return
	}
	var entry geo.Location
	if err := json.NewDecoder(r.Body).Decode(&entry); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}
	location, err := h.controlPlaneLocation.Set(r.Context(), entry.Lat, entry.Lon, entry.Label)
	if err != nil {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "%s", err), w)
		return
	}
	util.WriteJSONObject(r.Context(), w, location)
}

// bedrockLocationSet declares this account's Bedrock location on the NOC
// map -- see bedrock.Store.SetLocation.
func (h *handler) bedrockLocationSet(w http.ResponseWriter, r *http.Request) {
	user, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if h.bedrock == nil {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "Bedrock is not configured"), w)
		return
	}
	var entry geo.Location
	if err := json.NewDecoder(r.Body).Decode(&entry); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}
	cfg, err := h.bedrock.SetLocation(r.Context(), user.AccountId, entry.Lat, entry.Lon, entry.Label)
	if err != nil {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "%s", err), w)
		return
	}
	location := geo.Location{Lat: entry.Lat, Lon: entry.Lon, Label: entry.Label}
	if cfg.LocationLat != nil {
		location = geo.Location{Lat: *cfg.LocationLat, Lon: *cfg.LocationLon, Label: cfg.LocationLabel}
	}
	util.WriteJSONObject(r.Context(), w, location)
}

// turnDeenrollRequest is what a karst-scaler TURN driver (ADR-0045 §7b,
// issue #311 -- not built yet) sends to remove the registry entry for a
// TURN instance it is draining or has destroyed. Keyed by uri, not id:
// the driver builds an instance's uri deterministically at create() time
// (see turncred.Store.DeleteByURI's own doc comment) and has no reason to
// List first just to recover the id turnsDelete expects.
type turnDeenrollRequest struct {
	URI string `json:"uri"`
}

// turnDeenroll lets the Scaler role remove a turncred.Store entry without
// the generic Delete grant turnsDelete needs -- see this route's own
// entry in the Scaler hard-allowlist (above, in karstAuthorization) for
// why this is shaped as a POST/Create request rather than a widened
// Delete permission. Unlike turnEnroll, this runs through the ordinary
// karstRouter/karstAuthorization stack: the caller here is karst-scaler's
// own drive loop, which already holds a session-bearing Scaler PAT, not
// an unenrolled instance with no credential at all.
func (h *handler) turnDeenroll(w http.ResponseWriter, r *http.Request) {
	if _, err := nbcontext.GetUserAuthFromContext(r.Context()); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if h.turns == nil {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "turn registry is not configured"), w)
		return
	}
	var req turnDeenrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}
	if err := h.turns.DeleteByURI(r.Context(), req.URI); errors.Is(err, turncred.ErrNotFound) {
		util.WriteError(r.Context(), status.Errorf(status.NotFound, "turn server not found"), w)
		return
	} else if err != nil {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "%s", err), w)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// knownEventsList/knownEventsCreate/knownEventsDelete are ADR-0045 §8
// (Phase 3)'s operator-entered calendar -- the same shape as
// turnsList/turnsCreate/turnsDelete above, account-scoped via the ordinary
// karstAuthorization gate (this is the caller's own account's data, not
// cross-account the way the demand-history endpoint is).
func (h *handler) knownEventsList(w http.ResponseWriter, r *http.Request) {
	if _, err := nbcontext.GetUserAuthFromContext(r.Context()); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if h.knownEvents == nil {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "known events are not configured"), w)
		return
	}
	events, err := h.knownEvents.List(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, events)
}

func (h *handler) knownEventsCreate(w http.ResponseWriter, r *http.Request) {
	if _, err := nbcontext.GetUserAuthFromContext(r.Context()); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if h.knownEvents == nil {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "known events are not configured"), w)
		return
	}
	var entry knownevents.Entry
	if err := json.NewDecoder(r.Body).Decode(&entry); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}
	event, err := h.knownEvents.Create(r.Context(), entry)
	if err != nil {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "%s", err), w)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(event); err != nil {
		util.WriteError(r.Context(), err, w)
	}
}

func (h *handler) knownEventsDelete(w http.ResponseWriter, r *http.Request) {
	if _, err := nbcontext.GetUserAuthFromContext(r.Context()); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if h.knownEvents == nil {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "known events are not configured"), w)
		return
	}
	if err := h.knownEvents.Delete(r.Context(), mux.Vars(r)["eventId"]); errors.Is(err, knownevents.ErrNotFound) {
		util.WriteError(r.Context(), status.Errorf(status.NotFound, "known event not found"), w)
		return
	} else if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) auditExport(w http.ResponseWriter, r *http.Request) {
	user, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if h.audit == nil {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "audit log is not configured"), w)
		return
	}
	format := r.URL.Query().Get("format")
	if format != "json" && format != "csv" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "format must be json or csv"), w)
		return
	}
	if format == "json" {
		h.streamAuditJSON(w, r, user.AccountId)
		return
	}
	h.streamAuditCSV(w, r, user.AccountId)
}

func (h *handler) streamAuditJSON(w http.ResponseWriter, r *http.Request, accountID string) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("["))
	cursor := uint64(0)
	first := true
	for {
		page, err := h.audit.ListBeforeForAccount(r.Context(), accountID, cursor, 200)
		if err != nil {
			return // the response has begun; do not append an unrelated error body
		}
		for _, entry := range page {
			if !first {
				if _, err := w.Write([]byte(",")); err != nil {
					return
				}
			}
			first = false
			if err := json.NewEncoder(w).Encode(toAuditEntry(entry)); err != nil {
				return
			}
		}
		if len(page) < 200 {
			break
		}
		cursor = page[len(page)-1].Seq
	}
	_, _ = w.Write([]byte("]"))
}

func (h *handler) streamAuditCSV(w http.ResponseWriter, r *http.Request, accountID string) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=karst-audit.csv")
	writer := csv.NewWriter(w)
	if err := writer.Write([]string{"sequence", "created_at", "actor", "action", "target", "detail", "previous_hash", "hash"}); err != nil {
		return
	}
	cursor := uint64(0)
	for {
		page, err := h.audit.ListBeforeForAccount(r.Context(), accountID, cursor, 200)
		if err != nil {
			return
		}
		for _, entry := range page {
			if err := writer.Write([]string{fmt.Sprint(entry.Seq), entry.CreatedAt.UTC().Format(time.RFC3339Nano), csvSafe(entry.Actor), csvSafe(entry.Action), csvSafe(entry.Target), csvSafe(entry.Detail), entry.PrevHash, entry.Hash}); err != nil {
				return
			}
		}
		if len(page) < 200 {
			break
		}
		cursor = page[len(page)-1].Seq
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return
	}
}

func csvSafe(value string) string {
	if value == "" {
		return value
	}
	switch value[0] {
	case '=', '+', '-', '@':
		return "'" + value
	}
	return value
}

func (h *handler) auditSink(w http.ResponseWriter, r *http.Request) {
	if !requireUser(w, r) {
		return
	}
	if h.audit == nil {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "audit log is not configured"), w)
		return
	}
	var request struct {
		Kind     string `json:"kind"`
		Endpoint string `json:"endpoint"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}
	sink, err := h.audit.AddSink(r.Context(), request.Kind, request.Endpoint)
	if err != nil {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "%s", err), w)
		return
	}
	w.WriteHeader(http.StatusCreated)
	// Do not serialize the storage model: it carries account-scoped fields that
	// are not part of the public contract. Keep this response aligned with
	// AuditSink so generated clients see the complete, intentional shape.
	util.WriteJSONObject(r.Context(), w, map[string]any{"id": sink.ID, "kind": request.Kind, "endpoint": request.Endpoint})
}

func (h *handler) auditSinkList(w http.ResponseWriter, r *http.Request) {
	if !requireUser(w, r) {
		return
	}
	if h.audit == nil {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "audit log is not configured"), w)
		return
	}
	sinks, err := h.audit.ListSinks(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	// Same reason auditSink shapes its own response by hand: the storage
	// model carries account-scoped fields that are not part of the public
	// AuditSink contract.
	result := make([]map[string]any, 0, len(sinks))
	for _, sink := range sinks {
		result = append(result, map[string]any{"id": sink.ID, "kind": sink.Kind, "endpoint": sink.Endpoint})
	}
	util.WriteJSONObject(r.Context(), w, result)
}

func (h *handler) auditSinkDelete(w http.ResponseWriter, r *http.Request) {
	if !requireUser(w, r) {
		return
	}
	if h.audit == nil {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "audit log is not configured"), w)
		return
	}
	if err := h.audit.RemoveSink(r.Context(), mux.Vars(r)["sinkId"]); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) policyRollback(w http.ResponseWriter, r *http.Request) {
	if !h.requirePolicy(w, r) {
		return
	}
	user, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	number, err := strconv.ParseUint(mux.Vars(r)["version"], 10, 64)
	if err != nil {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid policy version"), w)
		return
	}
	expected, err := strconv.ParseUint(strings.Trim(r.Header.Get("If-Match"), "\""), 10, 64)
	if err != nil {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "If-Match must be a policy version"), w)
		return
	}
	previous, err := h.policy.Get(r.Context(), number)
	if errors.Is(err, karstpolicy.ErrNoVersion) {
		util.WriteError(r.Context(), status.Errorf(status.NotFound, "policy version not found"), w)
		return
	}
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	written, err := h.policy.Write(r.Context(), previous.Document, user.UserId, expected)
	if errors.Is(err, karstpolicy.ErrVersionConflict) {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "policy version changed"), w)
		return
	}
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	h.pushPolicyUpdate(r.Context(), user.AccountId)
	w.Header().Set("ETag", strconv.FormatUint(written.Version, 10))
	util.WriteJSONObject(r.Context(), w, policyVersionResponse(written))
}

func (h *handler) policyVersions(w http.ResponseWriter, r *http.Request) {
	if !h.requirePolicy(w, r) {
		return
	}
	if _, err := nbcontext.GetUserAuthFromContext(r.Context()); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	offset, limit, err := pageArguments(r)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	versions, err := h.policy.List(r.Context(), offset, limit+1)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	var next any
	if len(versions) > limit {
		versions = versions[:limit]
		next = strconv.Itoa(offset + limit)
	}
	items := make([]map[string]any, 0, len(versions))
	for index := range versions {
		items = append(items, policyVersionResponse(&versions[index]))
	}
	util.WriteJSONObject(r.Context(), w, map[string]any{"items": items, "next_cursor": next})
}

func (h *handler) policyVersion(w http.ResponseWriter, r *http.Request) {
	if !h.requirePolicy(w, r) {
		return
	}
	if _, err := nbcontext.GetUserAuthFromContext(r.Context()); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	number, err := strconv.ParseUint(mux.Vars(r)["version"], 10, 64)
	if err != nil {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid policy version"), w)
		return
	}
	version, err := h.policy.Get(r.Context(), number)
	if errors.Is(err, karstpolicy.ErrNoVersion) {
		util.WriteError(r.Context(), status.Errorf(status.NotFound, "policy version not found"), w)
		return
	}
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, policyVersionResponse(version))
}

func (h *handler) policyWrite(w http.ResponseWriter, r *http.Request) {
	if !h.requirePolicy(w, r) {
		return
	}
	user, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	expected, err := strconv.ParseUint(strings.Trim(r.Header.Get("If-Match"), "\""), 10, 64)
	if err != nil {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "If-Match must be a policy version"), w)
		return
	}
	var request struct {
		Document string `json:"document"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}
	version, err := h.policy.Write(r.Context(), request.Document, user.UserId, expected)
	if errors.Is(err, karstpolicy.ErrVersionConflict) {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "policy version changed"), w)
		return
	}
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	h.pushPolicyUpdate(r.Context(), user.AccountId)
	w.Header().Set("ETag", strconv.FormatUint(version.Version, 10))
	util.WriteJSONObject(r.Context(), w, policyVersionResponse(version))
}

// pushPolicyUpdate triggers a netmap push to every peer in the account after
// a policy write. Route and group mutations already push through the
// inherited account manager's own affected-peers dispatch; a policy change
// had no equivalent (GitHub issue #109), so an already-connected peer's
// compiled filter went stale — silently, sometimes indefinitely, until an
// unrelated reconnect — for as long as the account's own next netmap change
// happened to take. Account-wide, not a narrower affected set: unlike a
// route or group, a policy document has no fixed membership to diff against
// — any rule anywhere in it can name any node — so every peer's filter must
// be treated as potentially affected. Immediate, not buffered
// (`accountUpdater` deliberately exposes `UpdateAccountPeers`, not
// `BufferUpdateAccountPeers`): a policy write is an infrequent, deliberate
// admin action, not a hot path debounce needs to protect, and the
// motivating case — revoking access — is exactly the one plan §3.4 calls a
// security property, not a caching concern, to begin with.
func (h *handler) pushPolicyUpdate(ctx context.Context, accountID string) {
	if h.accounts == nil {
		return
	}
	h.accounts.UpdateAccountPeers(ctx, accountID, types.UpdateReason{
		Resource:  types.UpdateResourcePolicy,
		Operation: types.UpdateOperationUpdate,
	})
}

// policySchema serves a static JSON Schema for editor autocomplete/lint —
// issue #128. Unlike every other /policy route, it needs no policy store: the
// schema describes the document shape, not any particular version of one, so
// it is available even to an account that has never saved a policy yet.
func (h *handler) policySchema(w http.ResponseWriter, r *http.Request) {
	if !requireUser(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	_, _ = w.Write([]byte(karstpolicy.JSONSchema))
}

func (h *handler) policyCurrent(w http.ResponseWriter, r *http.Request) {
	if !h.requirePolicy(w, r) {
		return
	}
	if _, err := nbcontext.GetUserAuthFromContext(r.Context()); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	version, err := h.policy.Current(r.Context())
	if errors.Is(err, karstpolicy.ErrNoVersion) {
		util.WriteError(r.Context(), status.Errorf(status.NotFound, "no Karst policy version"), w)
		return
	}
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, policyVersionResponse(version))
}

// policyVersionResponse separates the public policy document from its
// account-scoped storage record. The latter has no JSON contract and must not
// leak into generated-client responses.
func policyVersionResponse(version *karstpolicy.Version) map[string]any {
	return map[string]any{"version": version.Version, "document": version.Document, "author": version.Author, "created_at": version.CreatedAt}
}

func (h *handler) policyValidate(w http.ResponseWriter, r *http.Request) {
	if _, err := nbcontext.GetUserAuthFromContext(r.Context()); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	var request struct {
		Document string `json:"document"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}
	if err := karstpolicy.ValidateDocument(request.Document); err != nil {
		line, column := karstpolicy.ErrorLocation([]byte(request.Document), err)
		util.WriteJSONObject(r.Context(), w, map[string]any{"valid": false, "diagnostics": []map[string]any{{"severity": "error", "message": err.Error(), "line": line, "column": column}}})
		return
	}
	util.WriteJSONObject(r.Context(), w, map[string]any{"valid": true, "diagnostics": []any{}})
}

// policyPreview compiles both documents against the caller-visible node set
// and diffs concrete source/destination/port flows. It deliberately uses the
// same compiler as netmap distribution; previewing a different interpretation
// of ACLs would be worse than offering no preview at all.
func (h *handler) policyPreview(w http.ResponseWriter, r *http.Request) {
	user, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if !h.requirePolicy(w, r) {
		return
	}
	var request struct {
		Document string `json:"document"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}
	candidate, err := karstpolicy.Parse([]byte(request.Document))
	if err != nil {
		line, column := karstpolicy.ErrorLocation([]byte(request.Document), err)
		util.WriteJSONObject(r.Context(), w, map[string]any{"added": []any{}, "removed": []any{}, "ssh_added": []any{}, "ssh_removed": []any{}, "diagnostics": []map[string]any{{"severity": "error", "message": err.Error(), "line": line, "column": column}}})
		return
	}
	visible, err := h.authorizedNodes(r.Context(), user.AccountId, user.UserId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	network := make([]karstpolicy.Node, 0, len(visible))
	for _, n := range visible {
		network = append(network, karstpolicy.Node{Handle: n.Handle, User: n.UserID, Tags: n.Tags})
	}
	current := &karstpolicy.Document{}
	if version, currentErr := h.policy.Current(r.Context()); currentErr == nil {
		current, err = karstpolicy.Parse([]byte(version.Document))
		if err != nil {
			util.WriteError(r.Context(), err, w)
			return
		}
	} else if !errors.Is(currentErr, karstpolicy.ErrNoVersion) {
		util.WriteError(r.Context(), currentErr, w)
		return
	}
	oldFlows, err := compiledFlows(current, network)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	newFlows, err := compiledFlows(candidate, network)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	added, removed := diffFlows(oldFlows, newFlows)

	oldSSH, err := compiledSSHGrants(current, network)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	newSSH, err := compiledSSHGrants(candidate, network)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	addedSSH, removedSSH := diffSSHGrants(oldSSH, newSSH)

	util.WriteJSONObject(r.Context(), w, map[string]any{
		"added": added, "removed": removed,
		"ssh_added": addedSSH, "ssh_removed": removedSSH,
	})
}

func (h *handler) requirePolicy(w http.ResponseWriter, r *http.Request) bool {
	if h.policy != nil {
		return true
	}
	util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "policy store is not configured"), w)
	return false
}

// policyTest currently executes the document's structural test: parse and
// compile validation. The response keeps a stable per-test shape so document
// fixtures can add packet-level cases without an API change.
func (h *handler) policyTest(w http.ResponseWriter, r *http.Request) {
	if !requireUser(w, r) {
		return
	}
	var request struct {
		Document string `json:"document"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}
	if err := karstpolicy.ValidateDocument(request.Document); err != nil {
		util.WriteJSONObject(r.Context(), w, map[string]any{"passed": false, "results": []map[string]any{{"name": "document-valid", "passed": false, "message": err.Error()}}})
		return
	}
	util.WriteJSONObject(r.Context(), w, map[string]any{"passed": true, "results": []map[string]any{{"name": "document-valid", "passed": true}}})
}

type policyFlow struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Protocol    string `json:"protocol"`
	Ports       string `json:"ports"`
}

func compiledFlows(document *karstpolicy.Document, nodes []karstpolicy.Node) (map[string]policyFlow, error) {
	flows := make(map[string]policyFlow)
	for _, source := range nodes {
		filter, err := document.CompileEgress(source, nodes)
		if err != nil {
			return nil, err
		}
		for _, rule := range filter.Rules {
			for _, destination := range rule.Dsts {
				for _, port := range rule.Ports {
					ports := strconv.FormatUint(uint64(port.First), 10)
					if port.Last != port.First {
						ports += "-" + strconv.FormatUint(uint64(port.Last), 10)
					}
					flow := policyFlow{Source: source.Handle, Destination: destination, Protocol: "tcp", Ports: ports}
					flows[flow.Source+"\x00"+flow.Destination+"\x00"+flow.Protocol+"\x00"+flow.Ports] = flow
				}
			}
		}
	}
	return flows, nil
}

func diffFlows(old, next map[string]policyFlow) (added, removed []policyFlow) {
	for key, flow := range next {
		if _, ok := old[key]; !ok {
			added = append(added, flow)
		}
	}
	for key, flow := range old {
		if _, ok := next[key]; !ok {
			removed = append(removed, flow)
		}
	}
	sort.Slice(added, func(i, j int) bool {
		return added[i].Source+added[i].Destination+added[i].Ports < added[j].Source+added[j].Destination+added[j].Ports
	})
	sort.Slice(removed, func(i, j int) bool {
		return removed[i].Source+removed[i].Destination+removed[i].Ports < removed[j].Source+removed[j].Destination+removed[j].Ports
	})
	return added, removed
}

// sshGrant is an "ssh" rule's effect, described in the same principal/target
// language as the source plan rather than as a host:port flow — ssh gating
// has no ports or protocol of its own (plans/phase-6/07-acl-gated-ssh.md §3.1).
type sshGrant struct {
	Principal string `json:"principal"`
	Target    string `json:"target"`
}

// compiledSSHGrants mirrors compiledFlows for the SSH gate: it compiles
// CompileSSH per node (who may reach it) rather than per source, since the
// gate is described by destination the same way the general ingress filter
// is.
func compiledSSHGrants(document *karstpolicy.Document, nodes []karstpolicy.Node) (map[string]sshGrant, error) {
	grants := make(map[string]sshGrant)
	for _, target := range nodes {
		filter, err := document.CompileSSH(target, nodes)
		if err != nil {
			return nil, err
		}
		if filter == nil {
			continue // no "ssh" block in this document: nothing to describe
		}
		for _, rule := range filter.Rules {
			for _, principal := range rule.Srcs {
				grant := sshGrant{Principal: principal, Target: target.Handle}
				grants[grant.Principal+"\x00"+grant.Target] = grant
			}
		}
	}
	return grants, nil
}

func diffSSHGrants(old, next map[string]sshGrant) (added, removed []sshGrant) {
	for key, grant := range next {
		if _, ok := old[key]; !ok {
			added = append(added, grant)
		}
	}
	for key, grant := range old {
		if _, ok := next[key]; !ok {
			removed = append(removed, grant)
		}
	}
	sort.Slice(added, func(i, j int) bool {
		return added[i].Principal+added[i].Target < added[j].Principal+added[j].Target
	})
	sort.Slice(removed, func(i, j int) bool {
		return removed[i].Principal+removed[i].Target < removed[j].Principal+removed[j].Target
	})
	return added, removed
}

func (h *handler) auditList(w http.ResponseWriter, r *http.Request) {
	if !h.requireAudit(w, r) {
		return
	}
	user, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	offset, limit, err := pageArguments(r)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	entries, err := h.audit.ListFilteredForAccount(r.Context(), user.AccountId, r.URL.Query().Get("actor"), r.URL.Query().Get("action"), offset, limit+1)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	var next any
	if len(entries) > limit {
		entries = entries[:limit]
		cursor := strconv.Itoa(offset + limit)
		next = cursor
	}
	var cursor *string
	if next != nil {
		value := next.(string)
		cursor = &value
	}
	// entries_since_anchor is this account's own entry count (ADR-0035), not
	// a deployment-wide sequence delta (ADR-0033's "Scoping note", now fixed).
	// Defaults to every entry the account has ever written, narrowed below
	// once an anchor is found.
	totalCount, countErr := h.audit.CountSince(r.Context(), user.AccountId, 0)
	if countErr != nil {
		util.WriteError(r.Context(), countErr, w)
		return
	}
	anchor := karstcontract.AuditAnchor{EntriesSinceAnchor: int(totalCount)}
	if h.chain != nil {
		chainEntries, chainErr := h.chain.All(r.Context(), user.AccountId)
		if chainErr != nil && !errors.Is(chainErr, bedrock.ErrNoLog) {
			util.WriteError(r.Context(), chainErr, w)
			return
		}
		if len(chainEntries) != 0 {
			state, verifyErr := bedrock.VerifyLog(chainEntries)
			if verifyErr != nil {
				util.WriteError(r.Context(), verifyErr, w)
				return
			}
			if state.Anchor != nil {
				anchoredSequence := int(state.Anchor.AuditSeq)
				anchor.LastAnchoredSequence = &anchoredSequence
				sinceAnchor, sinceErr := h.audit.CountSince(r.Context(), user.AccountId, state.Anchor.AuditSeq)
				if sinceErr != nil {
					util.WriteError(r.Context(), sinceErr, w)
					return
				}
				anchor.EntriesSinceAnchor = int(sinceAnchor)
				if at, ok := bedrock.LastAnchoredAt(chainEntries, state); ok {
					anchor.LastAnchoredAt = &at
				}
				// ADR-0016's payoff: report a log that contradicts its own
				// anchor rather than only counting entries since it.
				if auditHead, ok := h.audit.(auditAnchorReader); ok {
					if _, verifyAnchorErr := bedrock.VerifyAnchored(r.Context(), state, auditHead); verifyAnchorErr != nil {
						anchor.ContradictsAnchor = true
					}
				}
			}
		}
	}
	items := make([]karstcontract.AuditEntry, 0, len(entries))
	for _, entry := range entries {
		items = append(items, toAuditEntry(entry))
	}
	util.WriteJSONObject(r.Context(), w, karstcontract.AuditPage{
		Items:      items,
		NextCursor: cursor,
		Anchor:     anchor,
	})
}

func toAuditEntry(entry audit.Entry) karstcontract.AuditEntry {
	var detail *string
	if entry.Detail != "" {
		value := entry.Detail
		detail = &value
	}
	return karstcontract.AuditEntry{
		Sequence:     int(entry.Seq),
		CreatedAt:    entry.CreatedAt,
		Actor:        entry.Actor,
		Action:       entry.Action,
		Target:       entry.Target,
		Detail:       detail,
		PreviousHash: entry.PrevHash,
		Hash:         entry.Hash,
	}
}

func (h *handler) auditHead(w http.ResponseWriter, r *http.Request) {
	if !h.requireAudit(w, r) {
		return
	}
	user, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	seq, hash, err := h.audit.AccountHead(r.Context(), user.AccountId)
	if errors.Is(err, audit.ErrEmpty) {
		util.WriteJSONObject(r.Context(), w, map[string]any{"sequence": 0, "hash": ""})
		return
	}
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, map[string]any{"sequence": seq, "hash": hash})
}

func (h *handler) auditVerify(w http.ResponseWriter, r *http.Request) {
	if !h.requireAudit(w, r) {
		return
	}
	user, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	// Verify walks the whole deployment-wide chain (ADR-0035) — a stronger
	// check than one scoped to this account alone, and the correct one:
	// truncating any account's tail breaks every account's verification.
	// Only the reported head below is scoped to this account.
	bad, err := h.audit.Verify(r.Context())
	valid := err == nil
	seq, hash, headErr := h.audit.AccountHead(r.Context(), user.AccountId)
	if errors.Is(headErr, audit.ErrEmpty) {
		seq, hash, headErr = 0, "", nil
	}
	if headErr != nil {
		util.WriteError(r.Context(), headErr, w)
		return
	}
	var first any
	if !valid {
		first = bad
	}
	util.WriteJSONObject(r.Context(), w, map[string]any{"valid": valid, "first_bad_sequence": first, "head": map[string]any{"sequence": seq, "hash": hash}})
}

func (h *handler) requireAudit(w http.ResponseWriter, r *http.Request) bool {
	if h.audit != nil {
		return true
	}
	util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "audit log is not configured"), w)
	return false
}

func (h *handler) getPosture(w http.ResponseWriter, r *http.Request) {
	user, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	allowed, err := h.authorizedNodes(r.Context(), user.AccountId, user.UserId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	rows, err := h.nodes.AllSessionObservations()
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	rows = filterObservationRows(rows, allowed)
	now := time.Now().UTC()
	windowStart := now.Add(-5 * time.Minute)
	if raw := r.URL.Query().Get("observed_since"); raw != "" {
		parsed, parseErr := time.Parse(time.RFC3339, raw)
		if parseErr != nil {
			util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "observed_since must be RFC3339"), w)
			return
		}
		windowStart = parsed.UTC()
	}
	var pq, lattice int
	suites := map[string]int{}
	var asOf time.Time
	for _, row := range rows {
		if row.ObservedAt.Before(windowStart) {
			continue
		}
		if row.LatticeOnly {
			lattice++
		} else {
			pq++
		}
		suites[row.Suite]++
		if row.ObservedAt.After(asOf) {
			asOf = row.ObservedAt
		}
	}
	// The aggregate itself was evaluated at now even when the account has no
	// in-window observations. Returning Go's zero timestamp would satisfy the
	// string type but falsely imply a measurement from year one.
	if asOf.IsZero() {
		asOf = now
	}
	staleNodes := 0
	for _, candidate := range allowed {
		if candidate.Posture.Status == "stale" || candidate.Posture.Status == "unknown" {
			staleNodes++
		}
	}
	util.WriteJSONObject(r.Context(), w, map[string]any{"as_of": asOf, "window_start": windowStart, "observed_sessions": len(rows), "eligible_sessions": pq + lattice, "pq_covered_sessions": pq, "lattice_only_sessions": lattice, "stale_nodes": staleNodes, "suites": suites})
}

func (h *handler) listPostureSessions(w http.ResponseWriter, r *http.Request) {
	user, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	allowed, err := h.authorizedNodes(r.Context(), user.AccountId, user.UserId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	rows, err := h.nodes.AllSessionObservations()
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	rows = filterObservationRows(rows, allowed)
	if posture := r.URL.Query().Get("posture"); posture != "" {
		rows = filterPostureRows(rows, posture)
	}
	offset, limit, err := pageArguments(r)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if offset > len(rows) {
		offset = len(rows)
	}
	end := offset + limit
	if end > len(rows) {
		end = len(rows)
	}
	items := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		status := "pq"
		if row.LatticeOnly {
			status = "lattice_only"
		}
		items = append(items, map[string]any{"node_handle": row.ReporterHandle, "peer_handle": row.PeerHandle, "status": status, "suite": row.Suite, "psk_epoch": row.PSKEpoch, "lattice_only": row.LatticeOnly, "observed_at": row.ObservedAt})
	}
	var nextCursor any
	if end < len(rows) {
		nextCursor = strconv.Itoa(end)
	}
	util.WriteJSONObject(r.Context(), w, map[string]any{"items": items[offset:end], "next_cursor": nextCursor})
}

func filterObservationRows(rows []node.SessionObservation, allowed []nodeResponse) []node.SessionObservation {
	handles := make(map[string]struct{}, len(allowed))
	for _, n := range allowed {
		handles[n.Handle] = struct{}{}
	}
	filtered := make([]node.SessionObservation, 0, len(rows))
	for _, row := range rows {
		if _, ok := handles[row.ReporterHandle]; ok {
			filtered = append(filtered, row)
		}
	}
	return filtered
}

func filterPostureRows(rows []node.SessionObservation, posture string) []node.SessionObservation {
	filtered := make([]node.SessionObservation, 0, len(rows))
	for _, row := range rows {
		status := "pq"
		if row.LatticeOnly {
			status = "lattice_only"
		}
		if posture == status {
			filtered = append(filtered, row)
		}
	}
	return filtered
}

func (h *handler) getNodePaths(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	handle := mux.Vars(r)["handle"]
	found := false
	nodes, err := h.adminNodes(r.Context(), userAuth.AccountId, userAuth.UserId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	for _, n := range nodes {
		if n.Handle == handle {
			found = true
			break
		}
	}
	if !found {
		util.WriteError(r.Context(), status.Errorf(status.NotFound, "Karst node not found"), w)
		return
	}
	observations, err := h.nodes.SessionObservations(handle)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	paths := make([]karstcontract.PathObservation, 0, len(observations))
	var observedAt *time.Time
	for _, observation := range observations {
		at := observation.ObservedAt.UTC()
		if observedAt == nil || at.After(*observedAt) {
			observedAt = &at
		}
		var endpoint *string
		if observation.Endpoint != "" {
			value := observation.Endpoint
			endpoint = &value
		}
		paths = append(paths, karstcontract.PathObservation{
			PeerHandle: observation.PeerHandle,
			Kind:       karstcontract.PathObservationKind(observation.Path),
			Endpoint:   endpoint,
			ObservedAt: at,
			TxBytes:    int(observation.TxBytes),
			RxBytes:    int(observation.RxBytes),
		})
	}
	util.WriteJSONObject(r.Context(), w, karstcontract.NodePaths{ObservedAt: observedAt, Paths: paths})
}

func (h *handler) getNodePosture(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	handle := mux.Vars(r)["handle"]
	nodes, err := h.adminNodes(r.Context(), userAuth.AccountId, userAuth.UserId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if !containsHandle(nodes, handle) {
		util.WriteError(r.Context(), status.Errorf(status.NotFound, "Karst node not found"), w)
		return
	}
	observations, err := h.nodes.SessionObservations(handle)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, postureFromObservations(observations))
}

func containsHandle(nodes []nodeResponse, handle string) bool {
	for _, node := range nodes {
		if node.Handle == handle {
			return true
		}
	}
	return false
}

// nodeResponse has no identity public key, KEM key, PSK, or discovery
// key. Handles are stable identifiers, not key material, and are the only
// identity value this REST surface returns.
type nodeResponse struct {
	Handle   string   `json:"handle"`
	Name     string   `json:"name"`
	Platform string   `json:"platform"`
	UserID   string   `json:"user_id"`
	Tags     []string `json:"tags"`
	// DomainID is the peer's stable mesh domain ID, including the explicit root.
	// Older, unmigrated fixtures may omit it.
	DomainID string `json:"domain_id,omitempty"`
	// DNSLabel is root-relative, including the domain path and any deduplication
	// suffix. The account root suffix is appended once for a complete name;
	// domain API projections expose the corresponding complete namespace.
	DNSLabel   string      `json:"dns_label"`
	Enabled    bool        `json:"enabled"`
	ExpiresAt  *time.Time  `json:"expires_at"`
	CreatedAt  time.Time   `json:"created_at"`
	LastSeenAt *time.Time  `json:"last_seen_at"`
	Posture    nodePosture `json:"posture"`
}

// nodePosture is intentionally unknown until the authenticated node report is
// extended with negotiated session facts. Returning a suite or PSK epoch based
// on server assumptions would turn an absence of observation into a false
// green status in the console.
type nodePosture struct {
	Status      string     `json:"status"`
	Suite       *string    `json:"suite"`
	PSKEpoch    *uint32    `json:"psk_epoch"`
	LatticeOnly bool       `json:"lattice_only"`
	ObservedAt  *time.Time `json:"observed_at"`
}

type nodePage struct {
	Items      []nodeResponse `json:"items"`
	NextCursor *string        `json:"next_cursor"`
}

func (h *handler) listNodes(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	nodes, err := h.adminNodes(r.Context(), userAuth.AccountId, userAuth.UserId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	if userID := r.URL.Query().Get("user"); userID != "" {
		nodes = filterNodes(nodes, func(n nodeResponse) bool { return n.UserID == userID })
	}
	if posture := r.URL.Query().Get("posture"); posture != "" {
		if posture != "pq" && posture != "lattice_only" && posture != "stale" && posture != "unknown" {
			util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid posture filter"), w)
			return
		}
		nodes = filterNodes(nodes, func(n nodeResponse) bool { return n.Posture.Status == posture })
	}
	if coverage := r.URL.Query().Get("coverage"); coverage != "" {
		if coverage != "covered" && coverage != "uncovered" && coverage != "stale" {
			util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid coverage filter"), w)
			return
		}
		nodes = filterNodes(nodes, func(n nodeResponse) bool {
			switch coverage {
			case "covered":
				return n.Posture.Status == "pq"
			case "uncovered":
				return n.Posture.Status == "lattice_only"
			default:
				return n.Posture.Status == "stale" || n.Posture.Status == "unknown"
			}
		})
	}
	// Tags have no Karst-owned persistence yet. An explicit tag filter must not
	// silently broaden into an all-nodes response, which would mislead callers.
	if r.URL.Query().Get("tag") != "" {
		nodes = []nodeResponse{}
	}

	offset, limit, err := pageArguments(r)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	end := offset + limit
	if offset > len(nodes) {
		offset = len(nodes)
	}
	if end > len(nodes) {
		end = len(nodes)
	}
	var next *string
	if end < len(nodes) {
		cursor := strconv.Itoa(end)
		next = &cursor
	}
	util.WriteJSONObject(r.Context(), w, nodePage{Items: nodes[offset:end], NextCursor: next})
}

func (h *handler) getNode(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	nodes, err := h.adminNodes(r.Context(), userAuth.AccountId, userAuth.UserId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	handle := mux.Vars(r)["handle"]
	for _, n := range nodes {
		if n.Handle == handle {
			util.WriteJSONObject(r.Context(), w, n)
			return
		}
	}
	util.WriteError(r.Context(), status.Errorf(status.NotFound, "Karst node not found"), w)
}

func (h *handler) updateNode(w http.ResponseWriter, r *http.Request) {
	user, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	var request struct {
		Name      *string    `json:"name"`
		DomainID  *string    `json:"domain_id"`
		Tags      []string   `json:"tags"`
		ExpiresAt *time.Time `json:"expires_at"`
		Enabled   *bool      `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}
	if (request.Name == nil && request.DomainID == nil) || request.Tags != nil || request.ExpiresAt != nil || request.Enabled != nil {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "only name and domain_id are currently mutable for a Karst node"), w)
		return
	}
	peerRecord, err := h.lookupAdminPeer(r.Context(), user.AccountId, user.UserId, mux.Vars(r)["handle"])
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if h.peerWriter == nil {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "peer manager is not configured"), w)
		return
	}
	if request.Name != nil {
		peerRecord.Name = *request.Name
	}
	// DomainID (ADR-0032) placement is enforced by UpdatePeer itself
	// (ValidateDomainScopedPermission against both the peer's current and
	// requested domain) -- this handler does not need its own check beyond
	// the account-wide/domain-scoped one already gating this whole route.
	if request.DomainID != nil {
		if *request.DomainID == "" {
			util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "provide an explicit root domain ID to move a device to the account root"), w)
			return
		}
		peerRecord.DomainID = *request.DomainID
	}
	if _, err := h.peerWriter.UpdatePeer(r.Context(), user.AccountId, user.UserId, peerRecord); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	identity, err := h.nodes.Get(peerRecord.Key)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	observations, err := h.nodes.SessionObservations(peerRecord.Key)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, toNodeResponse(peerRecord, identity, postureFromObservations(observations)))
}

func (h *handler) deleteNode(w http.ResponseWriter, r *http.Request) {
	user, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	peerRecord, err := h.lookupAdminPeer(r.Context(), user.AccountId, user.UserId, mux.Vars(r)["handle"])
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if h.peerWriter == nil {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "peer manager is not configured"), w)
		return
	}
	if err := h.peerWriter.DeletePeer(r.Context(), user.AccountId, peerRecord.ID, user.UserId); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	// Before the identity goes. Session rows outlive the device on purpose — a
	// user who revokes a stolen laptop still wants to see where it was — so
	// they must be closed while the handle is still known to belong to this
	// subject, and a device deleted mid-session must not be left looking
	// connected forever.
	if closer, ok := h.nodes.(sessionCloser); ok {
		if err := closer.CloseSessionsForHandle(peerRecord.Key, time.Now()); err != nil {
			util.WriteError(r.Context(), err, w)
			return
		}
	}
	if deleter, ok := h.nodes.(nodeDeleter); ok {
		if err := deleter.Delete(peerRecord.Key); err != nil && !errors.Is(err, node.ErrUnknownNode) {
			util.WriteError(r.Context(), err, w)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) lookupAuthorizedPeer(ctx context.Context, accountID, userID, handle string) (*peer.Peer, error) {
	return h.lookupPeer(ctx, accountID, userID, handle, h.peers.GetPeers)
}

// lookupAdminPeer resolves a peer in the administrative node view. It differs
// from lookupAuthorizedPeer because an ordinary member may manage their own
// device through /me, but must never gain administrative /nodes access merely
// by owning one.
func (h *handler) lookupAdminPeer(ctx context.Context, accountID, userID, handle string) (*peer.Peer, error) {
	return h.lookupPeer(ctx, accountID, userID, handle, h.peers.GetAdminPeers)
}

func (h *handler) lookupPeer(ctx context.Context, accountID, userID, handle string, list func(context.Context, string, string, string, string) ([]*peer.Peer, error)) (*peer.Peer, error) {
	decoded, err := url.PathUnescape(handle)
	if err != nil {
		return nil, status.Errorf(status.InvalidArgument, "invalid node handle")
	}
	handle = decoded
	peers, err := list(ctx, accountID, userID, "", "")
	if err != nil {
		return nil, err
	}
	for _, candidate := range peers {
		if candidate.Key == handle {
			if _, err := h.nodes.Get(handle); err != nil {
				return nil, status.Errorf(status.NotFound, "Karst node not found")
			}
			return candidate, nil
		}
	}
	return nil, status.Errorf(status.NotFound, "Karst node not found")
}

func (h *handler) authorizedNodes(ctx context.Context, accountID, userID string) ([]nodeResponse, error) {
	peers, err := h.peers.GetPeers(ctx, accountID, userID, "", "")
	if err != nil {
		return nil, err
	}
	return h.nodesForPeers(peers)
}

// adminNodes is the node view for /nodes. Unlike authorizedNodes, it never
// falls back to a member's own devices: GetAdminPeers returns only an
// account-wide administrator's peers or a delegated admin's domain subtree.
func (h *handler) adminNodes(ctx context.Context, accountID, userID string) ([]nodeResponse, error) {
	peers, err := h.peers.GetAdminPeers(ctx, accountID, userID, "", "")
	if err != nil {
		return nil, err
	}
	return h.nodesForPeers(peers)
}

func (h *handler) nodesForPeers(peers []*peer.Peer) ([]nodeResponse, error) {
	result := make([]nodeResponse, 0, len(peers))
	for _, p := range peers {
		identity, err := h.nodes.Get(p.Key)
		if errors.Is(err, node.ErrUnknownNode) {
			continue // A fork peer is not necessarily an enrolled Karst node.
		}
		if err != nil {
			return nil, err
		}
		observations, err := h.nodes.SessionObservations(p.Key)
		if err != nil {
			return nil, err
		}
		result = append(result, toNodeResponse(p, identity, postureFromObservations(observations)))
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Handle < result[j].Handle })
	return result, nil
}

func toNodeResponse(p *peer.Peer, identity *node.Identity, posture nodePosture) nodeResponse {
	var lastSeen *time.Time
	if p.Status != nil && !p.Status.LastSeen.IsZero() {
		seen := p.Status.LastSeen.UTC()
		lastSeen = &seen
	}
	return nodeResponse{
		Handle: p.Key, Name: p.Name, Platform: peerPlatform(p), UserID: p.UserID, Tags: []string{},
		DomainID: p.DomainID, DNSLabel: p.DNSLabel,
		Enabled: true, CreatedAt: identity.CreatedAt.UTC(), LastSeenAt: lastSeen,
		Posture: posture,
	}
}

// peerPlatform is telemetry reported by the enrolling client. Prefer GoOS,
// which karstd supplies, but retain Platform for clients using the inherited
// peer metadata convention. The fallback is explicit because the portal must
// not pretend it knows an unenrolled client's operating system.
func peerPlatform(p *peer.Peer) string {
	if p.Meta.GoOS != "" {
		return p.Meta.GoOS
	}
	if p.Meta.Platform != "" {
		return p.Meta.Platform
	}
	return "unknown"
}

func postureFromObservations(observations []node.SessionObservation) nodePosture {
	if len(observations) == 0 {
		return nodePosture{Status: "unknown"}
	}
	latest := observations[0]
	latticeOnly := false
	for _, observation := range observations {
		if observation.ObservedAt.After(latest.ObservedAt) {
			latest = observation
		}
		latticeOnly = latticeOnly || observation.LatticeOnly
	}
	at := latest.ObservedAt.UTC()
	suite := latest.Suite
	epoch := latest.PSKEpoch
	state := "pq"
	if latticeOnly {
		state = "lattice_only"
	}
	if time.Since(at) > 5*time.Minute {
		state = "stale"
	}
	return nodePosture{Status: state, Suite: &suite, PSKEpoch: &epoch, LatticeOnly: latticeOnly, ObservedAt: &at}
}

func pageArguments(r *http.Request) (int, int, error) {
	const defaultLimit, maxLimit = 50, 200
	limit := defaultLimit
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > maxLimit {
			return 0, 0, status.Errorf(status.InvalidArgument, "limit must be between 1 and %d", maxLimit)
		}
		limit = parsed
	}
	cursor := r.URL.Query().Get("cursor")
	if cursor == "" {
		return 0, limit, nil
	}
	offset, err := strconv.Atoi(cursor)
	if err != nil || offset < 0 {
		return 0, 0, status.Errorf(status.InvalidArgument, "cursor must be a non-negative offset")
	}
	return offset, limit, nil
}

func filterNodes(nodes []nodeResponse, keep func(nodeResponse) bool) []nodeResponse {
	filtered := make([]nodeResponse, 0, len(nodes))
	for _, n := range nodes {
		if keep(n) {
			filtered = append(filtered, n)
		}
	}
	return filtered
}

// RegisterEnrollmentMetadata delivers public control pins through the same
// authenticated API as member enrollment. The browser supplies its HTTPS
// origin; no forwarded Host header becomes a trust anchor here.
func RegisterEnrollmentMetadata(router *mux.Router, kem, verify []byte) {
	router.HandleFunc("/karst/v1/me/enrollment", func(w http.ResponseWriter, r *http.Request) {
		if _, err := nbcontext.GetUserAuthFromContext(r.Context()); err != nil {
			util.WriteError(r.Context(), err, w)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		util.WriteJSONObject(r.Context(), w, map[string]any{"server_kem_pin": fmt.Sprintf("%x", kem), "server_verify_pin": fmt.Sprintf("%x", verify), "control_minimum_version": 1})
	}).Methods(http.MethodGet)
}
