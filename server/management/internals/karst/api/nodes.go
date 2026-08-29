// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// Package api serves Karst-owned administrative endpoints on the management
// router. It deliberately consumes the router's existing authentication
// middleware; this package never parses credentials itself.
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
	"github.com/netbirdio/netbird/management/internals/karst/node"
	karstpolicy "github.com/netbirdio/netbird/management/internals/karst/policy"
	"github.com/netbirdio/netbird/management/internals/karst/relayreg"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/types"
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

type enrollmentKeyBinder interface {
	BindEnrollmentKey(key, userID string) error
}

// peerReader is the existing, permission-aware peer listing. Its result is
// already scoped to the authenticated caller, so it is the authorization
// boundary for the peer half of the join.
type peerReader interface {
	GetPeers(ctx context.Context, accountID, userID, nameFilter, ipFilter string) ([]*peer.Peer, error)
}

type handler struct {
	nodes      nodeReader
	peers      peerReader
	audit      auditReader
	policy     policyReader
	relays     relayReader
	bedrock    bedrockReader
	chain      bedrockLogReader
	peerWriter peerWriter
}

type peerWriter interface {
	UpdatePeer(context.Context, string, string, *peer.Peer) (*peer.Peer, error)
	DeletePeer(context.Context, string, string, string) error
}

// setupKeyIssuer is deliberately optional. The normal daemon's AccountManager
// implements it; keeping it separate preserves the read-only test seam and
// ensures this small portal surface cannot acquire arbitrary account writes.
type setupKeyIssuer interface {
	CreateSetupKey(context.Context, string, string, types.SetupKeyType, time.Duration, []string, int, string, bool, bool) (*types.SetupKey, error)
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
	Head(context.Context) (uint64, string, error)
	Verify(context.Context) (uint64, error)
	List(context.Context, int, int) ([]audit.Entry, error)
	ListFiltered(context.Context, string, string, int, int) ([]audit.Entry, error)
	ListBefore(context.Context, uint64, int) ([]audit.Entry, error)
	AddSink(context.Context, string, string) (*audit.Sink, error)
}
type auditAnchorReader interface {
	Head(context.Context) (uint64, string, error)
	VerifyFrom(context.Context, uint64, string) (uint64, error)
}
type relayReader interface {
	List(context.Context) ([]relayreg.StoredRelay, error)
	Create(context.Context, relayreg.Entry) (*relayreg.StoredRelay, error)
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
}

const maxRequestBodyBytes = 1 << 20

// RegisterEndpoints registers the portion of the Karst contract backed by
// persisted state today. It is called on the management server's shared router
// before that router is served, so its routes receive the same auth, CORS, and
// metrics middleware as every /api endpoint.
func RegisterEndpoints(nodes nodeReader, peers peerReader, peerWriter peerWriter, log auditReader, policies policyReader, relays relayReader, bedrockStore bedrockReader, bedrockLog bedrockLogReader, permissionsManager permissions.Manager, router *mux.Router) {
	h := &handler{nodes: nodes, peers: peers, peerWriter: peerWriter, audit: log, policy: policies, relays: relays, bedrock: bedrockStore, chain: bedrockLog}
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
	karstRouter.HandleFunc("/policy", h.policyCurrent).Methods(http.MethodGet, http.MethodOptions)
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
	me.HandleFunc("/devices/enrol", h.meEnrol).Methods(http.MethodPost, http.MethodOptions)
	me.HandleFunc("/devices/{handle}", h.meRenameDevice).Methods(http.MethodPatch, http.MethodOptions)
	me.HandleFunc("/devices/{handle}", h.meRevokeDevice).Methods(http.MethodDelete, http.MethodOptions)
	me.HandleFunc("/sessions", h.meSessions).Methods(http.MethodGet, http.MethodOptions)
	me.HandleFunc("/access", h.meAccess).Methods(http.MethodGet, http.MethodOptions)
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
		if _, err := h.audit.Append(r.Context(), user.UserId, "karst."+strings.ToLower(r.Method), path, ""); err != nil {
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
			if strings.HasPrefix(strings.TrimPrefix(r.URL.Path, "/api"), "/karst/v1/me/") {
				scoped := audit.WithAccount(relayreg.WithAccount(karstpolicy.WithAccount(r.Context(), user.AccountId), user.AccountId), user.AccountId)
				next.ServeHTTP(w, r.WithContext(scoped))
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
			scoped := audit.WithAccount(relayreg.WithAccount(karstpolicy.WithAccount(ctx, user.AccountId), user.AccountId), user.AccountId)
			next.ServeHTTP(w, r.WithContext(scoped))
		})
	}
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

func (h *handler) meEnrol(w http.ResponseWriter, r *http.Request) {
	user, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	issuer, ok := h.peerWriter.(setupKeyIssuer)
	if !ok {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "device enrolment is not configured"), w)
		return
	}
	key, err := issuer.CreateSetupKey(r.Context(), user.AccountId, "portal device", types.SetupKeyOneOff, 15*time.Minute, nil, 1, user.UserId, false, false)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	binder, ok := h.nodes.(enrollmentKeyBinder)
	if !ok {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "portal enrollment ownership is not configured"), w)
		return
	}
	if err := binder.BindEnrollmentKey(key.Key, user.UserId); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	expires := time.Now().UTC().Add(15 * time.Minute)
	if key.ExpiresAt != nil {
		expires = key.ExpiresAt.UTC()
	}
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
		}
	case bedrock.OpAuthorityList:
		if a, err := bedrock.ParseAuthorityList(e.Body); err == nil {
			out["authorities"] = fingerprints(a.Authorities)
			out["quorum"] = a.Q
		}
	case bedrock.OpNodeSign:
		if n, err := bedrock.ParseNodeSign(e.Body); err == nil {
			out["handle"] = n.Handle
			out["identity"] = fingerprints([][]byte{n.IdentityKey})[0]
			out["kem"] = fingerprints([][]byte{n.KemPublicKey})[0]
			out["dh"] = fingerprints([][]byte{n.DhPublicKey})[0]
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
			entries = append(entries, bedrock.Entry{Seq: state.HeadSeq + uint64(len(entries)) + 1, Time: time.Now().UTC().Unix(), Op: bedrock.OpNodeSign, Body: bedrock.NodeSignBody(handle, identity.PublicKey, identity.KemPublicKey, identity.DhPublicKey, 0, 0)})
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
			util.WriteJSONObject(r.Context(), w, map[string]any{"source": "roster_mtime", "last_confirmed_at": nil, "sessions": nil, "bytes": nil, "admission_state": "unknown"})
			return
		}
	}
	util.WriteError(r.Context(), status.Errorf(status.NotFound, "relay not found"), w)
}

// enrolledKeys returns the caller's authorized nodes as the coverage query
// needs them: handle to the datapath keys the netmap presents for that node.
//
// The keys, not just the handles. Coverage binds a handle to its ML-KEM and
// X25519 static keys (spec §6.1), so a check that passed only handles would
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
			DhPublicKey:  identity.DhPublicKey,
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
	if errors.Is(err, bedrock.ErrAcknowledgementMismatch) {
		required := bedrock.UncoveredAt(state, enrolled, at)
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]any{"code": "acknowledgement_mismatch", "message": err.Error(), "required_cut_off_handles": required})
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
	util.WriteJSONObject(r.Context(), w, relays)
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
	if err := json.NewEncoder(w).Encode(relay); err != nil {
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

func (h *handler) auditExport(w http.ResponseWriter, r *http.Request) {
	if _, err := nbcontext.GetUserAuthFromContext(r.Context()); err != nil {
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
		h.streamAuditJSON(w, r)
		return
	}
	h.streamAuditCSV(w, r)
}

func (h *handler) streamAuditJSON(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("["))
	cursor := uint64(0)
	first := true
	for {
		page, err := h.audit.ListBefore(r.Context(), cursor, 200)
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

func (h *handler) streamAuditCSV(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=karst-audit.csv")
	writer := csv.NewWriter(w)
	if err := writer.Write([]string{"sequence", "created_at", "actor", "action", "target", "detail", "previous_hash", "hash"}); err != nil {
		return
	}
	cursor := uint64(0)
	for {
		page, err := h.audit.ListBefore(r.Context(), cursor, 200)
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
	w.Header().Set("ETag", strconv.FormatUint(version.Version, 10))
	util.WriteJSONObject(r.Context(), w, policyVersionResponse(version))
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
		util.WriteJSONObject(r.Context(), w, map[string]any{"added": []any{}, "removed": []any{}, "diagnostics": []map[string]any{{"severity": "error", "message": err.Error(), "line": line, "column": column}}})
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
	util.WriteJSONObject(r.Context(), w, map[string]any{"added": added, "removed": removed})
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

func (h *handler) auditList(w http.ResponseWriter, r *http.Request) {
	if !h.requireAudit(w, r) {
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
	entries, err := h.audit.ListFiltered(r.Context(), r.URL.Query().Get("actor"), r.URL.Query().Get("action"), offset, limit+1)
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
	seq, _, headErr := h.audit.Head(r.Context())
	if headErr != nil && !errors.Is(headErr, audit.ErrEmpty) {
		util.WriteError(r.Context(), headErr, w)
		return
	}
	var cursor *string
	if next != nil {
		value := next.(string)
		cursor = &value
	}
	anchor := karstcontract.AuditAnchor{EntriesSinceAnchor: int(seq)}
	if h.chain != nil {
		user, userErr := nbcontext.GetUserAuthFromContext(r.Context())
		if userErr != nil {
			util.WriteError(r.Context(), userErr, w)
			return
		}
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
				if seq >= state.Anchor.AuditSeq {
					anchor.EntriesSinceAnchor = int(seq - state.Anchor.AuditSeq)
				}
				for _, chainEntry := range chainEntries {
					if chainEntry.Op == bedrock.OpAnchor {
						parsed, err := bedrock.ParseAnchor(chainEntry.Body)
						if err == nil && parsed.AuditSeq == state.Anchor.AuditSeq {
							at := time.Unix(chainEntry.Time, 0).UTC()
							anchor.LastAnchoredAt = &at
						}
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
	if _, err := nbcontext.GetUserAuthFromContext(r.Context()); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	seq, hash, err := h.audit.Head(r.Context())
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
	if _, err := nbcontext.GetUserAuthFromContext(r.Context()); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	bad, err := h.audit.Verify(r.Context())
	valid := err == nil
	seq, hash, headErr := h.audit.Head(r.Context())
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
	nodes, err := h.authorizedNodes(r.Context(), userAuth.AccountId, userAuth.UserId)
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
	nodes, err := h.authorizedNodes(r.Context(), userAuth.AccountId, userAuth.UserId)
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

// nodeResponse has no identity public key, KEM key, DH key, PSK, or discovery
// key. Handles are stable identifiers, not key material, and are the only
// identity value this REST surface returns.
type nodeResponse struct {
	Handle     string      `json:"handle"`
	Name       string      `json:"name"`
	Platform   string      `json:"platform"`
	UserID     string      `json:"user_id"`
	Tags       []string    `json:"tags"`
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

	nodes, err := h.authorizedNodes(r.Context(), userAuth.AccountId, userAuth.UserId)
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
	nodes, err := h.authorizedNodes(r.Context(), userAuth.AccountId, userAuth.UserId)
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
		Tags      []string   `json:"tags"`
		ExpiresAt *time.Time `json:"expires_at"`
		Enabled   *bool      `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}
	if request.Name == nil || request.Tags != nil || request.ExpiresAt != nil || request.Enabled != nil {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "only name is currently mutable for a Karst node"), w)
		return
	}
	peerRecord, err := h.lookupAuthorizedPeer(r.Context(), user.AccountId, user.UserId, mux.Vars(r)["handle"])
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if h.peerWriter == nil {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "peer manager is not configured"), w)
		return
	}
	peerRecord.Name = *request.Name
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
	peerRecord, err := h.lookupAuthorizedPeer(r.Context(), user.AccountId, user.UserId, mux.Vars(r)["handle"])
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
	decoded, err := url.PathUnescape(handle)
	if err != nil {
		return nil, status.Errorf(status.InvalidArgument, "invalid node handle")
	}
	handle = decoded
	peers, err := h.peers.GetPeers(ctx, accountID, userID, "", "")
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
