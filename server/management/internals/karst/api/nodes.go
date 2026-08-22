// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// Package api serves Karst-owned administrative endpoints on the management
// router. It deliberately consumes the router's existing authentication
// middleware; this package never parses credentials itself.
package api

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"

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
	peerWriter peerWriter
}

type peerWriter interface {
	UpdatePeer(context.Context, string, string, *peer.Peer) (*peer.Peer, error)
	DeletePeer(context.Context, string, string, string) error
}

type policyReader interface {
	Current(context.Context) (*karstpolicy.Version, error)
	Write(context.Context, string, string, uint64) (*karstpolicy.Version, error)
	Get(context.Context, uint64) (*karstpolicy.Version, error)
	List(context.Context, int, int) ([]karstpolicy.Version, error)
}

type auditReader interface {
	Head(context.Context) (uint64, string, error)
	Verify(context.Context) (uint64, error)
	List(context.Context, int, int) ([]audit.Entry, error)
	ListFiltered(context.Context, string, string, int, int) ([]audit.Entry, error)
	ListBefore(context.Context, uint64, int) ([]audit.Entry, error)
	AddSink(context.Context, string, string) (*audit.Sink, error)
}
type relayReader interface {
	List(context.Context) ([]relayreg.StoredRelay, error)
	Create(context.Context, relayreg.Entry) (*relayreg.StoredRelay, error)
	Delete(context.Context, string) error
}
type bedrockReader interface {
	Configuration(context.Context, string) (*bedrock.Configuration, error)
	SetMode(context.Context, string, string, []string, []string) (*bedrock.Configuration, error)
	Uncovered(context.Context, string, []string) ([]string, error)
}

const maxRequestBodyBytes = 1 << 20

// RegisterEndpoints registers the portion of the Karst contract backed by
// persisted state today. It is called on the management server's shared router
// before that router is served, so its routes receive the same auth, CORS, and
// metrics middleware as every /api endpoint.
func RegisterEndpoints(nodes nodeReader, peers peerReader, peerWriter peerWriter, log auditReader, policies policyReader, relays relayReader, bedrockStore bedrockReader, permissionsManager permissions.Manager, router *mux.Router) {
	h := &handler{nodes: nodes, peers: peers, peerWriter: peerWriter, audit: log, policy: policies, relays: relays, bedrock: bedrockStore}
	karstRouter := router.PathPrefix("/karst/v1").Subrouter()
	karstRouter.Use(limitRequestBody)
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
	karstRouter.HandleFunc("/bedrock/responses/import", h.bedrockResponsesImport).Methods(http.MethodPost, http.MethodOptions)
	karstRouter.HandleFunc("/bedrock/mode", h.bedrockMode).Methods(http.MethodPut, http.MethodOptions)
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
		case "/karst/v1/policy/validate", "/karst/v1/policy/preview", "/karst/v1/policy/test", "/karst/v1/bedrock/requests/export":
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

func requireUser(w http.ResponseWriter, r *http.Request) bool {
	if _, err := nbcontext.GetUserAuthFromContext(r.Context()); err != nil {
		util.WriteError(r.Context(), err, w)
		return false
	}
	return true
}

// Bedrock's offline workflow owns signed log entries and requests. Until an
// authority bundle is imported, these endpoints honestly expose an empty
// queue/log rather than fabricating cryptographic state in the console.
func (h *handler) bedrockLog(w http.ResponseWriter, r *http.Request) {
	if requireUser(w, r) {
		util.WriteJSONObject(r.Context(), w, map[string]any{"items": []any{}, "next_cursor": nil})
	}
}
func (h *handler) bedrockLogVerify(w http.ResponseWriter, r *http.Request) {
	if requireUser(w, r) {
		util.WriteErrorResponse("Bedrock log verification is not implemented", http.StatusNotImplemented, w)
	}
}
func (h *handler) bedrockRequests(w http.ResponseWriter, r *http.Request) {
	if requireUser(w, r) {
		util.WriteJSONObject(r.Context(), w, []any{})
	}
}
func (h *handler) bedrockRequestsExport(w http.ResponseWriter, r *http.Request) {
	if requireUser(w, r) {
		util.WriteErrorResponse("Bedrock request export is not implemented", http.StatusNotImplemented, w)
	}
}
func (h *handler) bedrockResponsesImport(w http.ResponseWriter, r *http.Request) {
	if requireUser(w, r) {
		util.WriteErrorResponse("Bedrock response import is not implemented", http.StatusNotImplemented, w)
	}
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
	identities, err := h.authorizedNodes(r.Context(), user.AccountId, user.UserId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	handles := make([]string, 0, len(identities))
	for _, identity := range identities {
		handles = append(handles, identity.Handle)
	}
	uncovered, err := h.bedrock.Uncovered(r.Context(), user.AccountId, handles)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, map[string]any{"mode": configuration.Mode, "quorum": configuration.Quorum, "roots": []any{}, "authorities": []any{}, "uncovered_handles": uncovered})
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
	identities, err := h.authorizedNodes(r.Context(), user.AccountId, user.UserId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	handles := make([]string, 0, len(identities))
	for _, identity := range identities {
		handles = append(handles, identity.Handle)
	}
	configuration, err := h.bedrock.SetMode(r.Context(), user.AccountId, request.Mode, request.Acknowledged, handles)
	if errors.Is(err, bedrock.ErrAcknowledgementMismatch) {
		required, coverageErr := h.bedrock.Uncovered(r.Context(), user.AccountId, handles)
		if coverageErr != nil {
			util.WriteError(r.Context(), coverageErr, w)
			return
		}
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
	_ = json.NewEncoder(w).Encode(sink)
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
	util.WriteJSONObject(r.Context(), w, written)
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
	util.WriteJSONObject(r.Context(), w, map[string]any{"items": versions, "next_cursor": next})
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
	util.WriteJSONObject(r.Context(), w, version)
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
	util.WriteJSONObject(r.Context(), w, version)
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
	util.WriteJSONObject(r.Context(), w, version)
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
		util.WriteJSONObject(r.Context(), w, map[string]any{"valid": false, "diagnostics": []map[string]any{{"severity": "error", "message": err.Error(), "line": 1, "column": 1}}})
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
		util.WriteJSONObject(r.Context(), w, map[string]any{"added": []any{}, "removed": []any{}, "diagnostics": []map[string]any{{"severity": "error", "message": err.Error(), "line": 1, "column": 1}}})
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
	items := make([]karstcontract.AuditEntry, 0, len(entries))
	for _, entry := range entries {
		items = append(items, toAuditEntry(entry))
	}
	util.WriteJSONObject(r.Context(), w, karstcontract.AuditPage{
		Items:      items,
		NextCursor: cursor,
		Anchor: karstcontract.AuditAnchor{
			EntriesSinceAnchor: int(seq),
		},
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
	if h.peerWriter == nil {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "peer manager is not configured"), w)
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
	if h.peerWriter == nil {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "peer manager is not configured"), w)
		return
	}
	peerRecord, err := h.lookupAuthorizedPeer(r.Context(), user.AccountId, user.UserId, mux.Vars(r)["handle"])
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if err := h.peerWriter.DeletePeer(r.Context(), user.AccountId, peerRecord.ID, user.UserId); err != nil {
		util.WriteError(r.Context(), err, w)
		return
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
		Handle: p.Key, Name: p.Name, UserID: p.UserID, Tags: []string{},
		Enabled: true, CreatedAt: identity.CreatedAt.UTC(), LastSeenAt: lastSeen,
		Posture: posture,
	}
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
