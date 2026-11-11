// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strconv"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/management/internals/karst/estavellealloc"
	"github.com/netbirdio/netbird/management/internals/karst/estavellereg"
	"github.com/netbirdio/netbird/management/internals/karst/estavelleservice"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

type estavelleAllocationStore interface {
	Create(context.Context, estavellealloc.Allocation) (*estavellealloc.Allocation, error)
	List(context.Context) ([]estavellealloc.Allocation, error)
	Get(context.Context, string) (*estavellealloc.Allocation, error)
	Transition(ctx context.Context, id string, expectedRevision uint64, expectedState, to, reason, instanceID, estavelleID string) (*estavellealloc.Allocation, error)
	RequestDeprovision(ctx context.Context, id string, expectedRevision uint64) (*estavellealloc.Allocation, error)
	Delete(ctx context.Context, id string, expectedRevision uint64) error
}

type estavelleAllocationRegistry interface {
	FindByTLSServerName(context.Context, string) (*estavellereg.StoredEstavelle, error)
}

// estavelleAllocationGrantStore is estavelleservice.Store's own Create/Delete,
// reused directly rather than re-implemented -- ADR-0063 is explicit that
// granting must call "that exact transactional path", not a second one.
// Delete here only removes the association (estavelleservice.Store.Delete's
// own doc comment); it never touches the backend's registry row.
type estavelleAllocationGrantStore interface {
	Create(context.Context, estavelleservice.Service) (*estavelleservice.Service, error)
	Delete(context.Context, string) error
}

type EstavelleAllocationOptions struct {
	Audit auditReader
}

// estavelleAllocationsPendingPath and estavelleAllocationScalerActionPath are the
// hard-allowlist entries karstAuthorization (nodes.go) adds for
// types.UserRoleScaler, alongside the pre-existing relayEnrollTokensPath/
// relayDeenrollPath. Every allocation-driving action is a POST naming the
// one allocation and one step it acts on; "pending" is the only Scaler
// route with no {id}, so it gets its own exact-path check rather than
// trying to fold it into the same pattern.
//
// Deprecated, not removed: ADR-0045's 2026-11-04 addendum moves relay
// allocation's own reconciliation in-process (package estavellealloc,
// awsdrive_loop.go's RunAllocateWorker), which drives the same state
// machine through direct Go calls instead of these six routes. Nothing in
// this codebase calls them anymore, but they are kept working, exactly as
// this repo's own cloudaccounts->infraconnections rename addendum kept its
// old routes working rather than breaking an external consumer that might
// already have built the now-removed `karst-scaler allocate` process
// against this exact surface.
const estavelleAllocationsPendingPath = "/karst/v1/estavelle-allocations/pending"

var estavelleAllocationScalerActionPath = regexp.MustCompile(`^/karst/v1/estavelle-allocations/[^/]+/(provisioning|grant|revoke|deprovisioned|failed)$`)

// RegisterEstavelleAllocationEndpoints adds ADR-0063's admin-triggered relay
// allocation workflow: console-facing create/list/deprovision/delete under
// the normal KarstControl permission gate, plus a handful of narrow,
// single-purpose actions (pending/provisioning/grant/revoke/deprovisioned/
// failed) that only the Scaler role's hard-allowlisted PAT can reach -- the
// reconciliation loop issue #455 adds next drives an allocation through
// these one step at a time. grant/revoke call estavelleservice directly,
// in-process: the Scaler role itself is never given relay-services access,
// keeping its reach exactly as narrow as roles.Scaler's own doc comment
// says it should be.
func RegisterEstavelleAllocationEndpoints(router *mux.Router, manager permissions.Manager, store estavelleAllocationStore, registry estavelleAllocationRegistry, grants estavelleAllocationGrantStore, options ...EstavelleAllocationOptions) {
	var config EstavelleAllocationOptions
	if len(options) > 0 {
		config = options[0]
	}
	routes := router.PathPrefix("/karst/v1/estavelle-allocations").Subrouter()
	routes.Use((&handler{audit: config.Audit}).auditMutations)
	routes.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			if manager == nil {
				util.WriteError(r.Context(), status.Errorf(status.PermissionDenied, "Relay allocation authorization is not configured"), w)
				return
			}
			karstAuthorization(manager)(next).ServeHTTP(w, r)
		})
	})

	handle := func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			return
		}
		user, err := nbcontext.GetUserAuthFromContext(r.Context())
		if err != nil {
			util.WriteError(r.Context(), err, w)
			return
		}
		if store == nil {
			util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "Relay allocation storage is not configured"), w)
			return
		}
		allocCtx := estavellealloc.WithAccount(r.Context(), user.AccountId)
		switch mux.CurrentRoute(r).GetName() {
		case "estavelle-allocations-pending":
			handleRelayAllocationsPending(w, r, allocCtx, store)
		case "estavelle-allocation-provisioning":
			handleRelayAllocationProvisioning(w, r, allocCtx, store)
		case "estavelle-allocation-grant":
			registryCtx := estavellereg.WithAccount(r.Context(), user.AccountId)
			serviceCtx := estavelleservice.WithActor(estavelleservice.WithAccount(r.Context(), user.AccountId), user.UserId)
			handleRelayAllocationGrant(w, r, allocCtx, registryCtx, serviceCtx, store, registry, grants)
		case "estavelle-allocation-revoke":
			serviceCtx := estavelleservice.WithActor(estavelleservice.WithAccount(r.Context(), user.AccountId), user.UserId)
			handleRelayAllocationRevoke(w, r, allocCtx, serviceCtx, store, grants)
		case "estavelle-allocation-deprovisioned":
			handleRelayAllocationDeprovisioned(w, r, allocCtx, store)
		case "estavelle-allocation-failed":
			handleRelayAllocationFailed(w, r, allocCtx, store)
		case "estavelle-allocation-deprovision":
			handleRelayAllocationDeprovision(w, r, allocCtx, store)
		default:
			switch r.Method {
			case http.MethodGet:
				handleRelayAllocationsList(w, r, allocCtx, store)
			case http.MethodPost:
				handleRelayAllocationsCreate(w, r, allocCtx, store)
			case http.MethodDelete:
				handleRelayAllocationDelete(w, r, allocCtx, store)
			}
		}
	}

	routes.HandleFunc("/pending", handle).Methods(http.MethodPost).Name("estavelle-allocations-pending")
	routes.HandleFunc("", handle).Methods(http.MethodGet, http.MethodPost, http.MethodOptions)
	routes.HandleFunc("/{id}/provisioning", handle).Methods(http.MethodPost).Name("estavelle-allocation-provisioning")
	routes.HandleFunc("/{id}/grant", handle).Methods(http.MethodPost).Name("estavelle-allocation-grant")
	routes.HandleFunc("/{id}/revoke", handle).Methods(http.MethodPost).Name("estavelle-allocation-revoke")
	routes.HandleFunc("/{id}/deprovisioned", handle).Methods(http.MethodPost).Name("estavelle-allocation-deprovisioned")
	routes.HandleFunc("/{id}/failed", handle).Methods(http.MethodPost).Name("estavelle-allocation-failed")
	routes.HandleFunc("/{id}/deprovision", handle).Methods(http.MethodPost, http.MethodOptions).Name("estavelle-allocation-deprovision")
	routes.HandleFunc("/{id}", handle).Methods(http.MethodDelete, http.MethodOptions)
}

// decodeRelayAllocationRequest decodes exactly one JSON object within
// limit bytes into dst, rejecting unknown fields -- the same strict-decode
// convention relay_services.go's own handler repeats per route, factored
// out once here since every action below shares it.
func decodeRelayAllocationRequest(w http.ResponseWriter, r *http.Request, limit int64, dst any) bool {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		util.WriteErrorResponse("invalid relay allocation request", http.StatusBadRequest, w)
		return false
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		util.WriteErrorResponse("expected exactly one relay allocation request object", http.StatusBadRequest, w)
		return false
	}
	return true
}

func handleRelayAllocationsList(w http.ResponseWriter, _ *http.Request, ctx context.Context, store estavelleAllocationStore) {
	rows, err := store.List(ctx)
	if err != nil {
		relayAllocationError(ctx, w, err)
		return
	}
	util.WriteJSONObject(ctx, w, rows)
}

func handleRelayAllocationsCreate(w http.ResponseWriter, r *http.Request, ctx context.Context, store estavelleAllocationStore) {
	var draft estavellealloc.Allocation
	if !decodeRelayAllocationRequest(w, r, 8192, &draft) {
		return
	}
	created, err := store.Create(ctx, draft)
	if err != nil {
		relayAllocationError(ctx, w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(created)
}

// handleRelayAllocationDelete only ever removes a row Store.Delete itself
// agrees is safe to remove outright (StateRequested or StateDeprovisioned);
// anything else is rejected with ErrInvalid, and the console is expected to
// call /deprovision first.
func handleRelayAllocationDelete(w http.ResponseWriter, r *http.Request, ctx context.Context, store estavelleAllocationStore) {
	revision, ok := parseRelayAllocationRevision(w, r)
	if !ok {
		return
	}
	if err := store.Delete(ctx, mux.Vars(r)["id"], revision); err != nil {
		relayAllocationError(ctx, w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func parseRelayAllocationRevision(w http.ResponseWriter, r *http.Request) (uint64, bool) {
	revision, err := strconv.ParseUint(r.URL.Query().Get("revision"), 10, 64)
	if err != nil {
		util.WriteErrorResponse("a numeric revision query parameter is required", http.StatusBadRequest, w)
		return 0, false
	}
	return revision, true
}

// handleRelayAllocationDeprovision is the console's own entry point into
// teardown -- ADR-0063's reversed order starts here, moving a ready or
// failed allocation into StateRevoking. Mirrors relay-services' own
// acknowledge+revision double opt-in on every mutating action.
func handleRelayAllocationDeprovision(w http.ResponseWriter, r *http.Request, ctx context.Context, store estavelleAllocationStore) {
	var request struct {
		ExpectedRevision *uint64 `json:"revision"`
		Acknowledge      bool    `json:"acknowledge_deprovision"`
	}
	if !decodeRelayAllocationRequest(w, r, 256, &request) {
		return
	}
	if request.ExpectedRevision == nil {
		util.WriteErrorResponse("revision is required", http.StatusBadRequest, w)
		return
	}
	if !request.Acknowledge {
		util.WriteErrorResponse("review and acknowledge the deprovision request", http.StatusBadRequest, w)
		return
	}
	allocation, err := store.RequestDeprovision(ctx, mux.Vars(r)["id"], *request.ExpectedRevision)
	if err != nil {
		relayAllocationError(ctx, w, err)
		return
	}
	util.WriteJSONObject(ctx, w, allocation)
}

// handleRelayAllocationsPending answers the reconciliation loop's own poll:
// every allocation it still has work to do on. StateReady, StateFailed
// (unless an admin has since requested its deprovision) and
// StateDeprovisioned need nothing further from the loop.
func handleRelayAllocationsPending(w http.ResponseWriter, _ *http.Request, ctx context.Context, store estavelleAllocationStore) {
	rows, err := store.List(ctx)
	if err != nil {
		relayAllocationError(ctx, w, err)
		return
	}
	pending := make([]estavellealloc.Allocation, 0, len(rows))
	for _, row := range rows {
		switch row.State {
		case estavellealloc.StateRequested, estavellealloc.StateProvisioning, estavellealloc.StateGranting, estavellealloc.StateRevoking, estavellealloc.StateDeprovisioning:
			pending = append(pending, row)
		}
	}
	util.WriteJSONObject(ctx, w, pending)
}

// handleRelayAllocationProvisioning records the Driver::create result the
// loop already has once Driver::create returns -- bookkeeping only, no
// estavelleservice call here.
func handleRelayAllocationProvisioning(w http.ResponseWriter, r *http.Request, ctx context.Context, store estavelleAllocationStore) {
	var request struct {
		ExpectedRevision *uint64 `json:"expected_revision"`
		InstanceID       string  `json:"instance_id"`
	}
	if !decodeRelayAllocationRequest(w, r, 1024, &request) {
		return
	}
	if request.ExpectedRevision == nil || request.InstanceID == "" {
		util.WriteErrorResponse("expected_revision and instance_id are required", http.StatusBadRequest, w)
		return
	}
	id := mux.Vars(r)["id"]
	current, err := store.Get(ctx, id)
	if err != nil {
		relayAllocationError(ctx, w, err)
		return
	}
	if current.State == estavellealloc.StateProvisioning {
		util.WriteJSONObject(ctx, w, current) // already recorded -- idempotent retry
		return
	}
	updated, err := store.Transition(ctx, id, *request.ExpectedRevision, estavellealloc.StateRequested, estavellealloc.StateProvisioning, "", request.InstanceID, "")
	if err != nil {
		relayAllocationError(ctx, w, err)
		return
	}
	util.WriteJSONObject(ctx, w, updated)
}

// handleRelayAllocationGrant is ADR-0063's "granting" step end to end:
// look up the now-registered relay by the tls_server_name the loop's own
// Driver computed before the instance even existed, then call
// estavelleservice.Create with the allocation's permitted groups -- the exact
// transactional path estavelleservice.UpdateAccess's own callers use, not a
// second one. A 404 here specifically means "not registered yet, keep
// polling," distinct from every other error, which the loop should report
// through /failed instead of retrying forever.
func handleRelayAllocationGrant(w http.ResponseWriter, r *http.Request, allocCtx, registryCtx, serviceCtx context.Context, store estavelleAllocationStore, registry estavelleAllocationRegistry, grants estavelleAllocationGrantStore) {
	var request struct {
		ExpectedRevision *uint64 `json:"expected_revision"`
		TLSServerName    string  `json:"tls_server_name"`
	}
	if !decodeRelayAllocationRequest(w, r, 1024, &request) {
		return
	}
	if request.ExpectedRevision == nil || request.TLSServerName == "" {
		util.WriteErrorResponse("expected_revision and tls_server_name are required", http.StatusBadRequest, w)
		return
	}
	if registry == nil || grants == nil {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "Relay allocation granting is not configured"), w)
		return
	}
	id := mux.Vars(r)["id"]
	current, err := store.Get(allocCtx, id)
	if err != nil {
		relayAllocationError(allocCtx, w, err)
		return
	}
	switch current.State {
	case estavellealloc.StateReady:
		util.WriteJSONObject(allocCtx, w, current) // already granted -- idempotent retry
		return
	case estavellealloc.StateGranting:
		// A previous attempt already recorded intent; fall through and
		// retry the relay lookup/grant call itself.
	case estavellealloc.StateProvisioning:
		current, err = store.Transition(allocCtx, id, *request.ExpectedRevision, estavellealloc.StateProvisioning, estavellealloc.StateGranting, "", "", "")
		if err != nil {
			relayAllocationError(allocCtx, w, err)
			return
		}
	default:
		util.WriteErrorResponse("allocation is not awaiting a grant", http.StatusConflict, w)
		return
	}
	relay, err := registry.FindByTLSServerName(registryCtx, request.TLSServerName)
	if err != nil {
		if errors.Is(err, estavellereg.ErrNotFound) {
			util.WriteErrorResponse("relay has not registered yet", http.StatusNotFound, w)
			return
		}
		relayAllocationError(allocCtx, w, err)
		return
	}
	service := estavelleservice.Service{
		ID:            id,
		PonorID:       relay.ID,
		AccessManaged: true,
		AllowedGroups: current.PermittedGroups,
		ExitIPv4:      current.EgressV4,
		ExitIPv6:      current.EgressV6,
	}
	// ErrExists here means a previous attempt's Create already landed and
	// only the Transition below crashed or timed out -- resuming forward
	// is correct, not a real failure.
	if _, err := grants.Create(serviceCtx, service); err != nil && !errors.Is(err, estavelleservice.ErrExists) {
		failed, ferr := store.Transition(allocCtx, id, current.Revision, estavellealloc.StateGranting, estavellealloc.StateFailed, err.Error(), "", "")
		if ferr != nil {
			relayAllocationError(allocCtx, w, ferr)
			return
		}
		util.WriteJSONObject(allocCtx, w, failed)
		return
	}
	ready, err := store.Transition(allocCtx, id, current.Revision, estavellealloc.StateGranting, estavellealloc.StateReady, "", "", relay.ID)
	if err != nil {
		relayAllocationError(allocCtx, w, err)
		return
	}
	util.WriteJSONObject(allocCtx, w, ready)
}

// handleRelayAllocationRevoke withdraws the grant estavelleservice.Store holds
// before anything about teardown is reported back as deprovisioning --
// ADR-0063's reversed order's first half. estavelleservice.ErrNotFound (never
// granted, or already revoked by a previous attempt) is success, not a
// failure, mirroring AwsDriver's own deenroll-404-is-success convention.
func handleRelayAllocationRevoke(w http.ResponseWriter, r *http.Request, allocCtx, serviceCtx context.Context, store estavelleAllocationStore, grants estavelleAllocationGrantStore) {
	var request struct {
		ExpectedRevision *uint64 `json:"expected_revision"`
	}
	if !decodeRelayAllocationRequest(w, r, 256, &request) {
		return
	}
	if request.ExpectedRevision == nil {
		util.WriteErrorResponse("expected_revision is required", http.StatusBadRequest, w)
		return
	}
	if grants == nil {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "Relay allocation revocation is not configured"), w)
		return
	}
	id := mux.Vars(r)["id"]
	current, err := store.Get(allocCtx, id)
	if err != nil {
		relayAllocationError(allocCtx, w, err)
		return
	}
	if current.State == estavellealloc.StateDeprovisioning || current.State == estavellealloc.StateDeprovisioned {
		util.WriteJSONObject(allocCtx, w, current) // already withdrawn -- idempotent retry
		return
	}
	if current.State != estavellealloc.StateRevoking {
		util.WriteErrorResponse("allocation is not awaiting revocation", http.StatusConflict, w)
		return
	}
	if err := grants.Delete(serviceCtx, id); err != nil && !errors.Is(err, estavelleservice.ErrNotFound) {
		failed, ferr := store.Transition(allocCtx, id, current.Revision, estavellealloc.StateRevoking, estavellealloc.StateFailed, err.Error(), "", "")
		if ferr != nil {
			relayAllocationError(allocCtx, w, ferr)
			return
		}
		util.WriteJSONObject(allocCtx, w, failed)
		return
	}
	deprovisioning, err := store.Transition(allocCtx, id, current.Revision, estavellealloc.StateRevoking, estavellealloc.StateDeprovisioning, "", "", "")
	if err != nil {
		relayAllocationError(allocCtx, w, err)
		return
	}
	util.WriteJSONObject(allocCtx, w, deprovisioning)
}

// handleRelayAllocationDeprovisioned records that Driver::drain/destroy
// already completed -- bookkeeping only, no estavelleservice call here (the
// grant was already withdrawn by /revoke, before compute teardown began).
func handleRelayAllocationDeprovisioned(w http.ResponseWriter, r *http.Request, ctx context.Context, store estavelleAllocationStore) {
	var request struct {
		ExpectedRevision *uint64 `json:"expected_revision"`
	}
	if !decodeRelayAllocationRequest(w, r, 256, &request) {
		return
	}
	if request.ExpectedRevision == nil {
		util.WriteErrorResponse("expected_revision is required", http.StatusBadRequest, w)
		return
	}
	id := mux.Vars(r)["id"]
	current, err := store.Get(ctx, id)
	if err != nil {
		relayAllocationError(ctx, w, err)
		return
	}
	if current.State == estavellealloc.StateDeprovisioned {
		util.WriteJSONObject(ctx, w, current)
		return
	}
	updated, err := store.Transition(ctx, id, *request.ExpectedRevision, estavellealloc.StateDeprovisioning, estavellealloc.StateDeprovisioned, "", "", "")
	if err != nil {
		relayAllocationError(ctx, w, err)
		return
	}
	util.WriteJSONObject(ctx, w, updated)
}

// handleRelayAllocationFailed reports failure of whichever step the loop
// was on when a Driver call or an unrecoverable condition (not "not
// registered yet" -- that is /grant's own 404) stopped it, infer the "from"
// state from the row itself rather than trusting a caller-supplied one.
func handleRelayAllocationFailed(w http.ResponseWriter, r *http.Request, ctx context.Context, store estavelleAllocationStore) {
	var request struct {
		ExpectedRevision *uint64 `json:"expected_revision"`
		Reason           string  `json:"reason"`
	}
	if !decodeRelayAllocationRequest(w, r, 1024, &request) {
		return
	}
	if request.ExpectedRevision == nil || request.Reason == "" {
		util.WriteErrorResponse("expected_revision and reason are required", http.StatusBadRequest, w)
		return
	}
	id := mux.Vars(r)["id"]
	current, err := store.Get(ctx, id)
	if err != nil {
		relayAllocationError(ctx, w, err)
		return
	}
	if current.State == estavellealloc.StateFailed {
		util.WriteJSONObject(ctx, w, current)
		return
	}
	updated, err := store.Transition(ctx, id, *request.ExpectedRevision, current.State, estavellealloc.StateFailed, request.Reason, "", "")
	if err != nil {
		relayAllocationError(ctx, w, err)
		return
	}
	util.WriteJSONObject(ctx, w, updated)
}

func relayAllocationError(ctx context.Context, w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, estavellealloc.ErrInvalid):
		util.WriteError(ctx, status.Errorf(status.InvalidArgument, "%s", err), w)
	case errors.Is(err, estavellealloc.ErrExists):
		util.WriteError(ctx, status.Errorf(status.AlreadyExists, "allocation changed; reload before retrying"), w)
	case errors.Is(err, estavellealloc.ErrNotFound):
		util.WriteError(ctx, status.Errorf(status.NotFound, "relay allocation not found"), w)
	case errors.Is(err, estavellealloc.ErrNoAccount):
		util.WriteError(ctx, status.Errorf(status.PermissionDenied, "account scope required"), w)
	default:
		util.WriteError(ctx, status.Errorf(status.Internal, "relay allocation storage failed"), w)
	}
}
