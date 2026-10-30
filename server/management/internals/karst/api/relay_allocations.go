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

	"github.com/netbirdio/netbird/management/internals/karst/relayalloc"
	"github.com/netbirdio/netbird/management/internals/karst/relayreg"
	"github.com/netbirdio/netbird/management/internals/karst/relayservice"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

type relayAllocationStore interface {
	Create(context.Context, relayalloc.Allocation) (*relayalloc.Allocation, error)
	List(context.Context) ([]relayalloc.Allocation, error)
	Get(context.Context, string) (*relayalloc.Allocation, error)
	Transition(ctx context.Context, id string, expectedRevision uint64, expectedState, to, reason, instanceID, relayID string) (*relayalloc.Allocation, error)
	RequestDeprovision(ctx context.Context, id string, expectedRevision uint64) (*relayalloc.Allocation, error)
	Delete(ctx context.Context, id string, expectedRevision uint64) error
}

type relayAllocationRegistry interface {
	FindByTLSServerName(context.Context, string) (*relayreg.StoredRelay, error)
}

// relayAllocationGrantStore is relayservice.Store's own Create/Delete,
// reused directly rather than re-implemented -- ADR-0063 is explicit that
// granting must call "that exact transactional path", not a second one.
// Delete here only removes the association (relayservice.Store.Delete's
// own doc comment); it never touches the backend's registry row.
type relayAllocationGrantStore interface {
	Create(context.Context, relayservice.Service) (*relayservice.Service, error)
	Delete(context.Context, string) error
}

type RelayAllocationOptions struct {
	Audit auditReader
}

// relayAllocationsPendingPath and relayAllocationScalerActionPath are the
// hard-allowlist entries karstAuthorization (nodes.go) adds for
// types.UserRoleScaler, alongside the pre-existing relayEnrollTokensPath/
// relayDeenrollPath. Every allocation-driving action is a POST naming the
// one allocation and one step it acts on; "pending" is the only Scaler
// route with no {id}, so it gets its own exact-path check rather than
// trying to fold it into the same pattern.
const relayAllocationsPendingPath = "/karst/v1/relay-allocations/pending"

var relayAllocationScalerActionPath = regexp.MustCompile(`^/karst/v1/relay-allocations/[^/]+/(provisioning|grant|revoke|deprovisioned|failed)$`)

// RegisterRelayAllocationEndpoints adds ADR-0063's admin-triggered relay
// allocation workflow: console-facing create/list/deprovision/delete under
// the normal KarstControl permission gate, plus a handful of narrow,
// single-purpose actions (pending/provisioning/grant/revoke/deprovisioned/
// failed) that only the Scaler role's hard-allowlisted PAT can reach -- the
// reconciliation loop issue #455 adds next drives an allocation through
// these one step at a time. grant/revoke call relayservice directly,
// in-process: the Scaler role itself is never given relay-services access,
// keeping its reach exactly as narrow as roles.Scaler's own doc comment
// says it should be.
func RegisterRelayAllocationEndpoints(router *mux.Router, manager permissions.Manager, store relayAllocationStore, registry relayAllocationRegistry, grants relayAllocationGrantStore, options ...RelayAllocationOptions) {
	var config RelayAllocationOptions
	if len(options) > 0 {
		config = options[0]
	}
	routes := router.PathPrefix("/karst/v1/relay-allocations").Subrouter()
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
		allocCtx := relayalloc.WithAccount(r.Context(), user.AccountId)
		switch mux.CurrentRoute(r).GetName() {
		case "relay-allocations-pending":
			handleRelayAllocationsPending(w, r, allocCtx, store)
		case "relay-allocation-provisioning":
			handleRelayAllocationProvisioning(w, r, allocCtx, store)
		case "relay-allocation-grant":
			registryCtx := relayreg.WithAccount(r.Context(), user.AccountId)
			serviceCtx := relayservice.WithActor(relayservice.WithAccount(r.Context(), user.AccountId), user.UserId)
			handleRelayAllocationGrant(w, r, allocCtx, registryCtx, serviceCtx, store, registry, grants)
		case "relay-allocation-revoke":
			serviceCtx := relayservice.WithActor(relayservice.WithAccount(r.Context(), user.AccountId), user.UserId)
			handleRelayAllocationRevoke(w, r, allocCtx, serviceCtx, store, grants)
		case "relay-allocation-deprovisioned":
			handleRelayAllocationDeprovisioned(w, r, allocCtx, store)
		case "relay-allocation-failed":
			handleRelayAllocationFailed(w, r, allocCtx, store)
		case "relay-allocation-deprovision":
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

	routes.HandleFunc("/pending", handle).Methods(http.MethodPost).Name("relay-allocations-pending")
	routes.HandleFunc("", handle).Methods(http.MethodGet, http.MethodPost, http.MethodOptions)
	routes.HandleFunc("/{id}/provisioning", handle).Methods(http.MethodPost).Name("relay-allocation-provisioning")
	routes.HandleFunc("/{id}/grant", handle).Methods(http.MethodPost).Name("relay-allocation-grant")
	routes.HandleFunc("/{id}/revoke", handle).Methods(http.MethodPost).Name("relay-allocation-revoke")
	routes.HandleFunc("/{id}/deprovisioned", handle).Methods(http.MethodPost).Name("relay-allocation-deprovisioned")
	routes.HandleFunc("/{id}/failed", handle).Methods(http.MethodPost).Name("relay-allocation-failed")
	routes.HandleFunc("/{id}/deprovision", handle).Methods(http.MethodPost, http.MethodOptions).Name("relay-allocation-deprovision")
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

func handleRelayAllocationsList(w http.ResponseWriter, _ *http.Request, ctx context.Context, store relayAllocationStore) {
	rows, err := store.List(ctx)
	if err != nil {
		relayAllocationError(ctx, w, err)
		return
	}
	util.WriteJSONObject(ctx, w, rows)
}

func handleRelayAllocationsCreate(w http.ResponseWriter, r *http.Request, ctx context.Context, store relayAllocationStore) {
	var draft relayalloc.Allocation
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
func handleRelayAllocationDelete(w http.ResponseWriter, r *http.Request, ctx context.Context, store relayAllocationStore) {
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
func handleRelayAllocationDeprovision(w http.ResponseWriter, r *http.Request, ctx context.Context, store relayAllocationStore) {
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
func handleRelayAllocationsPending(w http.ResponseWriter, _ *http.Request, ctx context.Context, store relayAllocationStore) {
	rows, err := store.List(ctx)
	if err != nil {
		relayAllocationError(ctx, w, err)
		return
	}
	pending := make([]relayalloc.Allocation, 0, len(rows))
	for _, row := range rows {
		switch row.State {
		case relayalloc.StateRequested, relayalloc.StateProvisioning, relayalloc.StateGranting, relayalloc.StateRevoking, relayalloc.StateDeprovisioning:
			pending = append(pending, row)
		}
	}
	util.WriteJSONObject(ctx, w, pending)
}

// handleRelayAllocationProvisioning records the Driver::create result the
// loop already has once Driver::create returns -- bookkeeping only, no
// relayservice call here.
func handleRelayAllocationProvisioning(w http.ResponseWriter, r *http.Request, ctx context.Context, store relayAllocationStore) {
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
	if current.State == relayalloc.StateProvisioning {
		util.WriteJSONObject(ctx, w, current) // already recorded -- idempotent retry
		return
	}
	updated, err := store.Transition(ctx, id, *request.ExpectedRevision, relayalloc.StateRequested, relayalloc.StateProvisioning, "", request.InstanceID, "")
	if err != nil {
		relayAllocationError(ctx, w, err)
		return
	}
	util.WriteJSONObject(ctx, w, updated)
}

// handleRelayAllocationGrant is ADR-0063's "granting" step end to end:
// look up the now-registered relay by the tls_server_name the loop's own
// Driver computed before the instance even existed, then call
// relayservice.Create with the allocation's permitted groups -- the exact
// transactional path relayservice.UpdateAccess's own callers use, not a
// second one. A 404 here specifically means "not registered yet, keep
// polling," distinct from every other error, which the loop should report
// through /failed instead of retrying forever.
func handleRelayAllocationGrant(w http.ResponseWriter, r *http.Request, allocCtx, registryCtx, serviceCtx context.Context, store relayAllocationStore, registry relayAllocationRegistry, grants relayAllocationGrantStore) {
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
	case relayalloc.StateReady:
		util.WriteJSONObject(allocCtx, w, current) // already granted -- idempotent retry
		return
	case relayalloc.StateGranting:
		// A previous attempt already recorded intent; fall through and
		// retry the relay lookup/grant call itself.
	case relayalloc.StateProvisioning:
		current, err = store.Transition(allocCtx, id, *request.ExpectedRevision, relayalloc.StateProvisioning, relayalloc.StateGranting, "", "", "")
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
		if errors.Is(err, relayreg.ErrNotFound) {
			util.WriteErrorResponse("relay has not registered yet", http.StatusNotFound, w)
			return
		}
		relayAllocationError(allocCtx, w, err)
		return
	}
	service := relayservice.Service{
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
	if _, err := grants.Create(serviceCtx, service); err != nil && !errors.Is(err, relayservice.ErrExists) {
		failed, ferr := store.Transition(allocCtx, id, current.Revision, relayalloc.StateGranting, relayalloc.StateFailed, err.Error(), "", "")
		if ferr != nil {
			relayAllocationError(allocCtx, w, ferr)
			return
		}
		util.WriteJSONObject(allocCtx, w, failed)
		return
	}
	ready, err := store.Transition(allocCtx, id, current.Revision, relayalloc.StateGranting, relayalloc.StateReady, "", "", relay.ID)
	if err != nil {
		relayAllocationError(allocCtx, w, err)
		return
	}
	util.WriteJSONObject(allocCtx, w, ready)
}

// handleRelayAllocationRevoke withdraws the grant relayservice.Store holds
// before anything about teardown is reported back as deprovisioning --
// ADR-0063's reversed order's first half. relayservice.ErrNotFound (never
// granted, or already revoked by a previous attempt) is success, not a
// failure, mirroring AwsDriver's own deenroll-404-is-success convention.
func handleRelayAllocationRevoke(w http.ResponseWriter, r *http.Request, allocCtx, serviceCtx context.Context, store relayAllocationStore, grants relayAllocationGrantStore) {
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
	if current.State == relayalloc.StateDeprovisioning || current.State == relayalloc.StateDeprovisioned {
		util.WriteJSONObject(allocCtx, w, current) // already withdrawn -- idempotent retry
		return
	}
	if current.State != relayalloc.StateRevoking {
		util.WriteErrorResponse("allocation is not awaiting revocation", http.StatusConflict, w)
		return
	}
	if err := grants.Delete(serviceCtx, id); err != nil && !errors.Is(err, relayservice.ErrNotFound) {
		failed, ferr := store.Transition(allocCtx, id, current.Revision, relayalloc.StateRevoking, relayalloc.StateFailed, err.Error(), "", "")
		if ferr != nil {
			relayAllocationError(allocCtx, w, ferr)
			return
		}
		util.WriteJSONObject(allocCtx, w, failed)
		return
	}
	deprovisioning, err := store.Transition(allocCtx, id, current.Revision, relayalloc.StateRevoking, relayalloc.StateDeprovisioning, "", "", "")
	if err != nil {
		relayAllocationError(allocCtx, w, err)
		return
	}
	util.WriteJSONObject(allocCtx, w, deprovisioning)
}

// handleRelayAllocationDeprovisioned records that Driver::drain/destroy
// already completed -- bookkeeping only, no relayservice call here (the
// grant was already withdrawn by /revoke, before compute teardown began).
func handleRelayAllocationDeprovisioned(w http.ResponseWriter, r *http.Request, ctx context.Context, store relayAllocationStore) {
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
	if current.State == relayalloc.StateDeprovisioned {
		util.WriteJSONObject(ctx, w, current)
		return
	}
	updated, err := store.Transition(ctx, id, *request.ExpectedRevision, relayalloc.StateDeprovisioning, relayalloc.StateDeprovisioned, "", "", "")
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
func handleRelayAllocationFailed(w http.ResponseWriter, r *http.Request, ctx context.Context, store relayAllocationStore) {
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
	if current.State == relayalloc.StateFailed {
		util.WriteJSONObject(ctx, w, current)
		return
	}
	updated, err := store.Transition(ctx, id, *request.ExpectedRevision, current.State, relayalloc.StateFailed, request.Reason, "", "")
	if err != nil {
		relayAllocationError(ctx, w, err)
		return
	}
	util.WriteJSONObject(ctx, w, updated)
}

func relayAllocationError(ctx context.Context, w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, relayalloc.ErrInvalid):
		util.WriteError(ctx, status.Errorf(status.InvalidArgument, "%s", err), w)
	case errors.Is(err, relayalloc.ErrExists):
		util.WriteError(ctx, status.Errorf(status.AlreadyExists, "allocation changed; reload before retrying"), w)
	case errors.Is(err, relayalloc.ErrNotFound):
		util.WriteError(ctx, status.Errorf(status.NotFound, "relay allocation not found"), w)
	case errors.Is(err, relayalloc.ErrNoAccount):
		util.WriteError(ctx, status.Errorf(status.PermissionDenied, "account scope required"), w)
	default:
		util.WriteError(ctx, status.Errorf(status.Internal, "relay allocation storage failed"), w)
	}
}
