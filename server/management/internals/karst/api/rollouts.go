// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	"gorm.io/gorm"

	"github.com/netbirdio/netbird/management/internals/karst/rollout"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

type rolloutStore interface {
	Create(context.Context, rollout.Plan, []rollout.PlanComponent) (*rollout.Plan, []rollout.PlanComponent, error)
	Get(context.Context, string) (*rollout.Plan, []rollout.PlanComponent, error)
	List(context.Context) ([]rollout.Plan, error)
	Start(ctx context.Context, id string, expectedRevision uint64, acknowledge, overrideIncompatibility, stillBlocking bool, maintenanceWindowNote string) (*rollout.Plan, error)
	MarkComponentApplied(ctx context.Context, id string, expectedRevision uint64, name, observedDigest string) (*rollout.Plan, []rollout.PlanComponent, error)
	MarkComponentFailed(ctx context.Context, id string, expectedRevision uint64, name, reason string) (*rollout.Plan, []rollout.PlanComponent, error)
	RollBack(ctx context.Context, id string, expectedRevision uint64, reason string) (*rollout.Plan, error)
	Delete(ctx context.Context, id string, expectedRevision uint64) error
}

// rolloutFleetChecker is node.Store's own CountRelayLifecycleBelow/
// CountGatewayIngressBelow, mirroring rollout package's own narrow
// fleetChecker interface so this file does not need to import node
// directly, and so rollout.Preview can be called with whatever concrete
// store bootstrap.go wires in (normally the same *node.Store already
// threaded into NetmapHandler).
type rolloutFleetChecker interface {
	CountRelayLifecycleBelow(ctx context.Context, account string, required uint32, tx *gorm.DB) (int64, error)
	CountGatewayIngressBelow(ctx context.Context, account string, required uint32, tx *gorm.DB) (int64, error)
}

type RolloutOptions struct {
	Audit auditReader
}

type rolloutComponentRequest struct {
	Name                         string  `json:"name"`
	Sequence                     int     `json:"sequence"`
	CurrentDigest                string  `json:"current_digest,omitempty"`
	TargetDigest                 string  `json:"target_digest"`
	VerificationRef              string  `json:"verification_ref"`
	RequiresRelayLifecycleSchema *uint32 `json:"requires_relay_lifecycle_schema,omitempty"`
	RequiresGatewayIngressSchema *uint32 `json:"requires_gateway_ingress_schema,omitempty"`
}

// rolloutPlanPayload is the flat JSON shape every route below returns:
// the plan's own fields, its components, a live (never cached)
// compatibility preview where relevant, and an optional reconciliation
// note. Embedding *rollout.Plan flattens its fields into the same object
// rather than nesting them -- there is no name collision with Components/
// Compatibility/Note to worry about.
type rolloutPlanPayload struct {
	*rollout.Plan
	Components    []rollout.PlanComponent          `json:"components"`
	Compatibility []rollout.ComponentCompatibility `json:"compatibility,omitempty"`
	Note          string                           `json:"note,omitempty"`
}

// RegisterRolloutEndpoints adds ADR-0066's admin-tracked component rollout
// workflow. Every route is uniformly admin/owner-gated via
// requireRolloutAdminOrOwner, the same role check versions.go's own
// handler.versions already uses -- unlike relay allocation, there is no
// device/Scaler-role action to allowlist through karstAuthorization's own
// per-route rules. That gate is still what this mounts behind, though:
// requireRolloutAdminOrOwner only reads nbcontext.RoleFromContext, it does
// not populate it, and nothing upstream of this package's own routes does
// either -- versions.go's identical check only works because handler.versions
// is registered on nodes.go's karstRouter, which wraps every route in
// karstAuthorization(permissionsManager), and that call is what puts the
// role in context via ValidateAccountAccess/nbcontext.WithRole. This
// package's routes are mounted directly on the bootstrap-level router
// instead (RegisterAPIExtension, not RegisterEndpoints), so without wrapping
// them in karstAuthorization here too, RoleFromContext always came back
// !ok and every request -- admin, owner, anyone -- was refused.
func RegisterRolloutEndpoints(router *mux.Router, manager permissions.Manager, store rolloutStore, fleet rolloutFleetChecker, options ...RolloutOptions) {
	var config RolloutOptions
	if len(options) > 0 {
		config = options[0]
	}
	routes := router.PathPrefix("/karst/v1/rollouts").Subrouter()
	routes.Use((&handler{audit: config.Audit}).auditMutations)
	routes.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if manager == nil {
				util.WriteError(r.Context(), status.Errorf(status.PermissionDenied, "rollout authorization is not configured"), w)
				return
			}
			karstAuthorization(manager)(next).ServeHTTP(w, r)
		})
	})
	routes.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			requireRolloutAdminOrOwner(next).ServeHTTP(w, r)
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
			util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "Rollout plan storage is not configured"), w)
			return
		}
		ctx := rollout.WithAccount(r.Context(), user.AccountId)
		switch mux.CurrentRoute(r).GetName() {
		case "rollout-start":
			handleRolloutStart(w, r, ctx, user.AccountId, store, fleet)
		case "rollout-mark-applied":
			handleRolloutMarkApplied(w, r, ctx, store)
		case "rollout-mark-failed":
			handleRolloutMarkFailed(w, r, ctx, store)
		case "rollout-rollback":
			handleRolloutRollback(w, r, ctx, store)
		default:
			switch r.Method {
			case http.MethodGet:
				if _, ok := mux.Vars(r)["id"]; ok {
					handleRolloutGet(w, r, ctx, user.AccountId, store, fleet)
				} else {
					handleRolloutsList(w, r, ctx, store)
				}
			case http.MethodPost:
				handleRolloutsCreate(w, r, ctx, user.AccountId, store, fleet)
			case http.MethodDelete:
				handleRolloutDelete(w, r, ctx, store)
			}
		}
	}

	routes.HandleFunc("", handle).Methods(http.MethodGet, http.MethodPost, http.MethodOptions)
	routes.HandleFunc("/{id}", handle).Methods(http.MethodGet, http.MethodDelete, http.MethodOptions)
	routes.HandleFunc("/{id}/start", handle).Methods(http.MethodPost, http.MethodOptions).Name("rollout-start")
	routes.HandleFunc("/{id}/components/{name}/mark-applied", handle).Methods(http.MethodPost, http.MethodOptions).Name("rollout-mark-applied")
	routes.HandleFunc("/{id}/components/{name}/mark-failed", handle).Methods(http.MethodPost, http.MethodOptions).Name("rollout-mark-failed")
	routes.HandleFunc("/{id}/rollback", handle).Methods(http.MethodPost, http.MethodOptions).Name("rollout-rollback")
}

// requireRolloutAdminOrOwner mirrors versions.go's own handler.versions role
// check exactly -- this workflow is administrative, not device-facing, so it
// narrows past karstAuthorization's own module-level allowlist (which this
// package's RegisterRolloutEndpoints now wraps every route in, see its own
// doc comment) to admin/owner specifically, the same way handler.versions
// narrows past karstRouter's identical wrapping.
func requireRolloutAdminOrOwner(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}
		if _, err := nbcontext.GetUserAuthFromContext(r.Context()); err != nil {
			util.WriteError(r.Context(), err, w)
			return
		}
		role, ok := nbcontext.RoleFromContext(r.Context())
		if !ok || (types.UserRole(role) != types.UserRoleOwner && types.UserRole(role) != types.UserRoleAdmin) {
			util.WriteErrorResponse("Component rollout plans require the admin or owner role", http.StatusForbidden, w)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// decodeRolloutRequest decodes exactly one JSON object within limit bytes
// into dst, rejecting unknown fields -- the same strict-decode convention
// relay_allocations.go's own decodeRelayAllocationRequest already follows,
// kept as this file's own copy rather than a shared export since neither
// file is the other's dependency.
func decodeRolloutRequest(w http.ResponseWriter, r *http.Request, limit int64, dst any) bool {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		util.WriteErrorResponse("invalid rollout request", http.StatusBadRequest, w)
		return false
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		util.WriteErrorResponse("expected exactly one rollout request object", http.StatusBadRequest, w)
		return false
	}
	return true
}

func handleRolloutsList(w http.ResponseWriter, _ *http.Request, ctx context.Context, store rolloutStore) {
	rows, err := store.List(ctx)
	if err != nil {
		rolloutError(ctx, w, err)
		return
	}
	util.WriteJSONObject(ctx, w, rows)
}

func handleRolloutsCreate(w http.ResponseWriter, r *http.Request, ctx context.Context, account string, store rolloutStore, fleet rolloutFleetChecker) {
	var request struct {
		TargetRelease         string                    `json:"target_release"`
		MaintenanceWindowNote string                    `json:"maintenance_window_note,omitempty"`
		Components            []rolloutComponentRequest `json:"components"`
	}
	if !decodeRolloutRequest(w, r, 16384, &request) {
		return
	}
	components := make([]rollout.PlanComponent, len(request.Components))
	for i, component := range request.Components {
		components[i] = rollout.PlanComponent{
			Name:                         component.Name,
			Sequence:                     component.Sequence,
			CurrentDigest:                component.CurrentDigest,
			TargetDigest:                 component.TargetDigest,
			VerificationRef:              component.VerificationRef,
			RequiresRelayLifecycleSchema: component.RequiresRelayLifecycleSchema,
			RequiresGatewayIngressSchema: component.RequiresGatewayIngressSchema,
		}
	}
	draft := rollout.Plan{TargetRelease: request.TargetRelease, MaintenanceWindowNote: request.MaintenanceWindowNote}
	created, createdComponents, err := store.Create(ctx, draft, components)
	if err != nil {
		rolloutError(ctx, w, err)
		return
	}
	payload, err := rolloutPayload(r.Context(), account, created, createdComponents, fleet, "")
	if err != nil {
		rolloutError(ctx, w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(payload)
}

func handleRolloutGet(w http.ResponseWriter, r *http.Request, ctx context.Context, account string, store rolloutStore, fleet rolloutFleetChecker) {
	plan, components, err := store.Get(ctx, mux.Vars(r)["id"])
	if err != nil {
		rolloutError(ctx, w, err)
		return
	}
	payload, err := rolloutPayload(r.Context(), account, plan, components, fleet, "")
	if err != nil {
		rolloutError(ctx, w, err)
		return
	}
	util.WriteJSONObject(ctx, w, payload)
}

// handleRolloutStart re-checks the live compatibility preview itself --
// never trusting whatever the console last rendered -- and refuses to
// start if anything is still blocking unless override_incompatibility is
// explicitly set, which Store.Start also re-validates server-side.
func handleRolloutStart(w http.ResponseWriter, r *http.Request, ctx context.Context, account string, store rolloutStore, fleet rolloutFleetChecker) {
	var request struct {
		ExpectedRevision        *uint64 `json:"revision"`
		Acknowledge             bool    `json:"acknowledge"`
		OverrideIncompatibility bool    `json:"override_incompatibility"`
		MaintenanceWindowNote   string  `json:"maintenance_window_note,omitempty"`
	}
	if !decodeRolloutRequest(w, r, 4096, &request) {
		return
	}
	if request.ExpectedRevision == nil {
		util.WriteErrorResponse("revision is required", http.StatusBadRequest, w)
		return
	}
	id := mux.Vars(r)["id"]
	_, components, err := store.Get(ctx, id)
	if err != nil {
		rolloutError(ctx, w, err)
		return
	}
	compatibility, err := rollout.Preview(r.Context(), account, components, fleet)
	if err != nil {
		rolloutError(ctx, w, err)
		return
	}
	updated, err := store.Start(ctx, id, *request.ExpectedRevision, request.Acknowledge, request.OverrideIncompatibility, rollout.AnyBlocking(compatibility), request.MaintenanceWindowNote)
	if err != nil {
		rolloutError(ctx, w, err)
		return
	}
	_, components, err = store.Get(ctx, id)
	if err != nil {
		rolloutError(ctx, w, err)
		return
	}
	payload := rolloutPlanPayload{Plan: updated, Components: components, Compatibility: compatibility}
	util.WriteJSONObject(ctx, w, payload)
}

// handleRolloutMarkApplied is the console's own entry point once the
// operator has actually run the documented cosign/nomad steps by hand
// (ADR-0066): it never executes them itself. It reconciles the component's
// claimed completion, non-blockingly, against the existing
// KARST_COMPONENT_VERSIONS_FILE deployment snapshot loadDeploymentSnapshot
// (versions.go) already reads for the software-versions page.
func handleRolloutMarkApplied(w http.ResponseWriter, r *http.Request, ctx context.Context, store rolloutStore) {
	var request struct {
		ExpectedRevision *uint64 `json:"revision"`
	}
	if !decodeRolloutRequest(w, r, 1024, &request) {
		return
	}
	if request.ExpectedRevision == nil {
		util.WriteErrorResponse("revision is required", http.StatusBadRequest, w)
		return
	}
	id, name := mux.Vars(r)["id"], mux.Vars(r)["name"]
	_, components, err := store.Get(ctx, id)
	if err != nil {
		rolloutError(ctx, w, err)
		return
	}
	var targetDigest string
	for _, component := range components {
		if component.Name == name {
			targetDigest = component.TargetDigest
		}
	}
	observedDigest, note := reconcileObservedDigest(name, targetDigest)
	updated, updatedComponents, err := store.MarkComponentApplied(ctx, id, *request.ExpectedRevision, name, observedDigest)
	if err != nil {
		rolloutError(ctx, w, err)
		return
	}
	util.WriteJSONObject(ctx, w, rolloutPlanPayload{Plan: updated, Components: updatedComponents, Note: note})
}

func handleRolloutMarkFailed(w http.ResponseWriter, r *http.Request, ctx context.Context, store rolloutStore) {
	var request struct {
		ExpectedRevision *uint64 `json:"revision"`
		Reason           string  `json:"reason"`
	}
	if !decodeRolloutRequest(w, r, 1024, &request) {
		return
	}
	if request.ExpectedRevision == nil || request.Reason == "" {
		util.WriteErrorResponse("revision and reason are required", http.StatusBadRequest, w)
		return
	}
	id, name := mux.Vars(r)["id"], mux.Vars(r)["name"]
	updated, components, err := store.MarkComponentFailed(ctx, id, *request.ExpectedRevision, name, request.Reason)
	if err != nil {
		rolloutError(ctx, w, err)
		return
	}
	util.WriteJSONObject(ctx, w, rolloutPlanPayload{Plan: updated, Components: components})
}

// handleRolloutRollback requires an explicit acknowledge, the same
// double opt-in relay allocation's own deprovision route already requires.
// Control only records that a rollback happened (ADR-0066) -- the operator
// still restores the previous verified digest and reruns the documented
// nomad steps by hand.
func handleRolloutRollback(w http.ResponseWriter, r *http.Request, ctx context.Context, store rolloutStore) {
	var request struct {
		ExpectedRevision *uint64 `json:"revision"`
		Acknowledge      bool    `json:"acknowledge_rollback"`
		Reason           string  `json:"reason"`
	}
	if !decodeRolloutRequest(w, r, 1024, &request) {
		return
	}
	if request.ExpectedRevision == nil {
		util.WriteErrorResponse("revision is required", http.StatusBadRequest, w)
		return
	}
	if !request.Acknowledge {
		util.WriteErrorResponse("review and acknowledge the rollback", http.StatusBadRequest, w)
		return
	}
	id := mux.Vars(r)["id"]
	updated, err := store.RollBack(ctx, id, *request.ExpectedRevision, request.Reason)
	if err != nil {
		rolloutError(ctx, w, err)
		return
	}
	_, components, err := store.Get(ctx, id)
	if err != nil {
		rolloutError(ctx, w, err)
		return
	}
	util.WriteJSONObject(ctx, w, rolloutPlanPayload{Plan: updated, Components: components})
}

func handleRolloutDelete(w http.ResponseWriter, r *http.Request, ctx context.Context, store rolloutStore) {
	revision, ok := parseRolloutRevision(w, r)
	if !ok {
		return
	}
	if err := store.Delete(ctx, mux.Vars(r)["id"], revision); err != nil {
		rolloutError(ctx, w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func parseRolloutRevision(w http.ResponseWriter, r *http.Request) (uint64, bool) {
	revision, err := strconv.ParseUint(r.URL.Query().Get("revision"), 10, 64)
	if err != nil {
		util.WriteErrorResponse("a numeric revision query parameter is required", http.StatusBadRequest, w)
		return 0, false
	}
	return revision, true
}

func rolloutPayload(ctx context.Context, account string, plan *rollout.Plan, components []rollout.PlanComponent, fleet rolloutFleetChecker, note string) (rolloutPlanPayload, error) {
	compatibility, err := rollout.Preview(ctx, account, components, fleet)
	if err != nil {
		return rolloutPlanPayload{}, err
	}
	return rolloutPlanPayload{Plan: plan, Components: components, Compatibility: compatibility, Note: note}, nil
}

// rolloutContainerName maps a plan component name to the container/task
// name scripts/compose-versions.py's snapshot and the Nomad job itself use
// -- "relay_job" names this job's relay task group specifically (ADR-0066),
// distinct from the broader relay registry, but the job's own task/service
// name is simply "relay".
func rolloutContainerName(component string) string {
	if component == rollout.ComponentRelayJob {
		return "relay"
	}
	return component
}

// reconcileObservedDigest compares the deployment snapshot's observed
// image ID for component against targetDigest, non-blockingly: a mismatch
// or unavailable snapshot is surfaced as a note, never an error, since
// control never executed the rollout itself and has no stronger claim on
// "what is actually running" than the operator's own next snapshot refresh.
func reconcileObservedDigest(component, targetDigest string) (digest, note string) {
	snapshot, status := loadDeploymentSnapshot()
	if status != "available" {
		return "", "deployment snapshot is " + status + "; re-run scripts/compose-versions.py after applying, then mark this component applied again to refresh the observed digest"
	}
	containerName := rolloutContainerName(component)
	for _, observed := range snapshot.Components {
		if observed.Name != containerName {
			continue
		}
		if observed.ImageID == "" {
			return "", "deployment snapshot has no image ID recorded for " + containerName + "; re-run scripts/compose-versions.py"
		}
		if observed.ImageID != targetDigest {
			return observed.ImageID, "observed digest does not match the target digest; the snapshot may be stale -- re-run scripts/compose-versions.py"
		}
		return observed.ImageID, ""
	}
	return "", "no matching container named " + containerName + " in the deployment snapshot; re-run scripts/compose-versions.py"
}

func rolloutError(ctx context.Context, w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, rollout.ErrInvalid):
		util.WriteError(ctx, status.Errorf(status.InvalidArgument, "%s", err), w)
	case errors.Is(err, rollout.ErrExists):
		util.WriteError(ctx, status.Errorf(status.AlreadyExists, "rollout plan changed; reload before retrying"), w)
	case errors.Is(err, rollout.ErrNotFound):
		util.WriteError(ctx, status.Errorf(status.NotFound, "rollout plan not found"), w)
	case errors.Is(err, rollout.ErrNoAccount):
		util.WriteError(ctx, status.Errorf(status.PermissionDenied, "account scope required"), w)
	default:
		util.WriteError(ctx, status.Errorf(status.Internal, "rollout plan storage failed"), w)
	}
}
