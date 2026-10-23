// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/netbirdio/netbird/management/internals/karst/externalturn"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

type externalTurnStore interface {
	Create(context.Context, externalturn.CreateRequest) (*externalturn.Server, error)
	Update(context.Context, string, externalturn.UpdateRequest) (*externalturn.Server, error)
	List(context.Context) ([]externalturn.Server, error)
	Delete(context.Context, string) error
	Reorder(context.Context, []string) error
}

type ExternalTurnOptions struct {
	Accounts accountUpdater
}

// RegisterExternalTurnEndpoints adds issue #420's admin-configured,
// account-wide external TURN server list. Every response is the
// credential-free externalturn.Response projection -- see that package's
// own doc comment for why there is no read path for the stored value here
// at all, not even an obscured one.
func RegisterExternalTurnEndpoints(router *mux.Router, manager permissions.Manager, store externalTurnStore, options ...ExternalTurnOptions) {
	var config ExternalTurnOptions
	if len(options) > 0 {
		config = options[0]
	}
	push := func(ctx context.Context, account string) {
		if config.Accounts != nil {
			config.Accounts.UpdateAccountPeers(ctx, account, types.UpdateReason{Resource: types.UpdateResourceExternalTurn, Operation: types.UpdateOperationUpdate})
		}
	}
	routes := router.PathPrefix("/karst/v1/external-turn-servers").Subrouter()
	routes.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			if manager == nil {
				util.WriteError(r.Context(), status.Errorf(status.PermissionDenied, "External TURN server authorization is not configured"), w)
				return
			}
			karstAuthorization(manager)(next).ServeHTTP(w, r)
		})
	})
	handle := func(w http.ResponseWriter, r *http.Request) {
		user, err := nbcontext.GetUserAuthFromContext(r.Context())
		if err != nil {
			util.WriteError(r.Context(), err, w)
			return
		}
		if store == nil {
			util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "External TURN server storage is not configured"), w)
			return
		}
		ctx := externalturn.WithAccount(r.Context(), user.AccountId)
		if mux.CurrentRoute(r).GetName() == "external-turn-reorder" {
			if r.Method == http.MethodOptions {
				return
			}
			var request struct {
				Ids []string `json:"ids"`
			}
			decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&request); err != nil {
				util.WriteErrorResponse("invalid reorder request", http.StatusBadRequest, w)
				return
			}
			if err := decoder.Decode(new(any)); err != io.EOF {
				util.WriteErrorResponse("expected one reorder request", http.StatusBadRequest, w)
				return
			}
			if err := store.Reorder(ctx, request.Ids); err != nil {
				externalTurnError(w, r, err)
				return
			}
			push(ctx, user.AccountId)
			views, err := store.List(ctx)
			if err != nil {
				externalTurnError(w, r, err)
				return
			}
			util.WriteJSONObject(ctx, w, toExternalTurnResponses(views))
			return
		}
		if id, ok := mux.Vars(r)["serverId"]; ok {
			switch r.Method {
			case http.MethodOptions:
				return
			case http.MethodPut:
				var request externalturn.UpdateRequest
				decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192))
				decoder.DisallowUnknownFields()
				if err := decoder.Decode(&request); err != nil {
					util.WriteErrorResponse("invalid external TURN server JSON", http.StatusBadRequest, w)
					return
				}
				if err := decoder.Decode(new(any)); err != io.EOF {
					util.WriteErrorResponse("expected exactly one external TURN server object", http.StatusBadRequest, w)
					return
				}
				updated, err := store.Update(ctx, id, request)
				if err != nil {
					externalTurnError(w, r, err)
					return
				}
				push(ctx, user.AccountId)
				response := updated.ToResponse()
				util.WriteJSONObject(ctx, w, response)
			case http.MethodDelete:
				if err := store.Delete(ctx, id); err != nil {
					externalTurnError(w, r, err)
					return
				}
				push(ctx, user.AccountId)
				w.WriteHeader(http.StatusNoContent)
			}
			return
		}
		switch r.Method {
		case http.MethodOptions:
			return
		case http.MethodGet:
			views, err := store.List(ctx)
			if err != nil {
				externalTurnError(w, r, err)
				return
			}
			util.WriteJSONObject(ctx, w, toExternalTurnResponses(views))
		case http.MethodPost:
			var request externalturn.CreateRequest
			decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&request); err != nil {
				util.WriteErrorResponse("invalid external TURN server JSON", http.StatusBadRequest, w)
				return
			}
			if err := decoder.Decode(new(any)); err != io.EOF {
				util.WriteErrorResponse("expected exactly one external TURN server object", http.StatusBadRequest, w)
				return
			}
			created, err := store.Create(ctx, request)
			if err != nil {
				externalTurnError(w, r, err)
				return
			}
			push(ctx, user.AccountId)
			response := created.ToResponse()
			w.Header().Set("Content-Type", "application/json; charset=UTF-8")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(response)
		}
	}
	routes.HandleFunc("", handle).Methods(http.MethodGet, http.MethodPost, http.MethodOptions)
	routes.HandleFunc("/reorder", handle).Methods(http.MethodPut, http.MethodOptions).Name("external-turn-reorder")
	routes.HandleFunc("/{serverId}", handle).Methods(http.MethodPut, http.MethodDelete, http.MethodOptions)
}

func toExternalTurnResponses(servers []externalturn.Server) []externalturn.Response {
	out := make([]externalturn.Response, 0, len(servers))
	for i := range servers {
		out = append(out, servers[i].ToResponse())
	}
	return out
}

func externalTurnError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, externalturn.ErrNotFound):
		util.WriteError(r.Context(), status.Errorf(status.NotFound, "External TURN server not found"), w)
	case errors.Is(err, externalturn.ErrNoAccount):
		util.WriteError(r.Context(), status.Errorf(status.PermissionDenied, "account scope required"), w)
	case errors.Is(err, externalturn.ErrEncryptionRequired):
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "%s", err), w)
	case errors.Is(err, externalturn.ErrInvalid):
		// Every validate()/Reorder consistency-check message -- bad uri
		// scheme, empty username/credential, a malformed reorder set --
		// is wrapped in ErrInvalid precisely so it is safe to echo
		// verbatim here, unlike an unwrapped infrastructure error below.
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "%s", err), w)
	default:
		util.WriteError(r.Context(), status.Errorf(status.Internal, "External TURN server storage failed"), w)
	}
}
