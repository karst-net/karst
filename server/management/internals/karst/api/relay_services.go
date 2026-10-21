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
	"github.com/netbirdio/netbird/management/internals/karst/relayservice"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

type relayServiceStore interface {
	Create(context.Context, relayservice.Service) (*relayservice.Service, error)
	List(context.Context) ([]relayservice.View, error)
	Delete(context.Context, string) error
}

type relayServicePublisher interface {
	Publication(context.Context) (relayservice.Publication, error)
	Preview(context.Context, bool) ([]relayservice.Service, error)
	SetPublication(context.Context, string, bool) (relayservice.Publication, error)
}

type RelayServiceOptions struct {
	Accounts       accountUpdater
	TurnConfigured bool
}

// RegisterRelayServiceEndpoints adds the explicit association model without
// changing the legacy registries or granting control over external processes.
func RegisterRelayServiceEndpoints(router *mux.Router, manager permissions.Manager, store relayServiceStore, options ...RelayServiceOptions) {
	var config RelayServiceOptions
	if len(options) > 0 {
		config = options[0]
	}
	push := func(ctx context.Context, account string) {
		if config.Accounts != nil {
			config.Accounts.UpdateAccountPeers(ctx, account, types.UpdateReason{Resource: types.UpdateResourceService, Operation: types.UpdateOperationUpdate})
		}
	}
	routes := router.PathPrefix("/karst/v1/relay-services").Subrouter()
	routes.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			if manager == nil {
				util.WriteError(r.Context(), status.Errorf(status.PermissionDenied, "Relay service authorization is not configured"), w)
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
			util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "Relay service storage is not configured"), w)
			return
		}
		ctx := relayservice.WithAccount(r.Context(), user.AccountId)
		if mux.CurrentRoute(r).GetName() == "relay-publication" || mux.CurrentRoute(r).GetName() == "relay-publication-preview" {
			publisher, ok := store.(relayServicePublisher)
			if !ok {
				util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "Relay publication storage unavailable"), w)
				return
			}
			if r.Method == http.MethodOptions {
				return
			}
			if r.Method == http.MethodGet {
				value, err := publisher.Publication(ctx)
				if err != nil {
					relayServiceError(w, r, err)
					return
				}
				util.WriteJSONObject(ctx, w, value)
				return
			}
			if mux.CurrentRoute(r).GetName() == "relay-publication-preview" {
				services, err := publisher.Preview(ctx, config.TurnConfigured)
				if err != nil {
					relayServiceError(w, r, err)
					return
				}
				util.WriteJSONObject(ctx, w, services)
				return
			}
			var request struct {
				Mode        string `json:"mode"`
				Acknowledge bool   `json:"acknowledge_connectivity_change"`
			}
			decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&request); err != nil {
				util.WriteErrorResponse("invalid publication request", http.StatusBadRequest, w)
				return
			}
			if err := decoder.Decode(new(any)); err != io.EOF {
				util.WriteErrorResponse("expected one publication request", http.StatusBadRequest, w)
				return
			}
			if !request.Acknowledge {
				util.WriteErrorResponse("acknowledge_connectivity_change must be true", http.StatusBadRequest, w)
				return
			}
			value, err := publisher.SetPublication(ctx, request.Mode, config.TurnConfigured)
			if err != nil {
				relayServiceError(w, r, err)
				return
			}
			push(ctx, user.AccountId)
			util.WriteJSONObject(ctx, w, value)
			return
		}
		switch r.Method {
		case http.MethodGet:
			views, err := store.List(ctx)
			if err != nil {
				relayServiceError(w, r, err)
				return
			}
			util.WriteJSONObject(ctx, w, views)
		case http.MethodPost:
			var service relayservice.Service
			decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&service); err != nil {
				util.WriteErrorResponse("invalid Relay service JSON", http.StatusBadRequest, w)
				return
			}
			if err := decoder.Decode(new(any)); err != io.EOF {
				util.WriteErrorResponse("expected exactly one Relay service object", http.StatusBadRequest, w)
				return
			}
			created, err := store.Create(ctx, service)
			if err != nil {
				relayServiceError(w, r, err)
				return
			}
			push(ctx, user.AccountId)
			w.Header().Set("Content-Type", "application/json; charset=UTF-8")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(created)
		case http.MethodDelete:
			if err := store.Delete(ctx, mux.Vars(r)["serviceId"]); err != nil {
				relayServiceError(w, r, err)
				return
			}
			push(ctx, user.AccountId)
			w.WriteHeader(http.StatusNoContent)
		}
	}
	routes.HandleFunc("", handle).Methods(http.MethodGet, http.MethodPost, http.MethodOptions)
	routes.HandleFunc("/publication", handle).Methods(http.MethodGet, http.MethodPut, http.MethodOptions).Name("relay-publication")
	routes.HandleFunc("/publication/preview", handle).Methods(http.MethodPost, http.MethodOptions).Name("relay-publication-preview")
	routes.HandleFunc("/{serviceId}", handle).Methods(http.MethodDelete, http.MethodOptions)
}

func relayServiceError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, relayservice.ErrInvalid):
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "%s", err), w)
	case errors.Is(err, relayservice.ErrExists):
		util.WriteError(r.Context(), status.Errorf(status.AlreadyExists, "Relay service already exists"), w)
	case errors.Is(err, relayservice.ErrNotFound):
		util.WriteError(r.Context(), status.Errorf(status.NotFound, "Relay service not found"), w)
	case errors.Is(err, relayservice.ErrNoAccount):
		util.WriteError(r.Context(), status.Errorf(status.PermissionDenied, "account scope required"), w)
	default:
		util.WriteError(r.Context(), status.Errorf(status.Internal, "Relay service storage failed"), w)
	}
}
