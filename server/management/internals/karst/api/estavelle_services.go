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
	"github.com/netbirdio/netbird/management/internals/karst/policy"
	"github.com/netbirdio/netbird/management/internals/karst/estavelleservice"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

type estavelleServiceStore interface {
	Create(context.Context, estavelleservice.Service) (*estavelleservice.Service, error)
	List(context.Context) ([]estavelleservice.View, error)
	Delete(context.Context, string) error
}

type estavelleServicePublisher interface {
	Publication(context.Context) (estavelleservice.Publication, error)
	Preview(context.Context) ([]estavelleservice.Service, error)
	SetPublication(context.Context, string) (estavelleservice.Publication, error)
}

type estavelleServiceModes interface {
	SetModes(context.Context, string, bool) (*estavelleservice.Service, error)
}

type EstavelleServiceOptions struct {
	Audit    auditReader
	Accounts accountUpdater
}

// RegisterEstavelleServiceEndpoints adds the explicit association model without
// changing the legacy registries or granting control over external processes.
func RegisterEstavelleServiceEndpoints(router *mux.Router, manager permissions.Manager, store estavelleServiceStore, options ...EstavelleServiceOptions) {
	var config EstavelleServiceOptions
	if len(options) > 0 {
		config = options[0]
	}
	push := func(ctx context.Context, account string) {
		if config.Accounts != nil {
			config.Accounts.UpdateAccountPeers(ctx, account, types.UpdateReason{Resource: types.UpdateResourceService, Operation: types.UpdateOperationUpdate})
		}
	}
	routes := router.PathPrefix("/karst/v1/estavelle-services").Subrouter()
	routes.Use((&handler{audit: config.Audit}).auditMutations)
	routes.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			if manager == nil {
				util.WriteError(r.Context(), status.Errorf(status.PermissionDenied, "Estavelle service authorization is not configured"), w)
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
			util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "Estavelle service storage is not configured"), w)
			return
		}
		ctx := estavelleservice.WithActor(estavelleservice.WithAccount(r.Context(), user.AccountId), user.UserId)
		if mux.CurrentRoute(r).GetName() == "estavelle-access" {
			scoped, ok := store.(interface {
				UpdateAccess(context.Context, string, estavelleservice.Service) (*estavelleservice.Service, error)
			})
			if !ok {
				util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "Estavelle access storage unavailable"), w)
				return
			}
			var request struct {
				estavelleservice.Service
				ExpectedRevision *uint64 `json:"revision"`
				Acknowledge      bool    `json:"acknowledge_access_change"`
			}
			decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 65536))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&request); err != nil {
				util.WriteErrorResponse("invalid Estavelle access request", http.StatusBadRequest, w)
				return
			}
			if err := decoder.Decode(new(any)); err != io.EOF {
				util.WriteErrorResponse("expected one Estavelle access request", http.StatusBadRequest, w)
				return
			}
			if request.ExpectedRevision == nil {
				util.WriteErrorResponse("service revision is required", http.StatusBadRequest, w)
				return
			}
			request.Service.Revision = *request.ExpectedRevision
			if !request.Acknowledge {
				util.WriteErrorResponse("review and acknowledge the access change", http.StatusBadRequest, w)
				return
			}
			service, err := scoped.UpdateAccess(ctx, mux.Vars(r)["serviceId"], request.Service)
			if err != nil {
				estavelleServiceError(w, r, err)
				return
			}
			push(ctx, user.AccountId)
			util.WriteJSONObject(ctx, w, service)
			return
		}
		if mux.CurrentRoute(r).GetName() == "estavelle-admission-targets" {
			scoped, ok := store.(interface {
				AdmissionTargets(context.Context) ([]estavelleservice.AdmissionLease, error)
			})
			if !ok {
				util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "Estavelle admission capability unavailable"), w)
				return
			}
			targets, err := scoped.AdmissionTargets(ctx)
			if err != nil {
				estavelleServiceError(w, r, err)
				return
			}
			util.WriteJSONObject(ctx, w, targets)
			return
		}
		if mux.CurrentRoute(r).GetName() == "estavelle-modes" {
			if r.Method == http.MethodOptions {
				return
			}
			modes, ok := store.(estavelleServiceModes)
			if !ok {
				util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "Estavelle mode storage unavailable"), w)
				return
			}
			var request struct {
				PonorEnabled *bool `json:"ponor_enabled"`
				Acknowledge  bool  `json:"acknowledge_connectivity_change"`
			}
			decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&request); err != nil {
				util.WriteErrorResponse("invalid Estavelle mode request", http.StatusBadRequest, w)
				return
			}
			if err := decoder.Decode(new(any)); err != io.EOF {
				util.WriteErrorResponse("expected one Estavelle mode request", http.StatusBadRequest, w)
				return
			}
			if request.PonorEnabled == nil || !request.Acknowledge {
				util.WriteErrorResponse("both the mode state and acknowledge_connectivity_change are required", http.StatusBadRequest, w)
				return
			}
			service, err := modes.SetModes(ctx, mux.Vars(r)["serviceId"], *request.PonorEnabled)
			if err != nil {
				estavelleServiceError(w, r, err)
				return
			}
			push(ctx, user.AccountId)
			util.WriteJSONObject(ctx, w, service)
			return
		}
		if mux.CurrentRoute(r).GetName() == "estavelle-publication" || mux.CurrentRoute(r).GetName() == "estavelle-publication-preview" {
			publisher, ok := store.(estavelleServicePublisher)
			if !ok {
				util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "Estavelle publication storage unavailable"), w)
				return
			}
			if r.Method == http.MethodOptions {
				return
			}
			if r.Method == http.MethodGet {
				value, err := publisher.Publication(ctx)
				if err != nil {
					estavelleServiceError(w, r, err)
					return
				}
				util.WriteJSONObject(ctx, w, value)
				return
			}
			if mux.CurrentRoute(r).GetName() == "estavelle-publication-preview" {
				services, err := publisher.Preview(ctx)
				if err != nil {
					estavelleServiceError(w, r, err)
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
			value, err := publisher.SetPublication(ctx, request.Mode)
			if err != nil {
				estavelleServiceError(w, r, err)
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
				estavelleServiceError(w, r, err)
				return
			}
			util.WriteJSONObject(ctx, w, views)
		case http.MethodPost:
			var service estavelleservice.Service
			decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&service); err != nil {
				util.WriteErrorResponse("invalid Estavelle service JSON", http.StatusBadRequest, w)
				return
			}
			if err := decoder.Decode(new(any)); err != io.EOF {
				util.WriteErrorResponse("expected exactly one Estavelle service object", http.StatusBadRequest, w)
				return
			}
			created, err := store.Create(ctx, service)
			if err != nil {
				estavelleServiceError(w, r, err)
				return
			}
			push(ctx, user.AccountId)
			w.Header().Set("Content-Type", "application/json; charset=UTF-8")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(created)
		case http.MethodDelete:
			if err := store.Delete(ctx, mux.Vars(r)["serviceId"]); err != nil {
				estavelleServiceError(w, r, err)
				return
			}
			push(ctx, user.AccountId)
			w.WriteHeader(http.StatusNoContent)
		}
	}
	routes.HandleFunc("/admission-targets", handle).Methods(http.MethodGet).Name("estavelle-admission-targets")
	routes.HandleFunc("", handle).Methods(http.MethodGet, http.MethodPost, http.MethodOptions)
	routes.HandleFunc("/publication", handle).Methods(http.MethodGet, http.MethodPut, http.MethodOptions).Name("estavelle-publication")
	routes.HandleFunc("/publication/preview", handle).Methods(http.MethodPost, http.MethodOptions).Name("estavelle-publication-preview")
	routes.HandleFunc("/{serviceId}/access", handle).Methods(http.MethodPut).Name("estavelle-access")
	routes.HandleFunc("/{serviceId}/modes", handle).Methods(http.MethodPut, http.MethodOptions).Name("estavelle-modes")
	routes.HandleFunc("/{serviceId}", handle).Methods(http.MethodDelete, http.MethodOptions)
}

func estavelleServiceError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, estavelleservice.ErrInvalid):
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "%s", err), w)
	case errors.Is(err, estavelleservice.ErrExists), errors.Is(err, policy.ErrVersionConflict):
		util.WriteError(r.Context(), status.Errorf(status.AlreadyExists, "Estavelle service already exists"), w)
	case errors.Is(err, estavelleservice.ErrNotFound):
		util.WriteError(r.Context(), status.Errorf(status.NotFound, "Estavelle service not found"), w)
	case errors.Is(err, estavelleservice.ErrNoAccount):
		util.WriteError(r.Context(), status.Errorf(status.PermissionDenied, "account scope required"), w)
	default:
		util.WriteError(r.Context(), status.Errorf(status.Internal, "Estavelle service storage failed"), w)
	}
}
