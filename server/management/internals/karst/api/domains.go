// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package api

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/management/internals/modules/meshdomain"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

// domainManager is meshdomain/manager.Manager, kept as a narrow local
// interface the same way peerWriter/invitationManager are -- this package
// depends on behavior, not on the concrete manager package.
type domainManager interface {
	CreateDomain(ctx context.Context, accountID, userID, parentID, label string) (*meshdomain.Domain, error)
	ListDomains(ctx context.Context, accountID, userID string) ([]*meshdomain.Domain, error)
	GetDomain(ctx context.Context, accountID, userID, domainID string) (*meshdomain.Domain, error)
	DeleteDomain(ctx context.Context, accountID, userID, domainID string) error
	DelegateDomainAdmin(ctx context.Context, accountID, userID, domainID, targetUserID string) (*meshdomain.DomainRoleBinding, error)
	RevokeDomainDelegation(ctx context.Context, accountID, userID, bindingID string) error
	ListDelegations(ctx context.Context, accountID, userID, domainID string) ([]*meshdomain.DomainRoleBinding, error)
}

type domainResponse struct {
	ID       string `json:"id"`
	ParentID string `json:"parent_id,omitempty"`
	Label    string `json:"label"`
	Path     string `json:"path"`
}

func domainView(d *meshdomain.Domain) domainResponse {
	return domainResponse{ID: d.ID, ParentID: d.ParentID, Label: d.Label, Path: d.Path}
}

type delegationResponse struct {
	ID         string `json:"id"`
	DomainID   string `json:"domain_id"`
	DomainPath string `json:"domain_path"`
	UserID     string `json:"user_id"`
}

func delegationView(b *meshdomain.DomainRoleBinding) delegationResponse {
	return delegationResponse{ID: b.ID, DomainID: b.DomainID, DomainPath: b.DomainPath, UserID: b.UserID}
}

func (h *handler) domains(w http.ResponseWriter, r *http.Request) {
	user, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if h.domainMgr == nil {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "mesh domains are not configured"), w)
		return
	}
	mgr := h.domainMgr
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodGet {
		list, err := mgr.ListDomains(r.Context(), user.AccountId, user.UserId)
		if err != nil {
			util.WriteError(r.Context(), err, w)
			return
		}
		result := make([]domainResponse, 0, len(list))
		for _, d := range list {
			result = append(result, domainView(d))
		}
		util.WriteJSONObject(r.Context(), w, result)
		return
	}
	var request struct {
		ParentID string `json:"parent_id"`
		Label    string `json:"label"`
	}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid domain request"), w)
		return
	}
	d, err := mgr.CreateDomain(r.Context(), user.AccountId, user.UserId, request.ParentID, request.Label)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, domainView(d))
}

func (h *handler) getDomain(w http.ResponseWriter, r *http.Request) {
	user, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if h.domainMgr == nil {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "mesh domains are not configured"), w)
		return
	}
	mgr := h.domainMgr
	d, err := mgr.GetDomain(r.Context(), user.AccountId, user.UserId, mux.Vars(r)["id"])
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, domainView(d))
}

func (h *handler) deleteDomain(w http.ResponseWriter, r *http.Request) {
	user, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if h.domainMgr == nil {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "mesh domains are not configured"), w)
		return
	}
	mgr := h.domainMgr
	if err := mgr.DeleteDomain(r.Context(), user.AccountId, user.UserId, mux.Vars(r)["id"]); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) domainDelegations(w http.ResponseWriter, r *http.Request) {
	user, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if h.domainMgr == nil {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "mesh domains are not configured"), w)
		return
	}
	mgr := h.domainMgr
	domainID := mux.Vars(r)["id"]
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodGet {
		list, err := mgr.ListDelegations(r.Context(), user.AccountId, user.UserId, domainID)
		if err != nil {
			util.WriteError(r.Context(), err, w)
			return
		}
		result := make([]delegationResponse, 0, len(list))
		for _, b := range list {
			result = append(result, delegationView(b))
		}
		util.WriteJSONObject(r.Context(), w, result)
		return
	}
	var request struct {
		UserID string `json:"user_id"`
	}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid delegation request"), w)
		return
	}
	binding, err := mgr.DelegateDomainAdmin(r.Context(), user.AccountId, user.UserId, domainID, request.UserID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, delegationView(binding))
}

func (h *handler) revokeDomainDelegation(w http.ResponseWriter, r *http.Request) {
	user, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if h.domainMgr == nil {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "mesh domains are not configured"), w)
		return
	}
	mgr := h.domainMgr
	if err := mgr.RevokeDomainDelegation(r.Context(), user.AccountId, user.UserId, mux.Vars(r)["bindingId"]); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
