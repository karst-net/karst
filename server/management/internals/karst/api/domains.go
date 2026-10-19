// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

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
	NamingRevision uint64 `json:"naming_revision"`
	IsRoot         bool   `json:"is_root"`
	DNSSuffix      string `json:"dns_suffix,omitempty"`
	DNSName        string `json:"dns_name,omitempty"`
	ID             string `json:"id"`
	ParentID       string `json:"parent_id,omitempty"`
	Label          string `json:"label"`
	Path           string `json:"path"`
}

func domainView(d *meshdomain.Domain) domainResponse {
	return domainResponse{NamingRevision: d.NamingRevision, IsRoot: d.IsRoot(), DNSSuffix: d.DNSSuffix, ID: d.ID, ParentID: d.ParentID, Label: d.Label, Path: d.Path}
}

// domainViews projects complete names only after the domain manager has
// authorized and filtered the tree. A delegated subtree can be named without
// returning the root or any sibling outside that caller's administrative scope.
func (h *handler) domainViews(ctx context.Context, accountID string, domains []*meshdomain.Domain) ([]domainResponse, error) {
	suffix := ""
	var root *meshdomain.Domain
	if source, ok := h.peers.(interface {
		GetAccountRootDomain(context.Context, string) (*meshdomain.Domain, error)
	}); ok {
		var err error
		root, err = source.GetAccountRootDomain(ctx, accountID)
		if err != nil {
			return nil, err
		}
	}
	if root != nil {
		suffix = root.DNSSuffix
	} else if source, ok := h.peers.(interface {
		GetDNSDomain(context.Context, string) (string, error)
	}); ok {
		var err error
		suffix, err = source.GetDNSDomain(ctx, accountID)
		if err != nil {
			return nil, err
		}
	} else {
		for _, d := range domains {
			if d.IsRoot() {
				suffix = d.DNSSuffix
				break
			}
		}
	}
	result := make([]domainResponse, 0, len(domains))
	for _, d := range domains {
		view := domainView(d)
		if root != nil && d.ID == root.ID {
			view.DNSSuffix = root.DNSSuffix
			view.NamingRevision = root.NamingRevision
		}
		if suffix != "" {
			view.DNSName = suffix
			if d.Path != "" {
				view.DNSName = d.Path + "." + suffix
			}
		}
		result = append(result, view)
	}
	return result, nil
}

type rootRenameManager interface {
	PreviewRootRename(context.Context, string, string, string) (*meshdomain.RenamePreview, error)
	CommitRootRename(context.Context, string, string, string, string) (*meshdomain.RenamePreview, error)
}

func (h *handler) rootRename(w http.ResponseWriter, r *http.Request) {
	user, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	mgr, ok := h.domainMgr.(rootRenameManager)
	if !ok {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "root rename is not configured"), w)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	var request struct {
		Suffix   string `json:"dns_suffix"`
		Revision string `json:"revision"`
		Confirm  bool   `json:"confirm_no_aliases"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid root rename request"), w)
		return
	}
	var result *meshdomain.RenamePreview
	if strings.HasSuffix(r.URL.Path, "/preview") {
		result, err = mgr.PreviewRootRename(r.Context(), user.AccountId, user.UserId, request.Suffix)
	} else {
		if !request.Confirm || request.Revision == "" {
			util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "confirm the preview and that old DNS names will stop resolving"), w)
			return
		}
		result, err = mgr.CommitRootRename(r.Context(), user.AccountId, user.UserId, request.Suffix, request.Revision)
	}
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, result)
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
		result, err := h.domainViews(r.Context(), user.AccountId, list)
		if err != nil {
			util.WriteError(r.Context(), err, w)
			return
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
	views, err := h.domainViews(r.Context(), user.AccountId, []*meshdomain.Domain{d})
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, views[0])
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
	views, err := h.domainViews(r.Context(), user.AccountId, []*meshdomain.Domain{d})
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, views[0])
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
