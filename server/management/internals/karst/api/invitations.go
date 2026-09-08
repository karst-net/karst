// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

type invitationManager interface {
	CreateDeviceInvitation(context.Context, string, string, string, []string) (*types.SetupKey, error)
	ListSetupKeys(context.Context, string, string) ([]*types.SetupKey, error)
	GetSetupKey(context.Context, string, string, string) (*types.SetupKey, error)
	SaveSetupKey(context.Context, string, *types.SetupKey, string) (*types.SetupKey, error)
}

type invitationResponse struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Groups     []string   `json:"groups"`
	State      string     `json:"state"`
	ExpiresAt  time.Time  `json:"expires_at"`
	CreatedAt  time.Time  `json:"created_at"`
	RedeemedAt *time.Time `json:"redeemed_at,omitempty"`
	Credential string     `json:"credential,omitempty"`
}

func invitationView(key *types.SetupKey) invitationResponse {
	state := "pending"
	switch {
	case key.UsedTimes > 0:
		state = "redeemed"
	case key.Revoked:
		state = "revoked"
	case key.IsExpired():
		state = "expired"
	}
	return invitationResponse{ID: key.Id, Name: key.Name, Groups: key.AutoGroups, State: state, ExpiresAt: key.GetExpiresAt(), CreatedAt: key.CreatedAt, RedeemedAt: key.LastUsed}
}

func (h *handler) invitations(w http.ResponseWriter, r *http.Request) {
	user, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	manager, ok := h.peerWriter.(invitationManager)
	if !ok {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "device invitations are not configured"), w)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodGet {
		keys, err := manager.ListSetupKeys(r.Context(), user.AccountId, user.UserId)
		if err != nil {
			util.WriteError(r.Context(), err, w)
			return
		}
		result := make([]invitationResponse, 0)
		for _, key := range keys {
			if key.InvitationIssuerID != "" {
				result = append(result, invitationView(key))
			}
		}
		util.WriteJSONObject(r.Context(), w, result)
		return
	}
	var request struct {
		Name   string   `json:"name"`
		Groups []string `json:"groups"`
	}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid invitation request"), w)
		return
	}
	key, err := manager.CreateDeviceInvitation(r.Context(), user.AccountId, user.UserId, request.Name, request.Groups)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	result := invitationView(key)
	result.Credential = key.Key
	util.WriteJSONObject(r.Context(), w, result)
}

func (h *handler) revokeInvitation(w http.ResponseWriter, r *http.Request) {
	user, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	manager, ok := h.peerWriter.(invitationManager)
	if !ok {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "device invitations are not configured"), w)
		return
	}
	key, err := manager.GetSetupKey(r.Context(), user.AccountId, user.UserId, mux.Vars(r)["id"])
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if key.InvitationIssuerID == "" {
		util.WriteError(r.Context(), status.Errorf(status.NotFound, "invitation not found"), w)
		return
	}
	key.Revoked = true
	key, err = manager.SaveSetupKey(r.Context(), user.AccountId, key, user.UserId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	util.WriteJSONObject(r.Context(), w, invitationView(key))
}
