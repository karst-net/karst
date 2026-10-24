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
	// The trailing (assignedUserID string, reusable bool, usageLimit int)
	// are the only addition over a plain one-off device invitation: a
	// reusable invitation (CI/fleet enrollment) keeps assigning the same
	// owner to every device that redeems it, since nothing here ever
	// revokes the EnrollmentOwner binding -- see invitationAssigneeStore.
	CreateDeviceInvitation(context.Context, string, string, string, []string, string, string, bool, int) (*types.SetupKey, error)
	// ListDeviceInvitations and RevokeDeviceInvitation are deliberately not
	// ListSetupKeys/GetSetupKey/SaveSetupKey: this route is exempt from the
	// blanket KarstControl gate (see karstAuthorization) so a mesh-domain
	// delegated admin (ADR-0032) can reach it with no account-wide grant,
	// and the generic setup-key methods only ever check one.
	ListDeviceInvitations(context.Context, string, string) ([]*types.SetupKey, error)
	RevokeDeviceInvitation(context.Context, string, string, string) (*types.SetupKey, error)
}

// invitationAssigneeStore is the Karst-owned side table recording which
// account member an invitation is for -- see package node's
// InvitationAssignee (display, keyed by invitation ID) and EnrollmentOwner
// (the mechanism that actually sets the resulting peer's owner at
// redemption, keyed by the credential's own hash). Both live on the same
// *node.Store already wired in as h.nodes elsewhere in this package; this is
// a second, narrower view over it for the write side invitations need.
type invitationAssigneeStore interface {
	SetInvitationAssignee(keyID, userID string) error
	InvitationAssignees(keyIDs []string) (map[string]string, error)
	DeleteInvitationAssignee(keyID string) error
	BindEnrollmentKey(key, userID string, reusable ...bool) error
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
	// DomainID is the mesh domain (ADR-0032) the enrolling device will be
	// placed in, or "" for the account's implicit root.
	DomainID string `json:"domain_id,omitempty"`
	// AssignedUserID is who this invitation is for -- resolved from the
	// Karst-owned invitationAssigneeStore, not a field on the SetupKey
	// itself (ADR-0009).
	AssignedUserID string `json:"assigned_user_id,omitempty"`
	Reusable       bool   `json:"reusable,omitempty"`
	UsageLimit     int    `json:"usage_limit,omitempty"`
	UsedTimes      int    `json:"used_times,omitempty"`
}

func invitationView(key *types.SetupKey) invitationResponse {
	// A reusable invitation keeps accepting redemptions up to its usage
	// limit (0 = unlimited) -- "redeemed" only once it's exhausted, not on
	// its first use, unlike a one-off invitation which is terminal after one.
	exhausted := key.UsedTimes > 0
	if key.Type == types.SetupKeyReusable {
		exhausted = key.UsageLimit > 0 && key.UsedTimes >= key.UsageLimit
	}
	state := "pending"
	switch {
	case exhausted:
		state = "redeemed"
	case key.Revoked:
		state = "revoked"
	case key.IsExpired():
		state = "expired"
	}
	return invitationResponse{
		ID: key.Id, Name: key.Name, Groups: key.AutoGroups, State: state, ExpiresAt: key.GetExpiresAt(), CreatedAt: key.CreatedAt, RedeemedAt: key.LastUsed, DomainID: key.DomainID,
		Reusable: key.Type == types.SetupKeyReusable, UsageLimit: key.UsageLimit, UsedTimes: key.UsedTimes,
	}
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
		keys, err := manager.ListDeviceInvitations(r.Context(), user.AccountId, user.UserId)
		if err != nil {
			util.WriteError(r.Context(), err, w)
			return
		}
		result := make([]invitationResponse, 0, len(keys))
		ids := make([]string, 0, len(keys))
		for _, key := range keys {
			result = append(result, invitationView(key))
			ids = append(ids, key.Id)
		}
		// Best-effort: a failure to resolve assignees should not block
		// listing invitations, it just leaves assigned_user_id blank.
		if h.invitationAssignees != nil {
			if assignees, err := h.invitationAssignees.InvitationAssignees(ids); err == nil {
				for i := range result {
					result[i].AssignedUserID = assignees[result[i].ID]
				}
			}
		}
		util.WriteJSONObject(r.Context(), w, result)
		return
	}
	var request struct {
		Name       string   `json:"name"`
		Groups     []string `json:"groups"`
		DomainID   string   `json:"domain_id"`
		ForUserID  string   `json:"for_user_id"`
		Reusable   bool     `json:"reusable"`
		UsageLimit int      `json:"usage_limit"`
	}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid invitation request"), w)
		return
	}
	if request.ForUserID == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "an invitation must be assigned to a user"), w)
		return
	}
	key, err := manager.CreateDeviceInvitation(r.Context(), user.AccountId, user.UserId, request.Name, request.Groups, request.DomainID, request.ForUserID, request.Reusable, request.UsageLimit)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if h.invitationAssignees != nil {
		// Both calls are on the critical path for the feature this
		// invitation exists to provide (a displayed assignee, and the
		// resulting device actually owned by that user at redemption) --
		// surfacing a failure here, rather than silently degrading, is
		// what lets the admin retry instead of filing a confusing bug
		// report about a device that enrolled ownerless.
		if err := h.invitationAssignees.SetInvitationAssignee(key.Id, request.ForUserID); err != nil {
			util.WriteError(r.Context(), err, w)
			return
		}
		if err := h.invitationAssignees.BindEnrollmentKey(key.Key, request.ForUserID, request.Reusable); err != nil {
			util.WriteError(r.Context(), err, w)
			return
		}
	}
	result := invitationView(key)
	result.Credential = key.Key
	result.AssignedUserID = request.ForUserID
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
	id := mux.Vars(r)["id"]
	key, err := manager.RevokeDeviceInvitation(r.Context(), user.AccountId, user.UserId, id)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	// Cleanup only, after the revoke itself already succeeded -- a failure
	// here leaves a harmless orphaned display row, not a half-revoked
	// invitation, so it does not fail the request.
	if h.invitationAssignees != nil {
		_ = h.invitationAssignees.DeleteInvitationAssignee(id)
	}
	w.Header().Set("Cache-Control", "no-store")
	util.WriteJSONObject(r.Context(), w, invitationView(key))
}
