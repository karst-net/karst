// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package api

import (
	"context"
	"net/http"
	"testing"

	"github.com/gorilla/mux"
	"github.com/netbirdio/netbird/management/internals/karst/relayservice"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/stretchr/testify/require"
)

type publicationStub struct {
	serviceStub
	mode     string
	previews int
	setCalls int
}

func (s *publicationStub) SetModes(_ context.Context, id string, ponor bool) (*relayservice.Service, error) {
	s.setCalls++
	return &relayservice.Service{ID: id, PonorID: "p", PonorDisabled: !ponor}, s.err
}

func TestRelayModesRequireCompleteAcknowledgedStateAndPushOnlyAfterSuccess(t *testing.T) {
	store := &publicationStub{mode: "legacy"}
	push := &publicationPush{}
	router := mux.NewRouter()
	RegisterRelayServiceEndpoints(router, scanPermissions{role: types.UserRoleAdmin}, store, RelayServiceOptions{Accounts: push})
	for _, body := range []string{
		`{"acknowledge_connectivity_change":true}`,
		`{"ponor_enabled":true}`,
		`{"ponor_enabled":true,"acknowledge_connectivity_change":true} {}`,
	} {
		w := serviceRequest(router, http.MethodPut, "/one/modes", body, true)
		require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	}
	require.Zero(t, store.setCalls)
	w := serviceRequest(router, http.MethodPut, "/one/modes", `{"ponor_enabled":false,"acknowledge_connectivity_change":true}`, true)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), `"ponor_disabled":true`)
	require.Equal(t, []string{"a"}, push.accounts)
	store.err = relayservice.ErrNotFound
	w = serviceRequest(router, http.MethodPut, "/other/modes", `{"ponor_enabled":true,"acknowledge_connectivity_change":true}`, true)
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
	require.Equal(t, []string{"a"}, push.accounts)
	for _, role := range []types.UserRole{types.UserRoleUser, types.UserRoleScaler} {
		router := mux.NewRouter()
		RegisterRelayServiceEndpoints(router, scanPermissions{role: role}, store)
		w := serviceRequest(router, http.MethodPut, "/one/modes", `{"ponor_enabled":false,"acknowledge_connectivity_change":true}`, true)
		require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	}
}

func (s *publicationStub) Publication(context.Context) (relayservice.Publication, error) {
	return relayservice.Publication{Mode: s.mode}, s.err
}
func (s *publicationStub) Preview(context.Context) ([]relayservice.Service, error) {
	s.previews++
	return []relayservice.Service{{ID: "one", PonorID: "p"}}, s.err
}
func (s *publicationStub) SetPublication(_ context.Context, mode string) (relayservice.Publication, error) {
	s.setCalls++
	if s.err == nil {
		s.mode = mode
	}
	return relayservice.Publication{Mode: mode}, s.err
}

type publicationPush struct{ accounts []string }

func (p *publicationPush) UpdateAccountPeers(_ context.Context, account string, reason types.UpdateReason) {
	p.accounts = append(p.accounts, account)
}

func TestRelayPublicationPreviewAndAcknowledgedApplyNotifyOnlyAfterSuccess(t *testing.T) {
	store := &publicationStub{mode: "legacy"}
	push := &publicationPush{}
	router := mux.NewRouter()
	RegisterRelayServiceEndpoints(router, scanPermissions{role: types.UserRoleAdmin}, store, RelayServiceOptions{Accounts: push})
	w := serviceRequest(router, http.MethodGet, "/publication", "", true)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.JSONEq(t, `{"mode":"legacy"}`, w.Body.String())
	w = serviceRequest(router, http.MethodPost, "/publication/preview", "", true)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Equal(t, 1, store.previews)
	require.Zero(t, store.setCalls)
	require.Empty(t, push.accounts)
	for _, body := range []string{`{"mode":"services"}`, `{"mode":"services","acknowledge_connectivity_change":false}`, `{"mode":"services","acknowledge_connectivity_change":true} {}`} {
		w = serviceRequest(router, http.MethodPut, "/publication", body, true)
		require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	}
	require.Zero(t, store.setCalls)
	w = serviceRequest(router, http.MethodPut, "/publication", `{"mode":"services","acknowledge_connectivity_change":true}`, true)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Equal(t, "services", store.mode)
	require.Equal(t, []string{"a"}, push.accounts)
	store.err = relayservice.ErrInvalid
	w = serviceRequest(router, http.MethodPut, "/publication", `{"mode":"legacy","acknowledge_connectivity_change":true}`, true)
	require.Equal(t, http.StatusUnprocessableEntity, w.Code)
	require.Equal(t, []string{"a"}, push.accounts)
}

func TestRelayPublicationIsUnavailableToMembersAndScalers(t *testing.T) {
	for _, role := range []types.UserRole{types.UserRoleUser, types.UserRoleScaler} {
		store := &publicationStub{mode: "legacy"}
		router := mux.NewRouter()
		RegisterRelayServiceEndpoints(router, scanPermissions{role: role}, store)
		for _, tc := range []struct{ method, path, body string }{
			{http.MethodGet, "/publication", ""},
			{http.MethodPost, "/publication/preview", ""},
			{http.MethodPut, "/publication", `{"mode":"services","acknowledge_connectivity_change":true}`},
		} {
			w := serviceRequest(router, tc.method, tc.path, tc.body, true)
			require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
		}
		require.Zero(t, store.setCalls)
		require.Zero(t, store.previews)
	}
}
