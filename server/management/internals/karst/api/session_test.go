// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/karst/node"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/auth"
)

// sessionNodes is fakeNodes plus a session table, so the portal's history can
// be driven end to end through the router.
type sessionNodes struct {
	fakeNodes
	sessions []node.DeviceSession
	closed   []string
}

func (s *sessionNodes) SessionsForHandles(handles []string, _ int) ([]node.DeviceSession, error) {
	allowed := make(map[string]struct{}, len(handles))
	for _, handle := range handles {
		allowed[handle] = struct{}{}
	}
	var out []node.DeviceSession
	for _, session := range s.sessions {
		if _, ok := allowed[session.Handle]; ok {
			out = append(out, session)
		}
	}
	return out, nil
}

func (s *sessionNodes) CloseSessionsForHandle(handle string, _ time.Time) error {
	s.closed = append(s.closed, handle)
	return nil
}

// The gap plans/phase-5/05-user-portal.md §1 names: the endpoint used to
// return audit rows with a null end time and a null address for every one.
func TestMemberSessionHistoryCarriesRealEndTimesAndAddresses(t *testing.T) {
	ended := time.Date(2026, 8, 20, 10, 30, 0, 0, time.UTC)
	nodes := &sessionNodes{
		fakeNodes: fakeNodes{"handle-a": {Handle: "handle-a"}, "handle-b": {Handle: "handle-b"}},
		sessions: []node.DeviceSession{
			{Handle: "handle-a", ClientAddr: "203.0.113.7", StartedAt: ended.Add(-time.Hour), EndedAt: &ended},
			{Handle: "handle-a", ClientAddr: "203.0.113.9", StartedAt: ended.Add(time.Hour)},
			{Handle: "handle-b", ClientAddr: "198.51.100.4", StartedAt: ended, EndedAt: &ended},
		},
	}
	devices := fakePeers{
		{ID: "mine", Key: "handle-a", Name: "my laptop", UserID: "user-a"},
		{ID: "theirs", Key: "handle-b", Name: "their laptop", UserID: "user-b"},
	}
	owned := fakeOwnDevices{peers: devices}
	router := mux.NewRouter()
	RegisterEndpoints(nodes, owned, owned, nil, nil, nil, nil, nil, nil, scanPermissions{role: types.UserRoleUser}, router)

	req := httptest.NewRequest(http.MethodGet, "/karst/v1/me/sessions", nil)
	req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{AccountId: "account-a", UserId: "user-a"})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, req)
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())

	var items []map[string]any
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &items))

	// Only this subject's devices. handle-b belongs to user-b and the caller
	// never named a handle at all, so there is no parameter to forge.
	require.Len(t, items, 2, "a member saw another user's sessions: %s", response.Body.String())

	// The device is named the way its owner named it, not by its handle.
	require.Equal(t, "my laptop", items[0]["device"])
	require.Equal(t, "203.0.113.7", items[0]["ip"], "the address is still null")
	require.NotNil(t, items[0]["ended_at"], "a finished session still reports no end time")

	// A live session is the one case where a null end is the right answer.
	require.Nil(t, items[1]["ended_at"], "a live session was given an end time")
	require.Equal(t, "203.0.113.9", items[1]["ip"])
}

// Revocation has to close the row while the handle is still known to be this
// subject's, or a stolen laptop stays listed as connected.
func TestRevokingADeviceClosesItsSessionsThroughTheAPI(t *testing.T) {
	nodes := &sessionNodes{fakeNodes: fakeNodes{"handle-a": {Handle: "handle-a"}}}
	devices := fakePeers{{ID: "mine", Key: "handle-a", Name: "my laptop", UserID: "user-a"}}
	owned := fakeOwnDevices{peers: devices}
	router := mux.NewRouter()
	RegisterEndpoints(nodes, owned, owned, nil, nil, nil, nil, nil, nil, scanPermissions{role: types.UserRoleUser}, router)

	req := httptest.NewRequest(http.MethodDelete, "/karst/v1/me/devices/handle-a", nil)
	req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{AccountId: "account-a", UserId: "user-a"})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, req)
	require.Equal(t, http.StatusNoContent, response.Code, response.Body.String())
	require.Equal(t, []string{"handle-a"}, nodes.closed, "revocation left the device's sessions open")
}
