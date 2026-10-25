// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package groups

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/mock_server"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/auth"
	"github.com/netbirdio/netbird/shared/management/status"
	"github.com/stretchr/testify/require"
)

func TestGroupHTTPRevision(t *testing.T) {
	group := &types.Group{AccountID: "account", ID: "id-test", Name: "Test", Issued: types.GroupIssuedAPI}
	h := initGroupTestData(group)
	request := func(method, header string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "/groups/id-test", strings.NewReader(`{"name":"Edited","peers":[]}`))
		req = mux.SetURLVars(req, map[string]string{"groupId": "id-test"})
		req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{AccountId: "account", UserId: "admin"})
		if header != "" {
			req.Header.Set("If-Match", header)
		}
		recorder := httptest.NewRecorder()
		if method == http.MethodGet {
			h.getGroup(recorder, req)
		} else {
			h.updateGroup(recorder, req)
		}
		return recorder
	}
	get := request(http.MethodGet, "")
	require.Equal(t, http.StatusOK, get.Code)
	revision := get.Header().Get("ETag")
	require.Equal(t, types.GroupRevision(group), revision)
	require.Equal(t, "no-store", get.Header().Get("Cache-Control"))
	manager := h.accountManager.(*mock_server.MockAccountManager)
	calls := 0
	manager.UpdateGroupFunc = func(ctx context.Context, _, _ string, _ *types.Group) error {
		calls++
		require.Equal(t, revision, types.ExpectedGroupRevision(ctx))
		return status.Errorf(status.PreconditionFailed, "group changed")
	}
	for _, invalid := range []string{"*", "W/" + revision, "garbage"} {
		require.Equal(t, http.StatusBadRequest, request(http.MethodPut, invalid).Code)
	}
	require.Zero(t, calls)
	put := request(http.MethodPut, revision)
	require.Equal(t, http.StatusPreconditionFailed, put.Code, put.Body.String())
	require.Equal(t, 1, calls)
}
