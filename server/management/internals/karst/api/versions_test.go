// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package api

import (
	"encoding/json"
	"github.com/netbirdio/netbird/management/internals/karst/buildinfo"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/shared/auth"
	"github.com/stretchr/testify/require"
)

func TestSoftwareVersionsRolesAndSnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "versions.json")
	t.Setenv("KARST_COMPONENT_VERSIONS_FILE", path)
	require.NoError(t, os.WriteFile(path, []byte(`{"observed_at":"2026-10-20T12:00:00Z","components":[{"name":"relay","image":"relay:v1","image_id":"sha256:abc","tags":["relay:v1"],"state":"running","version":"v0.1.0-rc.31","revision":"observed-commit","secret":"never expose"}]}`), 0600))
	for _, role := range []string{"owner", "admin", "network_admin", "auditor", "noc", "user", ""} {
		t.Run(role, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/karst/v1/versions", nil)
			request = nbcontext.SetUserAuthInRequest(request, auth.UserAuth{AccountId: "account", UserId: "viewer"})
			request = request.WithContext(nbcontext.WithRole(request.Context(), role))
			response := httptest.NewRecorder()
			(&handler{}).versions(response, request)
			if role == "owner" || role == "admin" {
				require.Equal(t, http.StatusOK, response.Code)
				require.Contains(t, response.Body.String(), `"deployment_status":"available"`)
				require.Contains(t, response.Body.String(), `"image_id":"sha256:abc"`)
				require.Contains(t, response.Body.String(), `"version":"v0.1.0-rc.31"`)
				require.Contains(t, response.Body.String(), `"revision":"observed-commit"`)
				require.NotContains(t, response.Body.String(), "never expose")
				require.Equal(t, "no-store", response.Header().Get("Cache-Control"))
				var payload versionsResponse
				require.NoError(t, json.Unmarshal(response.Body.Bytes(), &payload))
				require.Equal(t, buildinfo.Current().ArtifactID, payload.Control.ArtifactID)
			} else {
				require.Equal(t, http.StatusForbidden, response.Code)
			}
		})
	}
}

func TestSoftwareVersionsMissingAndMalformedSnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "versions.json")
	for _, content := range []string{"", "{", `{}`, `{"components":[]}`} {
		require.NoError(t, os.WriteFile(path, []byte(content), 0600))
		t.Setenv("KARST_COMPONENT_VERSIONS_FILE", path)
		request := nbcontext.SetUserAuthInRequest(httptest.NewRequest(http.MethodGet, "/", nil), auth.UserAuth{AccountId: "a", UserId: "u"})
		request = request.WithContext(nbcontext.WithRole(request.Context(), "admin"))
		response := httptest.NewRecorder()
		(&handler{}).versions(response, request)
		require.Equal(t, http.StatusOK, response.Code)
		require.Contains(t, response.Body.String(), `"deployment_status":"unavailable"`)
		require.NotContains(t, response.Body.String(), `"deployment":`)
	}
	response := httptest.NewRecorder()
	(&handler{}).versions(response, httptest.NewRequest(http.MethodGet, "/", nil))
	require.NotEqual(t, http.StatusOK, response.Code)
}
