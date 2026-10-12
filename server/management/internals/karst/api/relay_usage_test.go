// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/karst/audit"
	"github.com/netbirdio/netbird/management/internals/karst/relayusage"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/auth"
)

type relayUsageReportStub struct {
	account string
	calls   int
}

type relayUsageAuditCapture struct {
	scanAudit
	userID string
	action string
}

func (a *relayUsageAuditCapture) Append(_ context.Context, userID, action, _, _ string) (*audit.Entry, error) {
	a.userID, a.action = userID, action
	return &audit.Entry{}, nil
}

func (s *relayUsageReportStub) Report(_ context.Context, account string, start, end time.Time) (relayusage.Report, error) {
	s.account, s.calls = account, s.calls+1
	return relayusage.Report{Start: start, End: end, AsOf: end, Coverage: "received_only", Complete: false,
		ReportedBytes: "123", MissingSequences: "0", Days: []relayusage.ReportDay{{Date: "2026-10-01", ReportedBytes: "123", ReportedWindows: 1, GapReasons: []string{}}},
		Limitations: []string{"producer coverage is not historized"}}, nil
}

const relayUsageReportURL = "/karst/v1/usage/relays?start=2026-10-01T00:00:00Z&end=2026-10-02T00:00:00Z"

func TestRelayUsageReportIsAccountScopedAndAudited(t *testing.T) {
	for _, role := range []types.UserRole{types.UserRoleOwner, types.UserRoleAdmin, types.UserRoleUser} {
		t.Run(string(role), func(t *testing.T) {
			reporter := &relayUsageReportStub{}
			auditLog := &relayUsageAuditCapture{}
			router := mux.NewRouter()
			RegisterRelayUsageEndpoints(router, scanPermissions{role: role}, reporter, auditLog)
			req := httptest.NewRequest(http.MethodGet, relayUsageReportURL+"&account=other", nil)
			req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{AccountId: "account-1", UserId: "viewer"})
			response := httptest.NewRecorder()
			router.ServeHTTP(response, req)
			require.Equal(t, "no-store", response.Header().Get("Cache-Control"))
			if role == types.UserRoleOwner || role == types.UserRoleAdmin {
				require.Equal(t, http.StatusOK, response.Code, response.Body.String())
				require.Equal(t, "account-1", reporter.account)
				require.Equal(t, "viewer", auditLog.userID)
				require.Equal(t, "karst.usage.relays.view", auditLog.action)
				require.NotContains(t, response.Body.String(), "other")
				var body map[string]any
				require.NoError(t, json.Unmarshal(response.Body.Bytes(), &body))
				spec := loadKarstOpenAPISchemas(t)
				assertDeclaredResponseFields(t, spec, responseSchema(spec, "/usage/relays", "GET", "200"), body, "relay usage report")
			} else {
				require.Equal(t, http.StatusForbidden, response.Code)
				require.Zero(t, reporter.calls)
			}
		})
	}
}

func TestRelayUsageReportRejectsInvalidQueryAndRequiresAudit(t *testing.T) {
	for _, query := range []string{"", "?start=not-a-date&end=2026-10-02T00:00:00Z", "?start=2026-10-01T00:00:00Z&start=2026-10-02T00:00:00Z&end=2026-10-03T00:00:00Z"} {
		reporter := &relayUsageReportStub{}
		router := mux.NewRouter()
		RegisterRelayUsageEndpoints(router, scanPermissions{role: types.UserRoleOwner}, reporter, scanAudit{})
		req := httptest.NewRequest(http.MethodGet, "/karst/v1/usage/relays"+query, nil)
		req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{AccountId: "a", UserId: "viewer"})
		response := httptest.NewRecorder()
		router.ServeHTTP(response, req)
		require.GreaterOrEqual(t, response.Code, 400)
		require.Zero(t, reporter.calls)
	}
	router := mux.NewRouter()
	RegisterRelayUsageEndpoints(router, scanPermissions{role: types.UserRoleOwner}, &relayUsageReportStub{}, failingUsageAudit{})
	req := httptest.NewRequest(http.MethodGet, relayUsageReportURL, nil)
	req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{AccountId: "a", UserId: "viewer"})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, req)
	require.Equal(t, http.StatusInternalServerError, response.Code)
	require.NotContains(t, response.Body.String(), "reported_bytes")
}
