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
	"github.com/netbirdio/netbird/management/internals/karst/estavelleusage"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/auth"
)

type estavelleUsageReportStub struct {
	account string
	calls   int
}

type estavelleUsageAuditCapture struct {
	scanAudit
	userID string
	action string
}

func (a *estavelleUsageAuditCapture) Append(_ context.Context, userID, action, _, _ string) (*audit.Entry, error) {
	a.userID, a.action = userID, action
	return &audit.Entry{}, nil
}

func (s *estavelleUsageReportStub) Report(_ context.Context, account string, start, end time.Time) (estavelleusage.Report, error) {
	s.account, s.calls = account, s.calls+1
	return estavelleusage.Report{Start: start, End: end, AsOf: end, AuthorizationHistoryStart: start, Coverage: "authorized_producers", HistoryComplete: false, Complete: false,
		ReportedBytes: "123", Days: []estavelleusage.ReportDay{{Date: "2026-10-01", ReportedBytes: "123", ReportedWindows: 1, GapReasons: []string{}}},
		Limitations: []string{"producer coverage is not historized"}}, nil
}

const estavelleUsageReportURL = "/karst/v1/usage/estavelles?start=2026-10-01T00:00:00Z&end=2026-10-02T00:00:00Z"

func TestEstavelleUsageReportIsAccountScopedAndAudited(t *testing.T) {
	for _, role := range []types.UserRole{types.UserRoleOwner, types.UserRoleAdmin, types.UserRoleUser} {
		t.Run(string(role), func(t *testing.T) {
			reporter := &estavelleUsageReportStub{}
			auditLog := &estavelleUsageAuditCapture{}
			router := mux.NewRouter()
			RegisterEstavelleUsageEndpoints(router, scanPermissions{role: role}, reporter, auditLog)
			req := httptest.NewRequest(http.MethodGet, estavelleUsageReportURL+"&account=other", nil)
			req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{AccountId: "account-1", UserId: "viewer"})
			response := httptest.NewRecorder()
			router.ServeHTTP(response, req)
			require.Equal(t, "no-store", response.Header().Get("Cache-Control"))
			if role == types.UserRoleOwner || role == types.UserRoleAdmin {
				require.Equal(t, http.StatusOK, response.Code, response.Body.String())
				require.Equal(t, "account-1", reporter.account)
				require.Equal(t, "viewer", auditLog.userID)
				require.Equal(t, "karst.usage.estavelles.view", auditLog.action)
				require.NotContains(t, response.Body.String(), "other")
				require.NotContains(t, response.Body.String(), "missing_sequences", "producer-wide sequence holes could reveal cross-account estavelle activity")
				var body map[string]any
				require.NoError(t, json.Unmarshal(response.Body.Bytes(), &body))
				spec := loadKarstOpenAPISchemas(t)
				assertDeclaredResponseFields(t, spec, responseSchema(spec, "/usage/estavelles", "GET", "200"), body, "estavelle usage report")
			} else {
				require.Equal(t, http.StatusForbidden, response.Code)
				require.Zero(t, reporter.calls)
			}
		})
	}
}

func TestEstavelleUsageReportRejectsInvalidQueryAndRequiresAudit(t *testing.T) {
	for _, query := range []string{"", "?start=not-a-date&end=2026-10-02T00:00:00Z", "?start=2026-10-01T00:00:00Z&start=2026-10-02T00:00:00Z&end=2026-10-03T00:00:00Z"} {
		reporter := &estavelleUsageReportStub{}
		router := mux.NewRouter()
		RegisterEstavelleUsageEndpoints(router, scanPermissions{role: types.UserRoleOwner}, reporter, scanAudit{})
		req := httptest.NewRequest(http.MethodGet, "/karst/v1/usage/estavelles"+query, nil)
		req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{AccountId: "a", UserId: "viewer"})
		response := httptest.NewRecorder()
		router.ServeHTTP(response, req)
		require.GreaterOrEqual(t, response.Code, 400)
		require.Zero(t, reporter.calls)
	}
	router := mux.NewRouter()
	RegisterEstavelleUsageEndpoints(router, scanPermissions{role: types.UserRoleOwner}, &estavelleUsageReportStub{}, failingUsageAudit{})
	req := httptest.NewRequest(http.MethodGet, estavelleUsageReportURL, nil)
	req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{AccountId: "a", UserId: "viewer"})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, req)
	require.Equal(t, http.StatusInternalServerError, response.Code)
	require.NotContains(t, response.Body.String(), "reported_bytes")
}
