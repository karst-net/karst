// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/netbirdio/netbird/management/internals/karst/audit"
	"github.com/netbirdio/netbird/management/internals/karst/usage"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/auth"
)

type usageReportStub struct {
	account string
	calls   int
	err     error
}

func (s *usageReportStub) Devices(_ context.Context, account string, start, end time.Time) (usage.DeviceReport, error) {
	s.account = account
	s.calls++
	return usage.DeviceReport{Start: start, End: end, AsOf: end, Complete: false, DeviceMicroseconds: "0",
		Segments: []usage.DeviceSegment{{Start: start, End: end, Coverage: "uncollected"}}}, s.err
}

type failingUsageAudit struct{ scanAudit }

func (failingUsageAudit) Append(context.Context, string, string, string, string) (*audit.Entry, error) {
	return nil, errors.New("audit unavailable")
}

const usageReportURL = "/karst/v1/usage/devices?start=2026-10-01T00:00:00Z&end=2026-10-02T00:00:00Z"

func TestUsageReportAuthorizationAndTenantScope(t *testing.T) {
	for _, role := range []types.UserRole{types.UserRoleOwner, types.UserRoleAdmin, types.UserRoleUser,
		types.UserRoleNOC, types.UserRoleNetworkAdmin, types.UserRoleAuditor, types.UserRoleAdvisor, types.UserRoleBillingAdmin} {
		t.Run(string(role), func(t *testing.T) {
			db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "audit.db")), &gorm.Config{})
			require.NoError(t, err)
			sql, err := db.DB()
			require.NoError(t, err)
			t.Cleanup(func() { _ = sql.Close() })
			log, err := audit.New(db)
			require.NoError(t, err)
			reporter := &usageReportStub{}
			router := mux.NewRouter()
			RegisterUsageEndpoints(router, scanPermissions{role: role}, reporter, log)
			// Register the broad router too: the usage route must remain reachable.
			RegisterEndpoints(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, scanPermissions{role: role}, nil, nil, nil, "", router)
			req := httptest.NewRequest(http.MethodGet, usageReportURL+"&account=other-account", nil)
			req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{AccountId: "authorized-account", UserId: "viewer"})
			response := httptest.NewRecorder()
			router.ServeHTTP(response, req)
			require.Equal(t, "no-store", response.Header().Get("Cache-Control"))
			if role == types.UserRoleOwner || role == types.UserRoleAdmin {
				require.Equal(t, http.StatusOK, response.Code, response.Body.String())
				require.Equal(t, "authorized-account", reporter.account)
				require.Contains(t, response.Body.String(), `"devices":null`)
				require.NotContains(t, response.Body.String(), "other-account")
				var body map[string]any
				require.NoError(t, json.Unmarshal(response.Body.Bytes(), &body))
				spec := loadKarstOpenAPISchemas(t)
				assertDeclaredResponseFields(t, spec, responseSchema(spec, "/usage/devices", "GET", "200"), body, "usage report")
				var rows []audit.Entry
				require.NoError(t, db.Find(&rows).Error)
				require.Len(t, rows, 1)
				require.Equal(t, "authorized-account", rows[0].AccountID)
				require.Equal(t, "karst.usage.devices.view", rows[0].Action)
			} else {
				require.Equal(t, http.StatusForbidden, response.Code, response.Body.String())
				require.Zero(t, reporter.calls)
			}
		})
	}
}

func TestUsageReportRejectsMissingAuthorizationAndInvalidQueries(t *testing.T) {
	for _, query := range []string{"", "?start=not-a-date&end=2026-10-02T00:00:00Z", "?start=2026-10-01T00:00:00Z&start=2026-10-02T00:00:00Z&end=2026-10-03T00:00:00Z"} {
		reporter := &usageReportStub{}
		router := mux.NewRouter()
		RegisterUsageEndpoints(router, scanPermissions{role: types.UserRoleOwner}, reporter, scanAudit{})
		req := httptest.NewRequest(http.MethodGet, "/karst/v1/usage/devices"+query, nil)
		req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{AccountId: "a", UserId: "viewer"})
		response := httptest.NewRecorder()
		router.ServeHTTP(response, req)
		require.GreaterOrEqual(t, response.Code, 400)
		require.Zero(t, reporter.calls)
	}
	router := mux.NewRouter()
	reporter := &usageReportStub{}
	RegisterUsageEndpoints(router, nil, reporter, scanAudit{})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, usageReportURL, nil))
	require.Equal(t, http.StatusForbidden, response.Code)
	require.Zero(t, reporter.calls)
	router = mux.NewRouter()
	RegisterUsageEndpoints(router, scanPermissions{role: types.UserRoleOwner}, reporter, scanAudit{})
	response = httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, usageReportURL, nil))
	require.GreaterOrEqual(t, response.Code, 400)
	require.Zero(t, reporter.calls, "an allowed role cannot replace missing session authentication")
}

func TestUsageReportRequiresSuccessfulAudit(t *testing.T) {
	router := mux.NewRouter()
	RegisterUsageEndpoints(router, scanPermissions{role: types.UserRoleOwner}, &usageReportStub{}, failingUsageAudit{})
	req := httptest.NewRequest(http.MethodGet, usageReportURL, nil)
	req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{AccountId: "a", UserId: "viewer"})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, req)
	require.Equal(t, http.StatusInternalServerError, response.Code)
	require.NotContains(t, response.Body.String(), "device_microseconds")
}
