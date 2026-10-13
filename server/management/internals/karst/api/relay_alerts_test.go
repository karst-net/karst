// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/karst/audit"
	"github.com/netbirdio/netbird/management/internals/karst/billing"
	"github.com/netbirdio/netbird/management/internals/karst/relayusage"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/auth"
)

type relayAlertUsageStub struct {
	account string
	calls   int
}

func (s *relayAlertUsageStub) Report(_ context.Context, account string, start, end time.Time) (relayusage.Report, error) {
	s.account = account
	s.calls++
	return relayusage.Report{Start: start, End: end, AsOf: time.Now().UTC(), ReportedBytes: "123"}, nil
}

type relayAlertBillingStub struct {
	evaluated bool
	listed    bool
	alerts    []billing.RelayAlertCandidate
}

func (s *relayAlertBillingStub) EvaluateAndRecordRelayAlerts(_ context.Context, _ relayusage.Report, cap *int64) ([]billing.RelayAlertCandidate, error) {
	s.evaluated = true
	if cap != nil {
		return nil, errors.New("unexpected cap")
	}
	return s.alerts, nil
}

func (s *relayAlertBillingStub) RelayAlerts(context.Context, time.Time, time.Time) ([]billing.RelayAlertCandidate, error) {
	s.listed = true
	return s.alerts, nil
}

func (s *relayAlertBillingStub) RelaySpendingCap(context.Context, time.Time, time.Time) (billing.RelaySpendingCap, error) {
	return billing.RelaySpendingCap{}, billing.ErrRelayCapNotConfigured
}

type relayAlertAuditStub struct {
	scanAudit
	userID string
	action string
}

func (a *relayAlertAuditStub) Append(_ context.Context, userID, action, _, _ string) (*audit.Entry, error) {
	a.userID, a.action = userID, action
	return &audit.Entry{}, nil
}

func TestRelayAlertFeedIsAccountScopedForOwnersAndAdmins(t *testing.T) {
	usageStore := &relayAlertUsageStub{}
	start := time.Now().UTC().Format("2006-01")
	alerts := []billing.RelayAlertCandidate{{Threshold: 75, ReportedBytes: "123", ThresholdBytes: "100"}}
	billingStore := &relayAlertBillingStub{alerts: alerts}
	auditLog := &relayAlertAuditStub{}
	router := mux.NewRouter()
	RegisterRelayAlertEndpoints(router, scanPermissions{role: types.UserRoleAdmin}, usageStore, billingStore, auditLog)
	req := httptest.NewRequest(http.MethodGet, "/karst/v1/usage/relay-alerts?period="+start, nil)
	req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{AccountId: "account-1", UserId: "billing-viewer"})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, req)
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	require.Equal(t, "no-store", response.Header().Get("Cache-Control"))
	require.Equal(t, "account-1", usageStore.account)
	require.Equal(t, 1, usageStore.calls)
	require.True(t, billingStore.evaluated)
	require.True(t, billingStore.listed)
	require.Equal(t, "billing-viewer", auditLog.userID)
	require.Equal(t, "karst.billing.relay_alerts.view", auditLog.action)
	require.Contains(t, response.Body.String(), `"threshold_percent":75`)
	require.Contains(t, response.Body.String(), `"coverage_complete":false`)
	require.Contains(t, response.Body.String(), "lower bounds")
	var body map[string]any
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &body))
	spec := loadKarstOpenAPISchemas(t)
	assertDeclaredResponseFields(t, spec, responseSchema(spec, "/usage/relay-alerts", "GET", "200"), body, "relay alert feed")
}

func TestRelayAlertFeedRejectsUnauthorizedAndMalformedPeriod(t *testing.T) {
	for _, tc := range []struct {
		name string
		role types.UserRole
		url  string
	}{
		{name: "regular user", role: types.UserRoleUser, url: "/karst/v1/usage/relay-alerts?period=2026-10"},
		{name: "malformed month", role: types.UserRoleOwner, url: "/karst/v1/usage/relay-alerts?period=2026-13"},
		{name: "duplicate month", role: types.UserRoleOwner, url: "/karst/v1/usage/relay-alerts?period=2026-10&period=2026-11"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			usageStore := &relayAlertUsageStub{}
			billingStore := &relayAlertBillingStub{}
			router := mux.NewRouter()
			RegisterRelayAlertEndpoints(router, scanPermissions{role: tc.role}, usageStore, billingStore, &relayAlertAuditStub{})
			req := httptest.NewRequest(http.MethodGet, tc.url, nil)
			req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{AccountId: "account-1", UserId: "viewer"})
			response := httptest.NewRecorder()
			router.ServeHTTP(response, req)
			if tc.role == types.UserRoleUser {
				require.Equal(t, http.StatusForbidden, response.Code)
			} else {
				require.GreaterOrEqual(t, response.Code, http.StatusBadRequest)
			}
			require.Zero(t, usageStore.calls)
			require.False(t, billingStore.evaluated)
		})
	}
}
