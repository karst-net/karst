// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/karst/billing"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/auth"
)

type relayCapBillingStub struct {
	cap      billing.RelaySpendingCap
	readErr  error
	writeErr error
	setCalls int
}

func (s *relayCapBillingStub) RelaySpendingCap(ctx context.Context, _, _ time.Time) (billing.RelaySpendingCap, error) {
	_ = ctx
	return s.cap, s.readErr
}

func (s *relayCapBillingStub) SetRelaySpendingCap(ctx context.Context, start, end time.Time, limit int64, acknowledged bool, actor string) (billing.RelaySpendingCap, error) {
	s.setCalls++
	_ = ctx
	if s.writeErr != nil {
		return billing.RelaySpendingCap{}, s.writeErr
	}
	s.cap = billing.RelaySpendingCap{PeriodStart: start, PeriodEnd: end, Currency: "USD", OverageMinor: limit, Acknowledged: acknowledged, UpdatedBy: actor, EffectiveAt: start}
	return s.cap, nil
}

func TestRelayCapCustomerEndpoint(t *testing.T) {
	start := currentRelayCapMonth(time.Now().UTC()).Format("2006-01")
	store := &relayCapBillingStub{readErr: billing.ErrRelayCapNotConfigured}
	router := mux.NewRouter()
	RegisterRelayCapEndpoints(router, scanPermissions{role: types.UserRoleOwner}, store, scanAudit{})

	request := func(method, body string) *httptest.ResponseRecorder {
		url := "/karst/v1/billing/relay-cap"
		if method == http.MethodGet {
			url += "?period=" + start
		}
		req := httptest.NewRequest(method, url, strings.NewReader(body))
		if method == http.MethodPut {
			req.Header.Set("Content-Type", "application/json; charset=utf-8")
		}
		req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{AccountId: "account-1", UserId: "owner-1"})
		response := httptest.NewRecorder()
		router.ServeHTTP(response, req)
		return response
	}

	get := request(http.MethodGet, "")
	require.Equal(t, http.StatusOK, get.Code, get.Body.String())
	require.Equal(t, "no-store", get.Header().Get("Cache-Control"))
	require.Contains(t, get.Body.String(), `"enabled":false`)

	put := request(http.MethodPut, `{"period":"`+start+`","overage_limit_minor":1250,"acknowledge_interruption":true}`)
	require.Equal(t, http.StatusOK, put.Code, put.Body.String())
	require.Contains(t, put.Body.String(), `"overage_limit_minor":1250`)
	require.Contains(t, put.Body.String(), `"effective_at"`)
	require.Equal(t, 1, store.setCalls)

	missingAcknowledgment := request(http.MethodPut, `{"period":"`+start+`","overage_limit_minor":1250}`)
	require.GreaterOrEqual(t, missingAcknowledgment.Code, http.StatusBadRequest)
	require.Equal(t, 1, store.setCalls)
}

func TestRelayCapCustomerEndpointRejectsUnauthorizedAndBadSchedule(t *testing.T) {
	for _, tc := range []struct {
		name     string
		role     types.UserRole
		writeErr error
		body     string
	}{
		{name: "member", role: types.UserRoleUser, body: `{"period":"2026-10","overage_limit_minor":1,"acknowledge_interruption":true}`},
		{name: "unassigned month", role: types.UserRoleOwner, writeErr: billing.ErrScheduleUnassigned, body: `{"period":"2026-10","overage_limit_minor":1,"acknowledge_interruption":true}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := &relayCapBillingStub{writeErr: tc.writeErr}
			router := mux.NewRouter()
			RegisterRelayCapEndpoints(router, scanPermissions{role: tc.role}, store, scanAudit{})
			req := httptest.NewRequest(http.MethodPut, "/karst/v1/billing/relay-cap", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{AccountId: "account-1", UserId: "user-1"})
			response := httptest.NewRecorder()
			router.ServeHTTP(response, req)
			require.GreaterOrEqual(t, response.Code, http.StatusBadRequest)
			if tc.role == types.UserRoleUser {
				require.Zero(t, store.setCalls)
			} else {
				require.Equal(t, 1, store.setCalls)
			}
		})
	}
}

func TestRelayCapCustomerEndpointRequiresScheduleForGet(t *testing.T) {
	store := &relayCapBillingStub{readErr: errors.New("database unavailable")}
	router := mux.NewRouter()
	RegisterRelayCapEndpoints(router, scanPermissions{role: types.UserRoleAdmin}, store, scanAudit{})
	req := httptest.NewRequest(http.MethodGet, "/karst/v1/billing/relay-cap?period=2026-10", nil)
	req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{AccountId: "account-1", UserId: "admin-1"})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, req)
	require.Equal(t, http.StatusInternalServerError, response.Code)
}
