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
	cap      billing.EstavelleSpendingCap
	readErr  error
	writeErr error
	setCalls int
}

func (s *relayCapBillingStub) EstavelleSpendingCap(ctx context.Context, _, _ time.Time) (billing.EstavelleSpendingCap, error) {
	_ = ctx
	return s.cap, s.readErr
}

func (s *relayCapBillingStub) SetEstavelleSpendingCap(ctx context.Context, start, end time.Time, limit int64, acknowledged bool, actor string) (billing.EstavelleSpendingCap, error) {
	s.setCalls++
	_ = ctx
	if s.writeErr != nil {
		return billing.EstavelleSpendingCap{}, s.writeErr
	}
	s.cap = billing.EstavelleSpendingCap{PeriodStart: start, PeriodEnd: end, Currency: "USD", OverageMinor: limit, Acknowledged: acknowledged, UpdatedBy: actor, EffectiveAt: start}
	return s.cap, nil
}

func TestRelayCapCustomerEndpoint(t *testing.T) {
	start := currentEstavelleCapMonth(time.Now().UTC()).Format("2006-01")
	store := &relayCapBillingStub{readErr: billing.ErrEstavelleCapNotConfigured}
	router := mux.NewRouter()
	RegisterEstavelleCapEndpoints(router, scanPermissions{role: types.UserRoleOwner}, store, scanAudit{})

	request := func(method, body string) *httptest.ResponseRecorder {
		url := "/karst/v1/billing/estavelle-cap"
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
	// Keep the request valid even after a calendar rollover so these cases
	// exercise authorization and schedule rejection, not past-period validation.
	period := currentEstavelleCapMonth(time.Now().UTC()).AddDate(0, 1, 0).Format("2006-01")
	body := `{"period":"` + period + `","overage_limit_minor":1,"acknowledge_interruption":true}`
	for _, tc := range []struct {
		name     string
		role     types.UserRole
		writeErr error
		body     string
	}{
		{name: "member", role: types.UserRoleUser, body: body},
		{name: "unassigned month", role: types.UserRoleOwner, writeErr: billing.ErrScheduleUnassigned, body: body},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := &relayCapBillingStub{writeErr: tc.writeErr}
			router := mux.NewRouter()
			RegisterEstavelleCapEndpoints(router, scanPermissions{role: tc.role}, store, scanAudit{})
			req := httptest.NewRequest(http.MethodPut, "/karst/v1/billing/estavelle-cap", strings.NewReader(tc.body))
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
	RegisterEstavelleCapEndpoints(router, scanPermissions{role: types.UserRoleAdmin}, store, scanAudit{})
	req := httptest.NewRequest(http.MethodGet, "/karst/v1/billing/estavelle-cap?period=2026-10", nil)
	req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{AccountId: "account-1", UserId: "admin-1"})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, req)
	require.Equal(t, http.StatusInternalServerError, response.Code)
}
