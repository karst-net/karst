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
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/netbirdio/netbird/management/internals/karst/audit"
	"github.com/netbirdio/netbird/management/internals/karst/billing"
	"github.com/netbirdio/netbird/management/internals/karst/relayusage"
	"github.com/netbirdio/netbird/management/internals/karst/usage"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/auth"
)

func TestCustomerPaymentQueueIsAccountScopedAuditedAndAsynchronous(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:customer-payment-api?mode=memory&cache=shared"), &gorm.Config{})
	require.NoError(t, err)
	log, err := audit.New(db)
	require.NoError(t, err)
	store, err := billing.NewStore(db)
	require.NoError(t, err)
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	end := start.AddDate(0, 1, 0)
	ctx := billing.WithAccount(context.Background(), "account-a")
	schedule := billing.RateSchedule{Version: "payment-api-v1", Currency: "USD", DeviceTiers: []billing.DeviceTier{{MinorPerPeriod: 250}}, RelayUnitBytes: 1}
	require.NoError(t, store.PutSchedule(ctx, schedule))
	require.NoError(t, store.AssignSchedule(ctx, start, end, schedule.Version))
	deviceCount := int64(2)
	devices := usage.DeviceReport{Start: start, End: end, AsOf: end, Complete: true,
		Segments: []usage.DeviceSegment{{Start: start, End: end, Coverage: "complete", Devices: &deviceCount}}}
	relays := relayusage.Report{Start: start, End: end, AsOf: end, Coverage: "authorized_producers", Complete: true, HistoryComplete: true, ExpectedWindows: 1, ReportedBytes: "0"}
	_, err = store.FinalizeInvoice(ctx, devices, relays)
	require.NoError(t, err)
	_, err = store.ConfigurePaddleAccount(ctx, true, "ctm_01grnn4zta5a1mf02jjze7y2ys", "pro_01grnn4zta5a1mf02jjze7y2ys")
	require.NoError(t, err)

	router := mux.NewRouter()
	RegisterPaymentEndpoints(router, scanPermissions{role: types.UserRoleOwner}, db, store, log, true)
	request := httptest.NewRequest(http.MethodGet, "/karst/v1/billing/payments?period=2026-01", nil)
	request = nbcontext.SetUserAuthInRequest(request, auth.UserAuth{AccountId: "account-a", UserId: "owner-a"})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	var initial customerPaymentView
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &initial))
	require.Equal(t, "not_queued", initial.State)
	require.Equal(t, int64(500), initial.TotalMinor)
	request = httptest.NewRequest(http.MethodPost, "/karst/v1/billing/payments?period=2026-01", nil)
	request = nbcontext.SetUserAuthInRequest(request, auth.UserAuth{AccountId: "account-a", UserId: "owner-a"})
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	require.Equal(t, http.StatusAccepted, response.Code, response.Body.String())
	require.Equal(t, "no-store", response.Header().Get("Cache-Control"))
	var view customerPaymentView
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &view))
	var responseBody map[string]any
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &responseBody))
	spec := loadKarstOpenAPISchemas(t)
	assertDeclaredResponseFields(t, spec, responseSchema(spec, "/billing/payments", "POST", "202"), responseBody, "billing payment queue")
	require.Equal(t, int64(500), view.TotalMinor)
	require.Equal(t, billing.PaymentReady, view.State)
	require.Empty(t, view.CheckoutURL)
	require.NotContains(t, response.Body.String(), "customer_id")

	var entries []audit.Entry
	require.NoError(t, db.Where("action = ?", "karst.billing.payment.queue").Find(&entries).Error)
	require.Len(t, entries, 1)
	require.Equal(t, "account-a", entries[0].AccountID)
	require.Equal(t, "owner-a", entries[0].Actor)

	request = httptest.NewRequest(http.MethodPost, "/karst/v1/billing/payments?period=2026-01", nil)
	request = nbcontext.SetUserAuthInRequest(request, auth.UserAuth{AccountId: "account-b", UserId: "other-owner"})
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	require.Equal(t, http.StatusPreconditionFailed, response.Code)
	require.NotContains(t, response.Body.String(), "account-a")
}

func TestCustomerPaymentPeriodIsStrictAndRejectsOtherQueryScope(t *testing.T) {
	for _, target := range []string{
		"/karst/v1/billing/payments?period=2026-1",
		"/karst/v1/billing/payments?period=2026-01&period=2026-02",
		"/karst/v1/billing/payments?period=2026-01&account=other",
	} {
		t.Run(target, func(t *testing.T) {
			router := mux.NewRouter()
			RegisterPaymentEndpoints(router, scanPermissions{role: types.UserRoleOwner}, nil, nil, nil, false)
			request := httptest.NewRequest(http.MethodPost, target, nil)
			request = nbcontext.SetUserAuthInRequest(request, auth.UserAuth{AccountId: "account-a", UserId: "owner-a"})
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			require.Equal(t, http.StatusUnprocessableEntity, response.Code)
		})
	}
}
