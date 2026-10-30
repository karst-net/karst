// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/netbirdio/netbird/management/internals/karst/infraconnections"
	karstpolicy "github.com/netbirdio/netbird/management/internals/karst/policy"
	"github.com/netbirdio/netbird/management/internals/karst/relayalloc"
	"github.com/netbirdio/netbird/management/internals/karst/relayreg"
	"github.com/netbirdio/netbird/management/internals/karst/relayservice"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/auth"
)

type relayAllocationEnv struct {
	db         *gorm.DB
	alloc      *relayalloc.Store
	registry   *relayreg.Store
	grants     *relayservice.Store
	connection string
	group      string
}

func relayAllocationFixture(t *testing.T) relayAllocationEnv {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sqlDB.Close()) })
	require.NoError(t, db.AutoMigrate(&infraconnections.Account{}, &types.Group{}, &karstpolicy.Version{}))
	connection := infraconnections.Account{ID: "conn-1", AccountID: "a", Type: infraconnections.TypeAWS, Mode: infraconnections.ModeReadWrite, Label: "aws"}
	require.NoError(t, db.Create(&connection).Error)
	group := types.Group{ID: "engineering", AccountID: "a", Name: "Engineering"}
	require.NoError(t, db.Create(&group).Error)
	alloc, err := relayalloc.NewStore(db)
	require.NoError(t, err)
	registry, err := relayreg.NewStore(db)
	require.NoError(t, err)
	grants, err := relayservice.NewStore(db)
	require.NoError(t, err)
	return relayAllocationEnv{db: db, alloc: alloc, registry: registry, grants: grants, connection: connection.ID, group: group.ID}
}

func relayAllocationRouter(e relayAllocationEnv, role types.UserRole) *mux.Router {
	router := mux.NewRouter()
	RegisterRelayAllocationEndpoints(router, scanPermissions{role: role}, e.alloc, e.registry, e.grants)
	return router
}

func allocationRequest(router *mux.Router, method, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "/karst/v1/relay-allocations"+path, strings.NewReader(body))
	r = nbcontext.SetUserAuthInRequest(r, auth.UserAuth{AccountId: "a", UserId: "admin"})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)
	return w
}

func decodeAllocation(t *testing.T, w *httptest.ResponseRecorder) relayalloc.Allocation {
	t.Helper()
	var allocation relayalloc.Allocation
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &allocation), w.Body.String())
	return allocation
}

func assertAllocationResponseFields(t *testing.T, w *httptest.ResponseRecorder, path, method, status string) {
	t.Helper()
	var raw any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &raw))
	spec := loadKarstOpenAPISchemas(t)
	assertDeclaredResponseFields(t, spec, responseSchema(spec, path, method, status), raw, "Relay allocation "+method+" "+path)
}

// TestRelayAllocationAPIHappyPathToReadyAndBackToDeprovisioned drives one
// allocation through every step of ADR-0063's state machine purely over
// HTTP, using two routers against the same underlying stores -- one as the
// console (Admin role) would reach it, one as the Scaler-role
// reconciliation loop would. Confirms the grant step's relay lookup,
// idempotent retries, and the reversed teardown order (revoke withdraws
// the relayservice grant before anything reports compute torn down).
func TestRelayAllocationAPIHappyPathToReadyAndBackToDeprovisioned(t *testing.T) {
	e := relayAllocationFixture(t)
	admin := relayAllocationRouter(e, types.UserRoleAdmin)
	scaler := relayAllocationRouter(e, types.UserRoleScaler)

	w := allocationRequest(admin, http.MethodPost, "", `{"name":"denver","infra_connection_id":"conn-1","location":"us-west-2","relay_transport":true,"permitted_groups":["engineering"]}`)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	created := decodeAllocation(t, w)
	require.Equal(t, relayalloc.StateRequested, created.State)
	assertAllocationResponseFields(t, w, "/relay-allocations", "post", "201")

	// Scaler sees it as pending.
	w = allocationRequest(scaler, http.MethodPost, "/pending", "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var pending []relayalloc.Allocation
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &pending))
	require.Len(t, pending, 1)
	// Scaler must never reach the console-only routes, though -- that
	// direction of the allowlist is what actually keeps it narrow; see
	// TestRelayAllocationAPIScalerIsNarrowerThanAdminButUserHasNeither.
	require.Equal(t, http.StatusForbidden, allocationRequest(scaler, http.MethodGet, "", "").Code)

	provisioning := decodeAllocation(t, allocationRequest(scaler, http.MethodPost, "/"+created.ID+"/provisioning",
		fmt.Sprintf(`{"expected_revision":%d,"instance_id":"i-1"}`, created.Revision)))
	require.Equal(t, relayalloc.StateProvisioning, provisioning.State)
	require.Equal(t, "i-1", provisioning.InstanceID)

	// The relay has not registered yet -- not ready, not an error.
	w = allocationRequest(scaler, http.MethodPost, "/"+created.ID+"/grant",
		fmt.Sprintf(`{"expected_revision":%d,"tls_server_name":"denver.aws.karst.internal"}`, provisioning.Revision))
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())

	// It registers.
	relay, err := e.registry.Create(relayreg.WithAccount(context.Background(), "a"), relayreg.Entry{
		Address:       "203.0.113.5:443",
		TLSServerName: "denver.aws.karst.internal",
		IdentityKey:   base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, relayreg.IdentityKeySize)),
	})
	require.NoError(t, err)

	// relayservice.configureAccess's own prerequisites, independent of
	// this allocation -- a live admission writer and service publication
	// mode, set up exactly as relayservice's own fixture does.
	require.NoError(t, e.grants.RefreshAdmissionLease(relay.ID))
	_, err = e.grants.SetPublication(relayservice.WithAccount(context.Background(), "a"), "services")
	require.NoError(t, err)

	// Retrying grant now succeeds -- note this reuses the SAME
	// expected_revision as the failed attempt above: that attempt already
	// advanced provisioning -> granting before the 404, so this is the
	// idempotent-resume path, not a fresh transition.
	w = allocationRequest(scaler, http.MethodPost, "/"+created.ID+"/grant",
		fmt.Sprintf(`{"expected_revision":%d,"tls_server_name":"denver.aws.karst.internal"}`, provisioning.Revision))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	ready := decodeAllocation(t, w)
	require.Equal(t, relayalloc.StateReady, ready.State)
	require.Equal(t, relay.ID, ready.RelayID)
	assertAllocationResponseFields(t, w, "/relay-allocations/{id}/grant", "post", "200")

	var serviceCount int64
	require.NoError(t, e.db.Model(&relayservice.Service{}).Where("id = ? AND ponor_id = ?", created.ID, relay.ID).Count(&serviceCount).Error)
	require.EqualValues(t, 1, serviceCount)

	// Retrying grant again (the loop re-polling an already-ready
	// allocation) is a safe no-op, not a second relayservice.Create.
	w = allocationRequest(scaler, http.MethodPost, "/"+created.ID+"/grant",
		fmt.Sprintf(`{"expected_revision":%d,"tls_server_name":"denver.aws.karst.internal"}`, ready.Revision))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Equal(t, relayalloc.StateReady, decodeAllocation(t, w).State)

	// Console requests deprovision.
	w = allocationRequest(admin, http.MethodPost, "/"+created.ID+"/deprovision",
		fmt.Sprintf(`{"revision":%d,"acknowledge_deprovision":true}`, ready.Revision))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	revoking := decodeAllocation(t, w)
	require.Equal(t, relayalloc.StateRevoking, revoking.State)

	// Scaler withdraws the grant -- before anything reports compute torn
	// down.
	w = allocationRequest(scaler, http.MethodPost, "/"+created.ID+"/revoke", fmt.Sprintf(`{"expected_revision":%d}`, revoking.Revision))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	deprovisioning := decodeAllocation(t, w)
	require.Equal(t, relayalloc.StateDeprovisioning, deprovisioning.State)

	require.NoError(t, e.db.Model(&relayservice.Service{}).Where("id = ?", created.ID).Count(&serviceCount).Error)
	require.Zero(t, serviceCount, "the grant must be withdrawn before anything confirms compute deprovisioned")

	w = allocationRequest(scaler, http.MethodPost, "/"+created.ID+"/deprovisioned", fmt.Sprintf(`{"expected_revision":%d}`, deprovisioning.Revision))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	deprovisioned := decodeAllocation(t, w)
	require.Equal(t, relayalloc.StateDeprovisioned, deprovisioned.State)

	w = allocationRequest(admin, http.MethodDelete, fmt.Sprintf("/%s?revision=%d", created.ID, deprovisioned.Revision), "")
	require.Equal(t, http.StatusNoContent, w.Code, w.Body.String())

	var remaining int64
	require.NoError(t, e.db.Model(&relayalloc.Allocation{}).Count(&remaining).Error)
	require.Zero(t, remaining)
}

// TestRelayAllocationGrantReportsFailureWithoutLeavingAPartialGrant covers
// the other branch of granting: relayservice rejects the attempt (no live
// admission writer configured here), and the allocation must land in
// StateFailed with no Service row ever created -- never a grant believed
// to have failed while compute silently kept running unaccounted for.
func TestRelayAllocationGrantReportsFailureWithoutLeavingAPartialGrant(t *testing.T) {
	e := relayAllocationFixture(t)
	admin := relayAllocationRouter(e, types.UserRoleAdmin)
	scaler := relayAllocationRouter(e, types.UserRoleScaler)

	created := decodeAllocation(t, allocationRequest(admin, http.MethodPost, "",
		`{"name":"denver","infra_connection_id":"conn-1","location":"us-west-2","relay_transport":true,"permitted_groups":["engineering"]}`))
	provisioning := decodeAllocation(t, allocationRequest(scaler, http.MethodPost, "/"+created.ID+"/provisioning",
		fmt.Sprintf(`{"expected_revision":%d,"instance_id":"i-1"}`, created.Revision)))

	_, err := e.registry.Create(relayreg.WithAccount(context.Background(), "a"), relayreg.Entry{
		Address:       "203.0.113.6:443",
		TLSServerName: "denver.aws.karst.internal",
		IdentityKey:   base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, relayreg.IdentityKeySize)),
	})
	require.NoError(t, err)
	// No RefreshAdmissionLease, no SetPublication -- configureAccess must
	// refuse this grant.

	w := allocationRequest(scaler, http.MethodPost, "/"+created.ID+"/grant",
		fmt.Sprintf(`{"expected_revision":%d,"tls_server_name":"denver.aws.karst.internal"}`, provisioning.Revision))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	failed := decodeAllocation(t, w)
	require.Equal(t, relayalloc.StateFailed, failed.State)
	require.Equal(t, relayalloc.StateGranting, failed.FailedStep)
	require.NotEmpty(t, failed.FailureReason)

	var serviceCount int64
	require.NoError(t, e.db.Model(&relayservice.Service{}).Count(&serviceCount).Error)
	require.Zero(t, serviceCount)
}

// TestRelayAllocationAPIScalerIsNarrowerThanAdminButUserHasNeither is the
// security property the hard allowlist exists for. It does not make the
// Scaler and Admin/Owner roles mutually exclusive -- ADR-0045 §7 Phase 2's
// own precedent (relayEnrollTokensPath: "Admin/Owner, who already hold
// Create on KarstControl, may too") means Admin can also reach every
// allocation-driving action. What the allowlist actually narrows is
// Scaler: it may drive allocations but never reach the console-only
// routes. A role with no KarstControl grant at all (User) reaches neither.
func TestRelayAllocationAPIScalerIsNarrowerThanAdminButUserHasNeither(t *testing.T) {
	e := relayAllocationFixture(t)
	created := decodeAllocation(t, allocationRequest(relayAllocationRouter(e, types.UserRoleAdmin), http.MethodPost, "",
		`{"name":"denver","infra_connection_id":"conn-1","location":"us-west-2","relay_transport":true,"permitted_groups":["engineering"]}`))

	consoleOnlyRoutes := []struct{ method, path, body string }{
		{http.MethodGet, "", ""},
		{http.MethodPost, "", `{"name":"x","infra_connection_id":"conn-1","location":"us-west-2","relay_transport":true,"permitted_groups":["engineering"]}`},
		{http.MethodDelete, "/" + created.ID + "?revision=1", ""},
		{http.MethodPost, "/" + created.ID + "/deprovision", `{"revision":1,"acknowledge_deprovision":true}`},
	}
	scalerOnlyRoutes := []struct{ method, path, body string }{
		{http.MethodPost, "/pending", ""},
		{http.MethodPost, "/" + created.ID + "/provisioning", `{"expected_revision":1,"instance_id":"i-1"}`},
		{http.MethodPost, "/" + created.ID + "/grant", `{"expected_revision":1,"tls_server_name":"x"}`},
		{http.MethodPost, "/" + created.ID + "/revoke", `{"expected_revision":1}`},
		{http.MethodPost, "/" + created.ID + "/deprovisioned", `{"expected_revision":1}`},
		{http.MethodPost, "/" + created.ID + "/failed", `{"expected_revision":1,"reason":"x"}`},
	}

	scaler := relayAllocationRouter(e, types.UserRoleScaler)
	for _, call := range consoleOnlyRoutes {
		w := allocationRequest(scaler, call.method, call.path, call.body)
		require.Equal(t, http.StatusForbidden, w.Code, "scaler %s %s: %s", call.method, call.path, w.Body.String())
	}

	user := relayAllocationRouter(e, types.UserRoleUser)
	for _, call := range append(append([]struct{ method, path, body string }{}, consoleOnlyRoutes...), scalerOnlyRoutes...) {
		w := allocationRequest(user, call.method, call.path, call.body)
		require.Equal(t, http.StatusForbidden, w.Code, "plain user %s %s: %s", call.method, call.path, w.Body.String())
	}

	// Admin reaches a Scaler-only route too -- the same relationship
	// relayEnrollTokensPath already has with Admin, not a regression.
	admin := relayAllocationRouter(e, types.UserRoleAdmin)
	w := allocationRequest(admin, http.MethodPost, "/pending", "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
}

// TestRelayAllocationFailedInfersFromStateAndIsIdempotent covers the
// generic failure-report action: it reads the "from" state off the row
// itself rather than trusting a caller-supplied one, and repeating it once
// already failed is a safe no-op.
func TestRelayAllocationFailedInfersFromStateAndIsIdempotent(t *testing.T) {
	e := relayAllocationFixture(t)
	admin := relayAllocationRouter(e, types.UserRoleAdmin)
	scaler := relayAllocationRouter(e, types.UserRoleScaler)
	created := decodeAllocation(t, allocationRequest(admin, http.MethodPost, "",
		`{"name":"denver","infra_connection_id":"conn-1","location":"us-west-2","relay_transport":true,"permitted_groups":["engineering"]}`))

	w := allocationRequest(scaler, http.MethodPost, "/"+created.ID+"/failed",
		fmt.Sprintf(`{"expected_revision":%d,"reason":"quota exceeded"}`, created.Revision))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	failed := decodeAllocation(t, w)
	require.Equal(t, relayalloc.StateFailed, failed.State)
	require.Equal(t, relayalloc.StateRequested, failed.FailedStep)
	require.Equal(t, "quota exceeded", failed.FailureReason)

	// Idempotent retry -- same result, no error, no second Transition.
	w = allocationRequest(scaler, http.MethodPost, "/"+created.ID+"/failed",
		fmt.Sprintf(`{"expected_revision":%d,"reason":"ignored"}`, failed.Revision))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Equal(t, "quota exceeded", decodeAllocation(t, w).FailureReason)
}

// TestRelayAllocationDeleteRequiresDeprovisionFirst confirms the API layer
// surfaces Store.Delete's own gating rather than papering over it: a
// provisioning allocation cannot simply be deleted out from under the loop.
func TestRelayAllocationDeleteRequiresDeprovisionFirst(t *testing.T) {
	e := relayAllocationFixture(t)
	admin := relayAllocationRouter(e, types.UserRoleAdmin)
	scaler := relayAllocationRouter(e, types.UserRoleScaler)
	created := decodeAllocation(t, allocationRequest(admin, http.MethodPost, "",
		`{"name":"denver","infra_connection_id":"conn-1","location":"us-west-2","relay_transport":true,"permitted_groups":["engineering"]}`))
	provisioning := decodeAllocation(t, allocationRequest(scaler, http.MethodPost, "/"+created.ID+"/provisioning",
		fmt.Sprintf(`{"expected_revision":%d,"instance_id":"i-1"}`, created.Revision)))

	w := allocationRequest(admin, http.MethodDelete, fmt.Sprintf("/%s?revision=%d", created.ID, provisioning.Revision), "")
	require.Equal(t, http.StatusUnprocessableEntity, w.Code, w.Body.String())

	var remaining int64
	require.NoError(t, e.db.Model(&relayalloc.Allocation{}).Count(&remaining).Error)
	require.EqualValues(t, 1, remaining)
}

// TestRelayAllocationAPIRejectsUnauthenticated mirrors every other karst
// endpoint's own baseline: no user auth context, no access at all.
func TestRelayAllocationAPIRejectsUnauthenticated(t *testing.T) {
	e := relayAllocationFixture(t)
	router := relayAllocationRouter(e, types.UserRoleAdmin)
	r := httptest.NewRequest(http.MethodGet, "/karst/v1/relay-allocations", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)
	require.NotEqual(t, http.StatusOK, w.Code)
}
