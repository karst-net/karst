// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package api

import (
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

	"github.com/netbirdio/netbird/management/internals/karst/node"
	"github.com/netbirdio/netbird/management/internals/karst/rollout"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/shared/auth"
)

const testValidDigest = "sha256:" + "0123456789abcdef" + "0123456789abcdef" + "0123456789abcdef" + "0123456789abcdef"

type rolloutEnv struct {
	db    *gorm.DB
	store *rollout.Store
	nodes *node.Store
}

func rolloutFixture(t *testing.T) rolloutEnv {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sqlDB.Close()) })
	require.NoError(t, db.Exec("CREATE TABLE peers (key TEXT PRIMARY KEY, account_id TEXT)").Error)
	store, err := rollout.NewStore(db)
	require.NoError(t, err)
	nodes, err := node.NewStore(db)
	require.NoError(t, err)
	return rolloutEnv{db: db, store: store, nodes: nodes}
}

func rolloutRouter(e rolloutEnv) *mux.Router {
	router := mux.NewRouter()
	RegisterRolloutEndpoints(router, e.store, e.nodes)
	return router
}

func rolloutRequest(router *mux.Router, role, method, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "/karst/v1/rollouts"+path, strings.NewReader(body))
	r = nbcontext.SetUserAuthInRequest(r, auth.UserAuth{AccountId: "a", UserId: "admin"})
	if role != "" {
		r = r.WithContext(nbcontext.WithRole(r.Context(), role))
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)
	return w
}

func decodeRolloutPayload(t *testing.T, w *httptest.ResponseRecorder) rolloutPlanPayload {
	t.Helper()
	var payload rolloutPlanPayload
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &payload), w.Body.String())
	return payload
}

func threeComponentPlanBody() string {
	return fmt.Sprintf(`{"target_release":"v0.9.0","components":[
		{"name":"control","sequence":0,"target_digest":%q,"verification_ref":"cosign verify ok"},
		{"name":"relay_job","sequence":1,"target_digest":%q,"verification_ref":"cosign verify ok"},
		{"name":"console","sequence":2,"target_digest":%q,"verification_ref":"cosign verify ok"}
	]}`, testValidDigest, testValidDigest, testValidDigest)
}

// TestRolloutAPIHappyPathToCompleted drives one plan through create, start,
// and every component's mark-applied purely over HTTP, confirming the
// sequencing enforcement and the auto-transition to completed once the last
// component applies.
func TestRolloutAPIHappyPathToCompleted(t *testing.T) {
	e := rolloutFixture(t)
	router := rolloutRouter(e)

	w := rolloutRequest(router, "admin", http.MethodPost, "", threeComponentPlanBody())
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	created := decodeRolloutPayload(t, w)
	require.Equal(t, rollout.StatePlanned, created.State)
	require.Len(t, created.Components, 3)
	require.Empty(t, created.Compatibility, "no component declares a required schema")

	w = rolloutRequest(router, "admin", http.MethodPost, "/"+created.ID+"/start",
		fmt.Sprintf(`{"revision":%d,"acknowledge":true}`, created.Revision))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	started := decodeRolloutPayload(t, w)
	require.Equal(t, rollout.StateInProgress, started.State)

	// Out of order: relay_job is sequence 1, control is sequence 0.
	w = rolloutRequest(router, "admin", http.MethodPost, "/"+created.ID+"/components/relay_job/mark-applied",
		fmt.Sprintf(`{"revision":%d}`, started.Revision))
	require.Equal(t, http.StatusUnprocessableEntity, w.Code, w.Body.String())

	w = rolloutRequest(router, "admin", http.MethodPost, "/"+created.ID+"/components/control/mark-applied",
		fmt.Sprintf(`{"revision":%d}`, started.Revision))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	afterControl := decodeRolloutPayload(t, w)
	require.Equal(t, rollout.StateInProgress, afterControl.State)
	require.Contains(t, afterControl.Note, "scripts/compose-versions.py", "no deployment snapshot is configured in this test")

	w = rolloutRequest(router, "admin", http.MethodPost, "/"+created.ID+"/components/relay_job/mark-applied",
		fmt.Sprintf(`{"revision":%d}`, afterControl.Revision))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	afterRelay := decodeRolloutPayload(t, w)

	w = rolloutRequest(router, "admin", http.MethodPost, "/"+created.ID+"/components/console/mark-applied",
		fmt.Sprintf(`{"revision":%d}`, afterRelay.Revision))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	completed := decodeRolloutPayload(t, w)
	require.Equal(t, rollout.StateCompleted, completed.State)
	for _, component := range completed.Components {
		require.Equal(t, "applied", component.Status)
	}
}

// TestRolloutAPIBlocksStartOnIncompatibleFleetUnlessOverridden confirms the
// compatibility preview is computed live and enforced server-side: an
// enrolled peer below the declared required schema blocks Start, and only
// an explicit override_incompatibility proceeds.
func TestRolloutAPIBlocksStartOnIncompatibleFleetUnlessOverridden(t *testing.T) {
	e := rolloutFixture(t)
	router := rolloutRouter(e)

	require.NoError(t, e.db.Create(&node.Identity{Handle: "peer-1", PublicKey: []byte{1}}).Error)
	require.NoError(t, e.db.Exec("INSERT INTO peers VALUES (?, ?)", "peer-1", "a").Error)
	// peer-1 never declares relay_lifecycle_schema; it stays at 0.

	body := fmt.Sprintf(`{"target_release":"v0.9.0","components":[
		{"name":"control","sequence":0,"target_digest":%q,"verification_ref":"ok","requires_relay_lifecycle_schema":2}
	]}`, testValidDigest)
	w := rolloutRequest(router, "admin", http.MethodPost, "", body)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	created := decodeRolloutPayload(t, w)
	require.Len(t, created.Compatibility, 1)
	require.True(t, created.Compatibility[0].Blocking)
	require.EqualValues(t, 1, created.Compatibility[0].IncompatiblePeerCount)

	w = rolloutRequest(router, "admin", http.MethodPost, "/"+created.ID+"/start",
		fmt.Sprintf(`{"revision":%d,"acknowledge":true}`, created.Revision))
	require.Equal(t, http.StatusUnprocessableEntity, w.Code, w.Body.String(), "blocking compatibility must refuse start without an override")

	w = rolloutRequest(router, "admin", http.MethodPost, "/"+created.ID+"/start",
		fmt.Sprintf(`{"revision":%d,"acknowledge":true,"override_incompatibility":true}`, created.Revision))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	started := decodeRolloutPayload(t, w)
	require.Equal(t, rollout.StateInProgress, started.State)
}

// TestRolloutAPIRoleGating confirms only admin/owner can reach any route --
// this workflow has no device-facing or Scaler-role action at all.
func TestRolloutAPIRoleGating(t *testing.T) {
	e := rolloutFixture(t)
	router := rolloutRouter(e)
	for _, role := range []string{"user", "noc", "auditor", ""} {
		w := rolloutRequest(router, role, http.MethodGet, "", "")
		require.Equal(t, http.StatusForbidden, w.Code, "role %q must be refused", role)
	}
	for _, role := range []string{"admin", "owner"} {
		w := rolloutRequest(router, role, http.MethodGet, "", "")
		require.Equal(t, http.StatusOK, w.Code, "role %q must be allowed", role)
	}
}

// TestRolloutAPIFailComponentAndRollBack covers the failure branch and
// confirms a rolled_back plan's component rows are left untouched for
// audit, and that the plan cannot be deleted afterward.
func TestRolloutAPIFailComponentAndRollBack(t *testing.T) {
	e := rolloutFixture(t)
	router := rolloutRouter(e)

	created := decodeRolloutPayload(t, rolloutRequest(router, "admin", http.MethodPost, "", threeComponentPlanBody()))
	started := decodeRolloutPayload(t, rolloutRequest(router, "admin", http.MethodPost, "/"+created.ID+"/start",
		fmt.Sprintf(`{"revision":%d,"acknowledge":true}`, created.Revision)))

	w := rolloutRequest(router, "admin", http.MethodPost, "/"+created.ID+"/components/control/mark-failed",
		fmt.Sprintf(`{"revision":%d,"reason":"nomad job run failed"}`, started.Revision))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	failed := decodeRolloutPayload(t, w)
	require.Equal(t, rollout.StateFailed, failed.State)
	require.Equal(t, "control", failed.FailedComponent)

	w = rolloutRequest(router, "admin", http.MethodPost, "/"+created.ID+"/rollback",
		fmt.Sprintf(`{"revision":%d,"acknowledge_rollback":true,"reason":"operator reverted digest"}`, failed.Revision))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	rolledBack := decodeRolloutPayload(t, w)
	require.Equal(t, rollout.StateRolledBack, rolledBack.State)
	for _, component := range rolledBack.Components {
		if component.Name == "control" {
			require.Equal(t, "failed", component.Status, "component rows stay as audit, rollback does not reset them")
		}
	}

	w = rolloutRequest(router, "admin", http.MethodDelete, fmt.Sprintf("/%s?revision=%d", created.ID, rolledBack.Revision), "")
	require.Equal(t, http.StatusUnprocessableEntity, w.Code, w.Body.String(), "a rolled_back plan must stay for audit, not be deletable")
}

// TestRolloutAPIDeleteRequiresPlannedState and
// TestRolloutAPIRejectsUnauthenticated mirror relay allocation's own
// baseline API tests.
func TestRolloutAPIDeleteRequiresPlannedState(t *testing.T) {
	e := rolloutFixture(t)
	router := rolloutRouter(e)
	created := decodeRolloutPayload(t, rolloutRequest(router, "admin", http.MethodPost, "", threeComponentPlanBody()))
	require.Equal(t, http.StatusNoContent, rolloutRequest(router, "admin", http.MethodDelete,
		fmt.Sprintf("/%s?revision=%d", created.ID, created.Revision), "").Code)

	var remaining int64
	require.NoError(t, e.db.Model(&rollout.Plan{}).Count(&remaining).Error)
	require.Zero(t, remaining)
}

func TestRolloutAPIRejectsUnauthenticated(t *testing.T) {
	e := rolloutFixture(t)
	router := rolloutRouter(e)
	r := httptest.NewRequest(http.MethodGet, "/karst/v1/rollouts", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)
	require.NotEqual(t, http.StatusOK, w.Code)
}
