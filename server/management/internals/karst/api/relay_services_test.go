// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/netbirdio/netbird/management/internals/karst/relayreg"
	"github.com/netbirdio/netbird/management/internals/karst/relayservice"
	"github.com/netbirdio/netbird/management/internals/karst/turncred"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/auth"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type serviceStub struct {
	calls int
	err   error
}

func TestRelayServiceAPIUsesAuthenticatedAccountWithRealStorage(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sqlDB.Close()) })
	require.NoError(t, db.AutoMigrate(&relayreg.StoredRelay{}, &turncred.StoredTurnServer{}))
	require.NoError(t, db.Create(&relayreg.StoredRelay{AccountID: "a", ID: "ponor-a"}).Error)
	require.NoError(t, db.Create(&turncred.StoredTurnServer{AccountID: "b", ID: "turn-b"}).Error)
	store, err := relayservice.NewStore(db)
	require.NoError(t, err)
	router := mux.NewRouter()
	RegisterRelayServiceEndpoints(router, scanPermissions{role: types.UserRoleAdmin}, store)
	w := serviceRequest(router, http.MethodPost, "", `{"id":"one","ponor_id":"ponor-a","turn_id":"turn-b","backend_kind":"external","backend_operator":"provider"}`, true)
	require.Equal(t, http.StatusUnprocessableEntity, w.Code, w.Body.String())
	require.NoError(t, db.Create(&turncred.StoredTurnServer{AccountID: "a", ID: "turn-a", URI: "turn:turn.example.test:3478"}).Error)
	w = serviceRequest(router, http.MethodPost, "", `{"id":"one","ponor_id":"ponor-a","turn_id":"turn-a","backend_kind":"external","backend_operator":"Provider"}`, true)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	w = serviceRequest(router, http.MethodGet, "", "", true)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), `"ponor_present":true`)
	require.Contains(t, w.Body.String(), `"turn_present":true`)
	require.Contains(t, w.Body.String(), `"state":"unknown"`)
	var response any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
	spec := loadKarstOpenAPISchemas(t)
	assertDeclaredResponseFields(t, spec, responseSchema(spec, "/relay-services", "GET", "200"), response, "Relay service list")
	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		path := "/karst/v1/relay-services"
		if method == http.MethodDelete {
			path += "/one"
		}
		r := nbcontext.SetUserAuthInRequest(httptest.NewRequest(method, path, nil), auth.UserAuth{AccountId: "b", UserId: "other-admin"})
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		if method == http.MethodGet {
			require.Equal(t, http.StatusOK, w.Code, w.Body.String())
			require.JSONEq(t, "[]", w.Body.String())
		} else {
			require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
		}
	}
	w = serviceRequest(router, http.MethodDelete, "/one", "", true)
	require.Equal(t, http.StatusNoContent, w.Code, w.Body.String())
	var remaining int64
	require.NoError(t, db.Model(&relayreg.StoredRelay{}).Count(&remaining).Error)
	require.EqualValues(t, 1, remaining)
}

func (s *serviceStub) Create(_ context.Context, service relayservice.Service) (*relayservice.Service, error) {
	s.calls++
	return &service, s.err
}
func (s *serviceStub) List(context.Context) ([]relayservice.View, error) {
	s.calls++
	return []relayservice.View{}, s.err
}
func (s *serviceStub) Delete(context.Context, string) error { s.calls++; return s.err }

func serviceRequest(router *mux.Router, method, path, body string, authenticated bool) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "/karst/v1/relay-services"+path, strings.NewReader(body))
	if authenticated {
		r = nbcontext.SetUserAuthInRequest(r, auth.UserAuth{AccountId: "a", UserId: "admin"})
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)
	return w
}

func TestRelayServiceAPIRejectsUnauthorizedBeforeStorage(t *testing.T) {
	for _, role := range []types.UserRole{types.UserRoleUser, types.UserRoleScaler} {
		store := &serviceStub{}
		router := mux.NewRouter()
		RegisterRelayServiceEndpoints(router, scanPermissions{role: role}, store)
		for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodDelete} {
			path := ""
			if method == http.MethodDelete {
				path = "/primary"
			}
			w := serviceRequest(router, method, path, `{}`, true)
			require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
		}
		require.Zero(t, store.calls)
	}
	store := &serviceStub{}
	router := mux.NewRouter()
	RegisterRelayServiceEndpoints(router, scanPermissions{role: types.UserRoleAdmin}, store)
	w := serviceRequest(router, http.MethodGet, "", "", false)
	require.GreaterOrEqual(t, w.Code, 400)
	require.Zero(t, store.calls)
	router = mux.NewRouter()
	RegisterRelayServiceEndpoints(router, nil, store)
	w = serviceRequest(router, http.MethodGet, "", "", true)
	require.Equal(t, http.StatusForbidden, w.Code)
	require.Zero(t, store.calls)
}

func TestRelayServiceAPIValidatesJSONAndMapsStorageResults(t *testing.T) {
	store := &serviceStub{}
	router := mux.NewRouter()
	RegisterRelayServiceEndpoints(router, scanPermissions{role: types.UserRoleAdmin}, store)
	for _, body := range []string{`{"id":"one","shared_secret":"secret"}`, `{"account_id":"other"}`, `{} {}`, `{"id":"` + strings.Repeat("x", 8192) + `"}`} {
		w := serviceRequest(router, http.MethodPost, "", body, true)
		require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	}
	require.Zero(t, store.calls)
	w := serviceRequest(router, http.MethodPost, "", `{"id":"one","ponor_id":"p"}`, true)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), `"ponor_id":"p"`)
	w = serviceRequest(router, http.MethodGet, "", "", true)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	w = serviceRequest(router, http.MethodDelete, "/one", "", true)
	require.Equal(t, http.StatusNoContent, w.Code, w.Body.String())
	for _, tc := range []struct {
		err  error
		code int
	}{
		{relayservice.ErrInvalid, http.StatusUnprocessableEntity},
		{relayservice.ErrExists, http.StatusConflict},
		{relayservice.ErrNotFound, http.StatusNotFound},
	} {
		store.err = tc.err
		w = serviceRequest(router, http.MethodPost, "", `{"id":"one","ponor_id":"p"}`, true)
		require.Equal(t, tc.code, w.Code, w.Body.String())
	}
}
