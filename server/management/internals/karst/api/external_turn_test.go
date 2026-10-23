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
	"github.com/netbirdio/netbird/management/internals/karst/externalturn"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/auth"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/netbirdio/netbird/util/crypt"
)

func newExternalTurnTestStore(t *testing.T) *externalturn.Store {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	key, err := crypt.GenerateKey()
	require.NoError(t, err)
	enc, err := crypt.NewFieldEncrypt(key)
	require.NoError(t, err)
	store, err := externalturn.NewStore(db, enc)
	require.NoError(t, err)
	return store
}

func externalTurnRequest(router *mux.Router, method, path, body string, authenticated bool) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "/karst/v1/external-turn-servers"+path, strings.NewReader(body))
	if authenticated {
		r = nbcontext.SetUserAuthInRequest(r, auth.UserAuth{AccountId: "a", UserId: "admin"})
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)
	return w
}

func TestExternalTurnAPICreateListNeverExposeTheCredential(t *testing.T) {
	store := newExternalTurnTestStore(t)
	router := mux.NewRouter()
	RegisterExternalTurnEndpoints(router, scanPermissions{role: types.UserRoleAdmin}, store)

	w := externalTurnRequest(router, http.MethodPost, "", `{"uri":"turns:turn.example:5349","username":"node","credential":"s3cret"}`, true)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	require.NotContains(t, w.Body.String(), "s3cret")
	require.NotContains(t, w.Body.String(), "credential")

	w = externalTurnRequest(router, http.MethodGet, "", "", true)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	require.NotContains(t, w.Body.String(), "s3cret")
	require.NotContains(t, w.Body.String(), "credential")

	var response any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
	spec := loadKarstOpenAPISchemas(t)
	assertDeclaredResponseFields(t, spec, responseSchema(spec, "/external-turn-servers", "GET", "200"), response, "External TURN server list")
}

func TestExternalTurnAPIRejectsPlainTurnSchemeAsUnprocessable(t *testing.T) {
	store := newExternalTurnTestStore(t)
	router := mux.NewRouter()
	RegisterExternalTurnEndpoints(router, scanPermissions{role: types.UserRoleAdmin}, store)

	w := externalTurnRequest(router, http.MethodPost, "", `{"uri":"turn:turn.example:3478","username":"node","credential":"s3cret"}`, true)
	require.Equal(t, http.StatusUnprocessableEntity, w.Code, w.Body.String())
}

func TestExternalTurnAPIUpdateLeavesCredentialAloneWhenOmitted(t *testing.T) {
	store := newExternalTurnTestStore(t)
	router := mux.NewRouter()
	RegisterExternalTurnEndpoints(router, scanPermissions{role: types.UserRoleAdmin}, store)

	w := externalTurnRequest(router, http.MethodPost, "", `{"uri":"turns:turn.example:5349","username":"node","credential":"s3cret"}`, true)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var created externalturn.Response
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &created))

	w = externalTurnRequest(router, http.MethodPut, "/"+created.ID, `{"uri":"turns:renamed.example:5349","username":"node"}`, true)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), `"uri":"turns:renamed.example:5349"`)

	rows, err := store.NetmapServers(context.Background(), "a")
	require.NoError(t, err)
	require.Len(t, rows, 1)
	require.Equal(t, "s3cret", rows[0].Credential, "omitting credential on update must not touch the stored one")
}

func TestExternalTurnAPIReorderAndDelete(t *testing.T) {
	store := newExternalTurnTestStore(t)
	router := mux.NewRouter()
	RegisterExternalTurnEndpoints(router, scanPermissions{role: types.UserRoleAdmin}, store)

	w := externalTurnRequest(router, http.MethodPost, "", `{"uri":"turns:a.example:5349","username":"node","credential":"s3cret"}`, true)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var a externalturn.Response
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &a))
	w = externalTurnRequest(router, http.MethodPost, "", `{"uri":"turns:b.example:5349","username":"node","credential":"s3cret"}`, true)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var b externalturn.Response
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &b))

	w = externalTurnRequest(router, http.MethodPut, "/reorder", `{"ids":["`+b.ID+`","`+a.ID+`"]}`, true)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var reordered []externalturn.Response
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &reordered))
	require.Len(t, reordered, 2)
	require.Equal(t, b.ID, reordered[0].ID)

	w = externalTurnRequest(router, http.MethodDelete, "/"+a.ID, "", true)
	require.Equal(t, http.StatusNoContent, w.Code, w.Body.String())
	w = externalTurnRequest(router, http.MethodGet, "", "", true)
	var remaining []externalturn.Response
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &remaining))
	require.Len(t, remaining, 1)
	require.Equal(t, b.ID, remaining[0].ID)
}

func TestExternalTurnAPIRejectsUnauthorizedBeforeStorage(t *testing.T) {
	for _, role := range []types.UserRole{types.UserRoleUser, types.UserRoleScaler} {
		store := newExternalTurnTestStore(t)
		router := mux.NewRouter()
		RegisterExternalTurnEndpoints(router, scanPermissions{role: role}, store)
		for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodDelete} {
			path := ""
			if method == http.MethodDelete {
				path = "/primary"
			}
			w := externalTurnRequest(router, method, path, `{}`, true)
			require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
		}
	}
	router := mux.NewRouter()
	RegisterExternalTurnEndpoints(router, nil, newExternalTurnTestStore(t))
	w := externalTurnRequest(router, http.MethodGet, "", "", true)
	require.Equal(t, http.StatusForbidden, w.Code)
}

func TestExternalTurnAPIIsScopedPerAccount(t *testing.T) {
	store := newExternalTurnTestStore(t)
	router := mux.NewRouter()
	RegisterExternalTurnEndpoints(router, scanPermissions{role: types.UserRoleAdmin}, store)
	w := externalTurnRequest(router, http.MethodPost, "", `{"uri":"turns:a.example:5349","username":"node","credential":"s3cret"}`, true)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())

	r := nbcontext.SetUserAuthInRequest(httptest.NewRequest(http.MethodGet, "/karst/v1/external-turn-servers", nil), auth.UserAuth{AccountId: "b", UserId: "other-admin"})
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, r)
	require.Equal(t, http.StatusOK, w2.Code, w2.Body.String())
	require.JSONEq(t, "[]", w2.Body.String())
}
