package idp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dexidp/dex/storage"
	"github.com/netbirdio/netbird/idp/dex"
	"github.com/stretchr/testify/require"
)

func TestKeycloakConnectorsCRUDAndIsolation(t *testing.T) {
	ctx := context.Background()
	items := map[string]broker{"unrelated": {Alias: "unrelated"}, "karst-other-provider": {Alias: "karst-other-provider"}}
	var origin string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			json.NewEncoder(w).Encode(map[string]string{"issuer": origin, "authorization_endpoint": origin + "/authorize", "token_endpoint": origin + "/token", "jwks_uri": origin + "/keys"})
			return
		}
		require.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))
		const base = "/identity-provider/instances"
		if r.URL.Path == base && r.Method == http.MethodGet {
			all := []broker{}
			for _, b := range items {
				all = append(all, b)
			}
			json.NewEncoder(w).Encode(all)
			return
		}
		if r.Method == http.MethodPost {
			var b broker
			require.NoError(t, json.NewDecoder(r.Body).Decode(&b))
			items[b.Alias] = b
			w.WriteHeader(201)
			return
		}
		id := r.URL.Path[len(base)+1:]
		b, ok := items[id]
		if !ok {
			w.WriteHeader(404)
			return
		}
		switch r.Method {
		case http.MethodGet:
			json.NewEncoder(w).Encode(b)
		case http.MethodPut:
			require.NoError(t, json.NewDecoder(r.Body).Decode(&b))
			items[id] = b
			w.WriteHeader(204)
		case http.MethodDelete:
			delete(items, id)
			w.WriteHeader(204)
		}
	}))
	defer srv.Close()
	origin = srv.URL
	credentials := &KeycloakCredentials{jwtToken: JWTToken{AccessToken: "test-token", expiresInTime: time.Now().Add(time.Hour)}}
	m := (&KeycloakManager{adminEndpoint: origin, httpClient: srv.Client(), credentials: credentials}).ConnectorsForAccount("account")
	c, err := m.CreateConnector(ctx, &dex.ConnectorConfig{ID: "example", Type: "oidc", Name: "Example", Issuer: origin, ClientID: "client", ClientSecret: "secret"})
	require.NoError(t, err)
	require.Equal(t, "karst-account-example", c.ID)
	list, err := m.ListConnectors(ctx)
	require.NoError(t, err)
	require.Len(t, list, 1)
	require.Empty(t, list[0].ClientSecret)
	require.Equal(t, origin+"/keys", items[c.ID].Config["jwksUrl"])
	c.Name = "Updated"
	c.ClientSecret = "rotated"
	require.NoError(t, m.UpdateConnector(ctx, c))
	require.Equal(t, "rotated", items[c.ID].Config["clientSecret"])
	_, err = m.GetConnector(ctx, "karst-other-provider")
	require.ErrorIs(t, err, storage.ErrNotFound)
	require.ErrorIs(t, m.DeleteConnector(ctx, "unrelated"), storage.ErrNotFound)
	require.NoError(t, m.DeleteConnector(ctx, c.ID))
	require.Len(t, items, 2)
}
