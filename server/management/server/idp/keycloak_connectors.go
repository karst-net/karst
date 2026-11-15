package idp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/dexidp/dex/storage"
	"github.com/netbirdio/netbird/idp/dex"
)

// KeycloakConnectors scopes Karst-managed brokers to one account. Other realm
// providers remain under Keycloak administration and are never overwritten.
type KeycloakConnectors struct {
	manager *KeycloakManager
	prefix  string
}

func (m *KeycloakManager) ConnectorsForAccount(account string) *KeycloakConnectors {
	return &KeycloakConnectors{m, "karst-" + account + "-"}
}

type broker struct {
	Alias       string            `json:"alias"`
	DisplayName string            `json:"displayName"`
	ProviderID  string            `json:"providerId"`
	Enabled     bool              `json:"enabled"`
	Config      map[string]string `json:"config"`
}

func (m *KeycloakConnectors) request(ctx context.Context, method, path string, value any, out any) error {
	token, err := m.manager.credentials.Authenticate(ctx)
	if err != nil {
		return err
	}
	var body bytes.Buffer
	if value != nil {
		if err := json.NewEncoder(&body).Encode(value); err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(m.manager.adminEndpoint, "/")+"/identity-provider/instances"+path, &body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := m.manager.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return storage.ErrNotFound
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("Keycloak identity provider request failed (HTTP %d)", resp.StatusCode)
	}
	if out != nil {
		return json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(out)
	}
	return nil
}
func (m *KeycloakConnectors) path(id string) (string, error) {
	if !strings.HasPrefix(id, m.prefix) || strings.ContainsAny(id, "/\\") {
		return "", storage.ErrNotFound
	}
	return "/" + url.PathEscape(id), nil
}
func (m *KeycloakConnectors) convert(b broker) *dex.ConnectorConfig {
	return &dex.ConnectorConfig{ID: b.Alias, Name: b.DisplayName, Type: b.Config["karstType"], Issuer: b.Config["issuer"], ClientID: b.Config["clientId"]}
}
func (m *KeycloakConnectors) ListConnectors(ctx context.Context) ([]*dex.ConnectorConfig, error) {
	var items []broker
	if err := m.request(ctx, http.MethodGet, "", nil, &items); err != nil {
		return nil, err
	}
	result := make([]*dex.ConnectorConfig, 0)
	for _, b := range items {
		if strings.HasPrefix(b.Alias, m.prefix) {
			result = append(result, m.convert(b))
		}
	}
	return result, nil
}
func (m *KeycloakConnectors) GetConnector(ctx context.Context, id string) (*dex.ConnectorConfig, error) {
	path, err := m.path(id)
	if err != nil {
		return nil, err
	}
	var b broker
	if err = m.request(ctx, http.MethodGet, path, nil, &b); err != nil {
		return nil, err
	}
	return m.convert(b), nil
}
func (m *KeycloakConnectors) representation(ctx context.Context, c *dex.ConnectorConfig) (broker, error) {
	b := broker{Alias: c.ID, DisplayName: c.Name, ProviderID: "oidc", Enabled: true, Config: map[string]string{"karstType": c.Type, "clientId": c.ClientID, "clientSecret": c.ClientSecret, "defaultScope": "openid profile email", "syncMode": "IMPORT", "validateSignature": "true", "useJwksUrl": "true"}}
	issuer := c.Issuer
	if c.Type == "google" {
		issuer = "https://accounts.google.com"
	}
	if c.Type == "microsoft" {
		issuer = "https://login.microsoftonline.com/common/v2.0"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(issuer, "/")+"/.well-known/openid-configuration", nil)
	if err != nil {
		return b, err
	}
	resp, err := m.manager.httpClient.Do(req)
	if err != nil {
		return b, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return b, fmt.Errorf("OIDC discovery failed (HTTP %d)", resp.StatusCode)
	}
	var discovery struct {
		Issuer        string `json:"issuer"`
		Authorization string `json:"authorization_endpoint"`
		Token         string `json:"token_endpoint"`
		UserInfo      string `json:"userinfo_endpoint"`
		JWKS          string `json:"jwks_uri"`
	}
	if err = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&discovery); err != nil {
		return b, err
	}
	if discovery.Issuer != issuer && c.Type != "microsoft" {
		return b, fmt.Errorf("OIDC discovery issuer mismatch")
	}
	if discovery.Authorization == "" || discovery.Token == "" || discovery.JWKS == "" {
		return b, fmt.Errorf("OIDC discovery is missing required endpoints")
	}
	b.Config["issuer"] = issuer
	b.Config["authorizationUrl"] = discovery.Authorization
	b.Config["tokenUrl"] = discovery.Token
	b.Config["userInfoUrl"] = discovery.UserInfo
	b.Config["jwksUrl"] = discovery.JWKS
	return b, nil
}
func (m *KeycloakConnectors) CreateConnector(ctx context.Context, c *dex.ConnectorConfig) (*dex.ConnectorConfig, error) {
	c.ID = m.prefix + c.ID
	b, err := m.representation(ctx, c)
	if err != nil {
		return nil, err
	}
	if err = m.request(ctx, http.MethodPost, "", b, nil); err != nil {
		return nil, err
	}
	return c, nil
}
func (m *KeycloakConnectors) UpdateConnector(ctx context.Context, c *dex.ConnectorConfig) error {
	path, err := m.path(c.ID)
	if err != nil {
		return err
	}
	existing, err := m.GetConnector(ctx, c.ID)
	if err != nil {
		return err
	}
	if existing.Type != c.Type {
		return fmt.Errorf("identity provider type cannot change")
	}
	b, err := m.representation(ctx, c)
	if err != nil {
		return err
	}
	return m.request(ctx, http.MethodPut, path, b, nil)
}
func (m *KeycloakConnectors) DeleteConnector(ctx context.Context, id string) error {
	path, err := m.path(id)
	if err != nil {
		return err
	}
	return m.request(ctx, http.MethodDelete, path, nil, nil)
}
