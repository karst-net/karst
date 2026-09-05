// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/karst/audit"
	"github.com/netbirdio/netbird/management/internals/karst/bedrock"
	"github.com/netbirdio/netbird/management/internals/karst/identity"
	"github.com/netbirdio/netbird/management/internals/karst/node"
	karstpolicy "github.com/netbirdio/netbird/management/internals/karst/policy"
	"github.com/netbirdio/netbird/management/internals/karst/relayreg"
	"github.com/netbirdio/netbird/management/internals/karst/turncred"
	"github.com/netbirdio/netbird/management/server/account"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/permissions/roles"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/auth"
	"github.com/netbirdio/netbird/shared/management/status"
	"gopkg.in/yaml.v3"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// karstOpenAPISchemas is deliberately a small, strict response-field checker.
// OpenAPI permits undeclared extra fields by default, but Karst does not: an
// undeclared response field is invisible to generated clients and is contract
// drift. This test guard catches that class while keeping the schema as the
// source of truth rather than maintaining a second response model in tests.
type karstOpenAPISchemas struct {
	Paths      map[string]map[string]any `yaml:"paths"`
	Components struct {
		Schemas map[string]map[string]any `yaml:"schemas"`
	} `yaml:"components"`
}

func loadKarstOpenAPISchemas(t *testing.T) karstOpenAPISchemas {
	t.Helper()
	path := filepath.Join("shared", "management", "http", "api", "karst-openapi.yml")
	contents, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		path = filepath.Join("..", "..", "..", "..", "shared", "management", "http", "api", "karst-openapi.yml")
		contents, err = os.ReadFile(path)
	}
	require.NoError(t, err)
	var spec karstOpenAPISchemas
	require.NoError(t, yaml.Unmarshal(contents, &spec))
	return spec
}

func responseSchema(spec karstOpenAPISchemas, path, method, status string) map[string]any {
	operation, ok := spec.Paths[path][strings.ToLower(method)].(map[string]any)
	if !ok {
		return nil
	}
	responses, _ := operation["responses"].(map[string]any)
	response, _ := responses[status].(map[string]any)
	content, _ := response["content"].(map[string]any)
	jsonContent, _ := content["application/json"].(map[string]any)
	schema, _ := jsonContent["schema"].(map[string]any)
	return schema
}

func assertDeclaredResponseFields(t *testing.T, spec karstOpenAPISchemas, schema map[string]any, value any, where string) {
	t.Helper()
	if reference, ok := schema["$ref"].(string); ok {
		schema = spec.Components.Schemas[strings.TrimPrefix(reference, "#/components/schemas/")]
	}
	object, ok := value.(map[string]any)
	if !ok {
		return
	}
	properties := schemaProperties(spec, schema)
	for key, child := range object {
		childSchema, declared := properties[key].(map[string]any)
		require.Truef(t, declared, "%s returns undeclared field %q", where, key)
		if nested, ok := child.(map[string]any); ok {
			assertDeclaredResponseFields(t, spec, childSchema, nested, where+"."+key)
		}
		if values, ok := child.([]any); ok {
			itemSchema, _ := childSchema["items"].(map[string]any)
			for _, item := range values {
				assertDeclaredResponseFields(t, spec, itemSchema, item, where+"."+key)
			}
		}
	}
}

func schemaProperties(spec karstOpenAPISchemas, schema map[string]any) map[string]any {
	if reference, ok := schema["$ref"].(string); ok {
		schema = spec.Components.Schemas[strings.TrimPrefix(reference, "#/components/schemas/")]
	}
	properties, _ := schema["properties"].(map[string]any)
	result := make(map[string]any, len(properties))
	for key, value := range properties {
		result[key] = value
	}
	allOf, _ := schema["allOf"].([]any)
	for _, item := range allOf {
		child, _ := item.(map[string]any)
		for key, value := range schemaProperties(spec, child) {
			result[key] = value
		}
	}
	return result
}

type fakeNodes map[string]*node.Identity

func (f fakeNodes) Get(handle string) (*node.Identity, error) {
	identity, ok := f[handle]
	if !ok {
		return nil, node.ErrUnknownNode
	}
	return identity, nil
}

func (f fakeNodes) SessionObservations(string) ([]node.SessionObservation, error) { return nil, nil }
func (f fakeNodes) AllSessionObservations() ([]node.SessionObservation, error)    { return nil, nil }
func (fakeNodes) BindEnrollmentKey(string, string) error                          { return nil }
func (f fakeNodes) All() ([]node.Identity, error) {
	items := make([]node.Identity, 0, len(f))
	for _, identity := range f {
		items = append(items, *identity)
	}
	return items, nil
}

type fakePeers []*peer.Peer

func (f fakePeers) GetPeers(_ context.Context, _, _, _, _ string) ([]*peer.Peer, error) {
	return f, nil
}

type fakeOwnDevices struct{ peers fakePeers }

func (f fakeOwnDevices) GetPeers(_ context.Context, _, userID, _, _ string) ([]*peer.Peer, error) {
	owned := make([]*peer.Peer, 0, len(f.peers))
	for _, item := range f.peers {
		if item.UserID == userID {
			owned = append(owned, item)
		}
	}
	return owned, nil
}

func (f fakeOwnDevices) UpdatePeer(_ context.Context, _, _ string, p *peer.Peer) (*peer.Peer, error) {
	return p, nil
}
func (f fakeOwnDevices) DeletePeer(context.Context, string, string, string) error { return nil }
func (f fakeOwnDevices) RenameOwnPeer(_ context.Context, _, userID, peerID, name string) (*peer.Peer, error) {
	for _, item := range f.peers {
		if item.ID == peerID && item.UserID == userID {
			copy := *item
			copy.Name = name
			return &copy, nil
		}
	}
	return nil, status.Errorf(status.NotFound, "peer not found")
}
func (f fakeOwnDevices) DeleteOwnPeer(_ context.Context, _, peerID, userID string) error {
	for _, item := range f.peers {
		if item.ID == peerID && item.UserID == userID {
			return nil
		}
	}
	return status.Errorf(status.NotFound, "peer not found")
}
func (f fakeOwnDevices) PortalPeers(context.Context, string) ([]*peer.Peer, error) {
	return f.peers, nil
}

type enrollmentWriter struct {
	fakeOwnDevices
	got *struct {
		keyType   types.SetupKeyType
		expiry    time.Duration
		limit     int
		user      string
		ephemeral bool
	}
}

func (w enrollmentWriter) CreateSetupKey(_ context.Context, _ string, _ string, keyType types.SetupKeyType, expiry time.Duration, _ []string, limit int, user string, ephemeral bool, _ bool) (*types.SetupKey, error) {
	*w.got = struct {
		keyType   types.SetupKeyType
		expiry    time.Duration
		limit     int
		user      string
		ephemeral bool
	}{keyType, expiry, limit, user, ephemeral}
	expires := time.Now().UTC().Add(expiry)
	return &types.SetupKey{Key: "one-time-key", Type: keyType, UsageLimit: limit, ExpiresAt: &expires}, nil
}

type portalPolicy struct{ version karstpolicy.Version }

func (p portalPolicy) Current(context.Context) (*karstpolicy.Version, error) { return &p.version, nil }
func (p portalPolicy) Write(context.Context, string, string, uint64) (*karstpolicy.Version, error) {
	return &p.version, nil
}
func (p portalPolicy) Get(context.Context, uint64) (*karstpolicy.Version, error) {
	return &p.version, nil
}
func (p portalPolicy) List(context.Context, int, int) ([]karstpolicy.Version, error) {
	return []karstpolicy.Version{p.version}, nil
}

type scanAudit struct{}

func (scanAudit) Append(context.Context, string, string, string, string) (*audit.Entry, error) {
	return &audit.Entry{}, nil
}
func (scanAudit) Head(context.Context) (uint64, string, error)          { return 0, "", audit.ErrEmpty }
func (scanAudit) Verify(context.Context) (uint64, error)                { return 0, nil }
func (scanAudit) List(context.Context, int, int) ([]audit.Entry, error) { return nil, nil }
func (scanAudit) ListFiltered(context.Context, string, string, int, int) ([]audit.Entry, error) {
	return nil, nil
}
func (scanAudit) ListBefore(context.Context, uint64, int) ([]audit.Entry, error) {
	return nil, nil
}
func (scanAudit) AddSink(context.Context, string, string) (*audit.Sink, error) {
	return &audit.Sink{ID: "sink"}, nil
}

type exportAudit struct{ entries []audit.Entry }

func (exportAudit) Append(context.Context, string, string, string, string) (*audit.Entry, error) {
	return &audit.Entry{}, nil
}
func (a exportAudit) Head(context.Context) (uint64, string, error) { return 1, "head", nil }
func (a exportAudit) Verify(context.Context) (uint64, error)       { return 1, nil }
func (a exportAudit) List(context.Context, int, int) ([]audit.Entry, error) {
	return a.entries, nil
}
func (a exportAudit) ListFiltered(context.Context, string, string, int, int) ([]audit.Entry, error) {
	return a.entries, nil
}
func (a exportAudit) ListBefore(_ context.Context, before uint64, _ int) ([]audit.Entry, error) {
	if before != 0 {
		return nil, nil
	}
	return a.entries, nil
}
func (exportAudit) AddSink(context.Context, string, string) (*audit.Sink, error) {
	return &audit.Sink{ID: "sink"}, nil
}

type scanPolicy struct{}

func (scanPolicy) Current(context.Context) (*karstpolicy.Version, error) {
	return nil, karstpolicy.ErrNoVersion
}
func (scanPolicy) Write(context.Context, string, string, uint64) (*karstpolicy.Version, error) {
	return &karstpolicy.Version{}, nil
}
func (scanPolicy) Get(context.Context, uint64) (*karstpolicy.Version, error) {
	return nil, karstpolicy.ErrNoVersion
}
func (scanPolicy) List(context.Context, int, int) ([]karstpolicy.Version, error) { return nil, nil }

type scanRelays struct{}

func (scanRelays) List(context.Context) ([]relayreg.StoredRelay, error) { return nil, nil }
func (scanRelays) Create(context.Context, relayreg.Entry) (*relayreg.StoredRelay, error) {
	return &relayreg.StoredRelay{}, nil
}
func (scanRelays) Delete(context.Context, string) error { return nil }

type scanTurns struct{}

func (scanTurns) List(context.Context) ([]turncred.StoredTurnServer, error) { return nil, nil }
func (scanTurns) Create(context.Context, turncred.Entry) (*turncred.StoredTurnServer, error) {
	return &turncred.StoredTurnServer{}, nil
}
func (scanTurns) Delete(context.Context, string) error { return nil }

type scanPermissions struct{ role types.UserRole }

func (p scanPermissions) ValidateUserPermissions(ctx context.Context, _, _ string, _ modules.Module, operation operations.Operation) (bool, context.Context, error) {
	return roles.RolesMap[p.role].Permissions[modules.KarstControl][operation], ctx, nil
}
func (p scanPermissions) ValidateRoleModuleAccess(_ context.Context, _ string, role roles.RolePermissions, module modules.Module, operation operations.Operation) bool {
	return role.Permissions[module][operation]
}
func (scanPermissions) ValidateAccountAccess(ctx context.Context, _ string, _ *types.User, _ bool) (context.Context, error) {
	return ctx, nil
}
func (scanPermissions) GetPermissionsByRole(_ context.Context, role types.UserRole) (roles.Permissions, error) {
	return roles.RolesMap[role].Permissions, nil
}
func (scanPermissions) SetAccountManager(account.Manager) {}

var _ permissions.Manager = scanPermissions{}

func TestListNodes_OnlyEnrolledNodesAndNoKeyMaterial(t *testing.T) {
	created := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	router := mux.NewRouter()
	RegisterEndpoints(fakeNodes{
		"handle-a": {Handle: "handle-a", PublicKey: []byte("identity-public-material"), KemPublicKey: []byte("kem-public-material"), CreatedAt: created},
	}, fakePeers{
		{Key: "fork-only-peer", Name: "not-karst", UserID: "user-a"},
		{Key: "handle-a", Name: "karst-node", UserID: "user-a", Status: &peer.PeerStatus{LastSeen: created}},
	}, nil, nil, nil, nil, nil, nil, nil, scanPermissions{role: types.UserRoleOwner}, router)

	req := httptest.NewRequest(http.MethodGet, "/karst/v1/nodes?limit=1", nil)
	req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{AccountId: "account-a", UserId: "user-a"})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, req)

	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	require.NotContains(t, response.Body.String(), "public_key")
	require.NotContains(t, response.Body.String(), "kem_public_key")
	require.NotContains(t, response.Body.String(), "dh_public_key")

	var page nodePage
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &page))
	require.Len(t, page.Items, 1)
	require.Equal(t, "handle-a", page.Items[0].Handle)
	require.Equal(t, "unknown", page.Items[0].Posture.Status)
	require.Nil(t, page.NextCursor)
}

// A REST response is a plaintext boundary. Seed material that resembles the
// three classes of secret prohibited by the contract and make the list/detail
// handlers prove that their join structs cannot accidentally serialize it.
func TestNodeResponsesNeverContainSecretFixtureMaterial(t *testing.T) {
	secrets := []string{"known-psk-fixture-bytes", "known-disco-fixture-bytes", "known-setup-key-fixture-bytes"}
	router := mux.NewRouter()
	RegisterEndpoints(fakeNodes{"handle-a": {Handle: "handle-a", PublicKey: []byte(secrets[0]), KemPublicKey: []byte(secrets[1])}}, fakePeers{{Key: "handle-a", Name: "node", UserID: "user-a", SSHKey: secrets[2]}}, nil, nil, nil, nil, nil, nil, nil, scanPermissions{role: types.UserRoleOwner}, router)
	for _, path := range []string{"/karst/v1/nodes", "/karst/v1/nodes/handle-a"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{AccountId: "account-a", UserId: "user-a"})
		response := httptest.NewRecorder()
		router.ServeHTTP(response, req)
		require.Equal(t, http.StatusOK, response.Code, response.Body.String())
		for _, secret := range secrets {
			require.NotContains(t, response.Body.String(), secret, path)
		}
	}
}

func TestGetNode_HidesNodesOutsideAuthorizedPeerSet(t *testing.T) {
	router := mux.NewRouter()
	RegisterEndpoints(fakeNodes{
		"handle-a": {Handle: "handle-a"},
		"handle-b": {Handle: "handle-b"},
	}, fakePeers{{Key: "handle-a", Name: "visible", UserID: "user-a"}}, nil, nil, nil, nil, nil, nil, nil, scanPermissions{role: types.UserRoleOwner}, router)

	req := httptest.NewRequest(http.MethodGet, "/karst/v1/nodes/handle-b", nil)
	req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{AccountId: "account-a", UserId: "user-a"})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, req)

	require.Equal(t, http.StatusNotFound, response.Code, response.Body.String())
}

func TestUserRoleIsDeniedByKarstAuthorization(t *testing.T) {
	router := mux.NewRouter()
	RegisterEndpoints(fakeNodes{}, fakePeers{}, nil, nil, nil, nil, nil, nil, nil, scanPermissions{role: types.UserRoleUser}, router)
	req := httptest.NewRequest(http.MethodGet, "/karst/v1/nodes", nil)
	req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{AccountId: "account-a", UserId: "user-a"})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, req)
	require.Equal(t, http.StatusForbidden, response.Code, response.Body.String())
}

// The member hostility test walks the same router that production serves. A
// newly-added admin route therefore cannot silently become usable by Members.
func TestMemberCannotUseAnyAdminRouteButCanUseOwnPortal(t *testing.T) {
	router := mux.NewRouter()
	RegisterEndpoints(fakeNodes{"handle-a": {Handle: "handle-a"}}, fakePeers{{ID: "peer-a", Key: "handle-a", Name: "mine", UserID: "user-a"}}, nil, nil, nil, nil, nil, nil, nil, scanPermissions{role: types.UserRoleUser}, router)
	require.NoError(t, router.Walk(func(route *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		template, err := route.GetPathTemplate()
		if err != nil || !strings.HasPrefix(template, "/karst/v1/") || strings.HasPrefix(template, "/karst/v1/me/") {
			return nil
		}
		methods, err := route.GetMethods()
		if err != nil {
			return nil
		}
		for _, method := range methods {
			if method == http.MethodOptions {
				continue
			}
			path := strings.NewReplacer("{handle}", "handle-a", "{version}", "1", "{relayId}", "relay-a", "{turnId}", "turn-a").Replace(template)
			req := httptest.NewRequest(method, path, strings.NewReader(`{}`))
			req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{AccountId: "account-a", UserId: "user-a"})
			response := httptest.NewRecorder()
			router.ServeHTTP(response, req)
			require.Equalf(t, http.StatusForbidden, response.Code, "member %s %s", method, template)
		}
		return nil
	}))
	request := httptest.NewRequest(http.MethodGet, "/karst/v1/me/devices", nil)
	request = nbcontext.SetUserAuthInRequest(request, auth.UserAuth{AccountId: "account-a", UserId: "user-a"})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	require.Equal(t, http.StatusOK, response.Code)
	// There is no user id in a /me path. A guessed device handle is a 404, not
	// a disclosure that a different user's device exists.
	request = httptest.NewRequest(http.MethodDelete, "/karst/v1/me/devices/someone-elses-device", nil)
	request = nbcontext.SetUserAuthInRequest(request, auth.UserAuth{AccountId: "account-a", UserId: "user-a"})
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	require.Equal(t, http.StatusNotFound, response.Code)
}

func TestMemberPortalCanRenameAndRevokeOnlyOwnDevice(t *testing.T) {
	devices := fakePeers{{ID: "mine", Key: "handle-a", Name: "old", UserID: "user-a", Meta: peer.PeerSystemMeta{GoOS: "linux"}}, {ID: "theirs", Key: "handle-b", Name: "other", UserID: "user-b", Meta: peer.PeerSystemMeta{GoOS: "windows"}}}
	ownedDevices := fakeOwnDevices{peers: devices}
	router := mux.NewRouter()
	RegisterEndpoints(fakeNodes{"handle-a": {Handle: "handle-a"}, "handle-b": {Handle: "handle-b"}}, ownedDevices, ownedDevices, nil, nil, nil, nil, nil, nil, scanPermissions{role: types.UserRoleUser}, router)
	list := httptest.NewRequest(http.MethodGet, "/karst/v1/me/devices", nil)
	list = nbcontext.SetUserAuthInRequest(list, auth.UserAuth{AccountId: "account-a", UserId: "user-a"})
	listResponse := httptest.NewRecorder()
	router.ServeHTTP(listResponse, list)
	require.Equal(t, http.StatusOK, listResponse.Code, listResponse.Body.String())
	require.JSONEq(t, `[{"handle":"handle-a","name":"old","platform":"linux","last_seen_at":null}]`, listResponse.Body.String())
	for _, tc := range []struct {
		method, path, body string
		want               int
	}{
		{http.MethodPatch, "/karst/v1/me/devices/handle-a", `{"name":"new"}`, http.StatusOK},
		{http.MethodDelete, "/karst/v1/me/devices/handle-a", "", http.StatusNoContent},
		{http.MethodPatch, "/karst/v1/me/devices/handle-b", `{"name":"nope"}`, http.StatusNotFound},
		{http.MethodDelete, "/karst/v1/me/devices/handle-b", "", http.StatusNotFound},
	} {
		req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{AccountId: "account-a", UserId: "user-a"})
		response := httptest.NewRecorder()
		router.ServeHTTP(response, req)
		require.Equal(t, tc.want, response.Code, tc.method+" "+tc.path)
	}
}

func TestMemberAccessExplainsCompiledDestinationWithRuleAndGroup(t *testing.T) {
	devices := fakePeers{{ID: "mine", Key: "handle-a", Name: "laptop", UserID: "user-a"}, {ID: "database", Key: "handle-b", Name: "db-prod", UserID: "user-b"}}
	policy := portalPolicy{version: karstpolicy.Version{Version: 4, Author: "alice@example.test", CreatedAt: time.Date(2026, 8, 12, 0, 0, 0, 0, time.UTC), Document: `{"groups":{"group:sre":["user-a"],"group:db":["user-b"]},"acls":[{"action":"accept","src":["group:sre"],"dst":["group:db:5432"]}]}`}}
	router := mux.NewRouter()
	RegisterEndpoints(fakeNodes{"handle-a": {Handle: "handle-a"}, "handle-b": {Handle: "handle-b"}}, devices, fakeOwnDevices{peers: devices}, nil, policy, nil, nil, nil, nil, scanPermissions{role: types.UserRoleUser}, router)
	req := httptest.NewRequest(http.MethodGet, "/karst/v1/me/access", nil)
	req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{AccountId: "account-a", UserId: "user-a"})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, req)
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	var items []struct {
		Destination, Group string
		Rule               int
	}
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &items))
	require.Equal(t, []struct {
		Destination, Group string
		Rule               int
	}{{Destination: "db-prod:5432", Group: "group:sre", Rule: 1}}, items)
}

func TestMemberEnrollmentIssuesShortLivedSingleUseKey(t *testing.T) {
	devices := fakePeers{{ID: "mine", Key: "handle-a", UserID: "user-a"}}
	got := &struct {
		keyType   types.SetupKeyType
		expiry    time.Duration
		limit     int
		user      string
		ephemeral bool
	}{}
	router := mux.NewRouter()
	RegisterEndpoints(fakeNodes{}, devices, enrollmentWriter{fakeOwnDevices: fakeOwnDevices{peers: devices}, got: got}, nil, nil, nil, nil, nil, nil, scanPermissions{role: types.UserRoleUser}, router)
	req := httptest.NewRequest(http.MethodPost, "/karst/v1/me/devices/enroll", nil)
	req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{AccountId: "account-a", UserId: "user-a"})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, req)
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	require.Equal(t, types.SetupKeyOneOff, got.keyType)
	require.Equal(t, 15*time.Minute, got.expiry)
	require.Equal(t, 1, got.limit)
	require.Equal(t, "user-a", got.user)
	require.False(t, got.ephemeral)
}

func TestFilterPostureRows_OnlyReturnsRequestedPosture(t *testing.T) {
	rows := []node.SessionObservation{{PeerHandle: "a"}, {PeerHandle: "b", LatticeOnly: true}, {PeerHandle: "c", LatticeOnly: true}}
	filtered := filterPostureRows(rows, "lattice_only")
	require.Len(t, filtered, 2)
	require.Equal(t, "b", filtered[0].PeerHandle)
	require.Equal(t, "c", filtered[1].PeerHandle)
}

func TestPolicyPreviewCompilesFiftyNodesUnderOneSecond(t *testing.T) {
	nodes := make(fakeNodes, 50)
	peers := make(fakePeers, 0, 50)
	for i := 0; i < 50; i++ {
		handle := fmt.Sprintf("node-%02d", i)
		nodes[handle] = &node.Identity{Handle: handle}
		peers = append(peers, &peer.Peer{Key: handle, Name: handle, UserID: fmt.Sprintf("user-%02d@example.test", i)})
	}
	router := mux.NewRouter()
	RegisterEndpoints(nodes, peers, nil, nil, scanPolicy{}, nil, nil, nil, nil, scanPermissions{role: types.UserRoleOwner}, router)
	req := httptest.NewRequest(http.MethodPost, "/karst/v1/policy/preview", strings.NewReader(`{"document":"{\"acls\":[{\"action\":\"accept\",\"src\":[\"*\"],\"dst\":[\"*:443\"]}]}"}`))
	req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{AccountId: "account-a", UserId: "user-a"})
	started := time.Now()
	response := httptest.NewRecorder()
	router.ServeHTTP(response, req)
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	require.Less(t, time.Since(started), time.Second)
	var result struct {
		Added []policyFlow `json:"added"`
	}
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &result))
	// A wildcard remains one concrete compiler flow per source rather than
	// being expanded into a quadratic presentation-only set.
	require.Len(t, result.Added, 50)
}

func TestBedrockEnforcingStaleacknowledgmentReturnsConflict(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:api-bedrock-409?mode=memory&cache=shared"), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	store, err := bedrock.NewStore(db)
	require.NoError(t, err)
	router := mux.NewRouter()
	RegisterEndpoints(fakeNodes{"node-a": {Handle: "node-a"}, "node-b": {Handle: "node-b"}}, fakePeers{{Key: "node-a", UserID: "user-a"}, {Key: "node-b", UserID: "user-a"}}, nil, nil, nil, nil, nil, store, nil, scanPermissions{role: types.UserRoleOwner}, router)
	req := httptest.NewRequest(http.MethodPut, "/karst/v1/bedrock/mode", strings.NewReader(`{"mode":"enforcing","acknowledged_cut_off_handles":["node-a"]}`))
	req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{AccountId: "account-a", UserId: "user-a"})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, req)
	require.Equal(t, http.StatusConflict, response.Code, response.Body.String())
	require.JSONEq(t, `{"code":"acknowledgment_mismatch","message":"bedrock: acknowledgment list does not match uncovered nodes: required [node-a node-b]","required_cut_off_handles":["node-a","node-b"]}`, response.Body.String())
}

// GET /bedrock must publish the same set PUT /bedrock/mode demands back. Without
// it a client has to guess the cut-off list from node liveness, which is a
// different set — coverage is a property of the signed log, not of whether a
// node is up — and so is a guaranteed 409. The field was returned but undeclared
// in karst-openapi.yml, which kept it out of the generated client entirely.
func TestBedrockStatusPublishesUncoveredHandles(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:api-bedrock-uncovered?mode=memory&cache=shared"), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	store, err := bedrock.NewStore(db)
	require.NoError(t, err)
	router := mux.NewRouter()
	RegisterEndpoints(fakeNodes{"node-a": {Handle: "node-a"}, "node-b": {Handle: "node-b"}}, fakePeers{{Key: "node-a", UserID: "user-a"}, {Key: "node-b", UserID: "user-a"}}, nil, nil, nil, nil, nil, store, nil, scanPermissions{role: types.UserRoleOwner}, router)
	req := httptest.NewRequest(http.MethodGet, "/karst/v1/bedrock", nil)
	req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{AccountId: "account-a", UserId: "user-a"})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, req)
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	var status struct {
		Mode      string   `json:"mode"`
		Uncovered []string `json:"uncovered_handles"`
	}
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &status))
	// Exactly what the 409 above says it requires.
	require.Equal(t, []string{"node-a", "node-b"}, status.Uncovered)
}

// This is the operator's actual ceremony, without test-only shortcuts: a root
// bootstraps the log, enrollment makes the node visible, the server exports a
// durable request, an authority signs it offline, and only then can enforcing
// mode be enabled without cutting the enrolled node off.
func TestBedrockOfflineCeremonyCoversEnrollmentBeforeEnforcing(t *testing.T) {
	ctx := context.Background()
	db, err := gorm.Open(sqlite.Open("file:api-bedrock-ceremony?mode=memory&cache=shared"), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	configuration, err := bedrock.NewStore(db)
	require.NoError(t, err)
	chain, err := bedrock.NewLog(db)
	require.NoError(t, err)
	auditLog, err := audit.New(db)
	require.NoError(t, err)

	root, err := bedrock.RootFromSeed(bytes.Repeat([]byte{0x11}, bedrock.RootSeedSize))
	require.NoError(t, err)
	authority, err := bedrock.AuthorityFromSeed(bytes.Repeat([]byte{0x22}, bedrock.AuthoritySeedSize))
	require.NoError(t, err)
	nodeKey, err := identity.FromSeed(bytes.Repeat([]byte{0x33}, identity.SeedSize))
	require.NoError(t, err)
	identityKey := nodeKey.Public()
	handle := node.Handle(identityKey)
	kem := bytes.Repeat([]byte{0x44}, bedrock.KemPublicKeySize)

	builder := bedrock.NewBuilder()
	genesis, input := builder.Prepare(1, bedrock.OpGenesis, bedrock.GenesisBody("test.karst.", [][]byte{root.Public()}, 1, [][]byte{authority.Public()}, 1, nil))
	rootSigs, err := bedrock.SignRoots(input, bedrock.RootSigner{Index: 0, Key: root})
	require.NoError(t, err)
	require.NoError(t, builder.Commit(genesis, rootSigs))

	router := mux.NewRouter()
	RegisterEndpoints(fakeNodes{handle: {Handle: handle, PublicKey: identityKey, KemPublicKey: kem}}, fakePeers{{Key: handle, UserID: "user-a"}}, nil, auditLog, nil, nil, nil, configuration, chain, scanPermissions{role: types.UserRoleOwner}, router)
	user := auth.UserAuth{AccountId: "account-a", UserId: "user-a"}
	bootstrapBody, err := json.Marshal(map[string]string{"format": "bedrock-log-v1", "payload": base64.StdEncoding.EncodeToString(bedrock.EncodeLog(builder.Entries()))})
	require.NoError(t, err)
	bootstrap := httptest.NewRequest(http.MethodPost, "/karst/v1/bedrock/bootstrap/import", bytes.NewReader(bootstrapBody))
	bootstrap = nbcontext.SetUserAuthInRequest(bootstrap, user)
	bootstrapped := httptest.NewRecorder()
	router.ServeHTTP(bootstrapped, bootstrap)
	require.Equal(t, http.StatusNoContent, bootstrapped.Code, bootstrapped.Body.String())

	export := httptest.NewRequest(http.MethodPost, "/karst/v1/bedrock/requests/export", nil)
	export = nbcontext.SetUserAuthInRequest(export, user)
	exported := httptest.NewRecorder()
	router.ServeHTTP(exported, export)
	require.Equal(t, http.StatusOK, exported.Code, exported.Body.String())
	var bundle struct{ Format, Payload string }
	require.NoError(t, json.Unmarshal(exported.Body.Bytes(), &bundle))
	require.Equal(t, "bedrock-signed-bundle-v1", bundle.Format)
	requestJSON, err := base64.StdEncoding.DecodeString(bundle.Payload)
	require.NoError(t, err)
	require.Contains(t, string(requestJSON), `"kind": "request"`)

	pending, err := chain.Pending(ctx, "account-a")
	require.NoError(t, err)
	require.NotNil(t, pending)
	entries, err := bedrock.DecodeLog(pending.Entries)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	var offlineResponse []byte
	if signer := os.Getenv("KARST_BEDROCK_BIN"); signer != "" {
		// This optional path is run by scripts/test_bedrock_vertical_slice.sh.
		// It proves the exact JSON bytes exported by this handler are accepted
		// by the independently-built offline signer, before its response comes
		// back through this API. The normal unit test remains self-contained.
		dir := t.TempDir()
		requestPath := filepath.Join(dir, "request.json")
		keyPath := filepath.Join(dir, "authority.key")
		responsePath := filepath.Join(dir, "response.json")
		require.NoError(t, os.WriteFile(requestPath, requestJSON, 0o600))
		require.NoError(t, os.WriteFile(keyPath, bytes.Repeat([]byte{0x22}, bedrock.AuthoritySeedSize), 0o600))
		command := exec.Command(signer, "sign", requestPath, keyPath, responsePath)
		command.Stdin = strings.NewReader("sign\n")
		output, runErr := command.CombinedOutput()
		require.NoErrorf(t, runErr, "offline signer failed: %s", output)
		offlineResponse, err = os.ReadFile(responsePath)
		require.NoError(t, err)
	} else {
		authoritySigs, err := bedrock.SignAuthorities(entries[0].SigningInput(genesis.Hash), bedrock.AuthoritySigner{Index: 0, Key: authority})
		require.NoError(t, err)
		offlineResponse, err = json.Marshal(map[string]any{
			"bundle": "bedrock-bundle-v1", "kind": "response",
			"signatures": []map[string]any{{"seq": entries[0].Seq, "signer_index": 0, "sig": hex.EncodeToString(authoritySigs[0].Sig)}},
		})
		require.NoError(t, err)
	}
	importBody, err := json.Marshal(map[string]string{"format": "bedrock-signed-bundle-v1", "payload": base64.StdEncoding.EncodeToString(offlineResponse)})
	require.NoError(t, err)
	importRequest := httptest.NewRequest(http.MethodPost, "/karst/v1/bedrock/responses/import", bytes.NewReader(importBody))
	importRequest = nbcontext.SetUserAuthInRequest(importRequest, user)
	imported := httptest.NewRecorder()
	router.ServeHTTP(imported, importRequest)
	require.Equal(t, http.StatusNoContent, imported.Code, imported.Body.String())

	statusRequest := httptest.NewRequest(http.MethodGet, "/karst/v1/bedrock", nil)
	statusRequest = nbcontext.SetUserAuthInRequest(statusRequest, user)
	statusResponse := httptest.NewRecorder()
	router.ServeHTTP(statusResponse, statusRequest)
	require.Equal(t, http.StatusOK, statusResponse.Code, statusResponse.Body.String())
	var state struct {
		Uncovered []string `json:"uncovered_handles"`
		Covered   int      `json:"covered_count"`
	}
	require.NoError(t, json.Unmarshal(statusResponse.Body.Bytes(), &state))
	require.Empty(t, state.Uncovered)
	require.Equal(t, 1, state.Covered)

	enforce := httptest.NewRequest(http.MethodPut, "/karst/v1/bedrock/mode", strings.NewReader(`{"mode":"enforcing","acknowledged_cut_off_handles":[]}`))
	enforce = nbcontext.SetUserAuthInRequest(enforce, user)
	enforced := httptest.NewRecorder()
	router.ServeHTTP(enforced, enforce)
	require.Equal(t, http.StatusOK, enforced.Code, enforced.Body.String())
	stored, err := configuration.Configuration(ctx, "account-a")
	require.NoError(t, err)
	require.Equal(t, bedrock.ModeEnforcing, stored.Mode)

	// The audit anchor is a second instance of the same offline authority
	// ceremony. It must cover a real, non-empty audit head and become
	// independently verifiable only after the signed response is imported.
	anchorExport := httptest.NewRequest(http.MethodPost, "/karst/v1/bedrock/audit-anchor/export", nil)
	anchorExport = nbcontext.SetUserAuthInRequest(anchorExport, user)
	anchored := httptest.NewRecorder()
	router.ServeHTTP(anchored, anchorExport)
	require.Equal(t, http.StatusOK, anchored.Code, anchored.Body.String())
	pending, err = chain.Pending(ctx, "account-a")
	require.NoError(t, err)
	require.NotNil(t, pending)
	anchorEntries, err := bedrock.DecodeLog(pending.Entries)
	require.NoError(t, err)
	require.Len(t, anchorEntries, 1)
	require.Equal(t, bedrock.OpAnchor, anchorEntries[0].Op)
	previousHead, _, err := chain.Head(ctx, "account-a")
	require.NoError(t, err)
	anchorSigs, err := bedrock.SignAuthorities(anchorEntries[0].SigningInput(previousHead), bedrock.AuthoritySigner{Index: 0, Key: authority})
	require.NoError(t, err)
	anchorResponse, err := json.Marshal(map[string]any{"bundle": "bedrock-bundle-v1", "kind": "response", "signatures": []map[string]any{{"seq": anchorEntries[0].Seq, "signer_index": 0, "sig": hex.EncodeToString(anchorSigs[0].Sig)}}})
	require.NoError(t, err)
	anchorImportBody, err := json.Marshal(map[string]string{"format": "bedrock-signed-bundle-v1", "payload": base64.StdEncoding.EncodeToString(anchorResponse)})
	require.NoError(t, err)
	anchorImport := httptest.NewRequest(http.MethodPost, "/karst/v1/bedrock/responses/import", bytes.NewReader(anchorImportBody))
	anchorImport = nbcontext.SetUserAuthInRequest(anchorImport, user)
	anchorImported := httptest.NewRecorder()
	router.ServeHTTP(anchorImported, anchorImport)
	require.Equal(t, http.StatusNoContent, anchorImported.Code, anchorImported.Body.String())
	anchorState, err := chain.State(ctx, "account-a")
	require.NoError(t, err)
	broken, err := bedrock.VerifyAnchored(ctx, anchorState, auditLog)
	require.NoError(t, err)
	require.Zero(t, broken)
	auditRequest := httptest.NewRequest(http.MethodGet, "/karst/v1/audit?limit=10", nil)
	auditRequest = nbcontext.SetUserAuthInRequest(auditRequest, user)
	auditResponse := httptest.NewRecorder()
	router.ServeHTTP(auditResponse, auditRequest)
	require.Equal(t, http.StatusOK, auditResponse.Code, auditResponse.Body.String())
	var auditPage struct {
		Anchor struct {
			Sequence    *int `json:"last_anchored_sequence"`
			Since       int  `json:"entries_since_anchor"`
			Contradicts bool `json:"contradicts_anchor"`
		} `json:"anchor"`
	}
	require.NoError(t, json.Unmarshal(auditResponse.Body.Bytes(), &auditPage))
	require.NotNil(t, auditPage.Anchor.Sequence)
	require.Equal(t, int(anchorState.Anchor.AuditSeq), *auditPage.Anchor.Sequence)
	require.GreaterOrEqual(t, auditPage.Anchor.Since, 0)
	// A real ceremony's anchor is written against the log it actually
	// commits to, so the endpoint's VerifyAnchored wiring (ADR-0016) must
	// find it intact rather than reporting a contradiction.
	require.False(t, auditPage.Anchor.Contradicts)
}

// The payoff of ADR-0016's audit-status wiring: a log whose anchor entry
// commits to a head the audit log never produced. VerifyAnchored exists
// specifically to catch this — a server that truncated or rewrote its audit
// log after anchoring it — and TestBedrockOfflineCeremonyCoversEnrollmentBeforeEnforcing
// above already covers the intact case.
func TestAuditListReportsAnchorContradiction(t *testing.T) {
	ctx := context.Background()
	db, err := gorm.Open(sqlite.Open("file:api-audit-anchor-contradiction?mode=memory&cache=shared"), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	chain, err := bedrock.NewLog(db)
	require.NoError(t, err)
	auditLog, err := audit.New(db)
	require.NoError(t, err)

	_, err = auditLog.Append(ctx, "admin", "test.action", "test/target", "")
	require.NoError(t, err)
	auditSeq, _, err := auditLog.Head(ctx)
	require.NoError(t, err)

	root, err := bedrock.RootFromSeed(bytes.Repeat([]byte{0x11}, bedrock.RootSeedSize))
	require.NoError(t, err)
	authority, err := bedrock.AuthorityFromSeed(bytes.Repeat([]byte{0x22}, bedrock.AuthoritySeedSize))
	require.NoError(t, err)

	builder := bedrock.NewBuilder()
	genesis, input := builder.Prepare(1, bedrock.OpGenesis, bedrock.GenesisBody("test.karst.", [][]byte{root.Public()}, 1, [][]byte{authority.Public()}, 1, nil))
	rootSigs, err := bedrock.SignRoots(input, bedrock.RootSigner{Index: 0, Key: root})
	require.NoError(t, err)
	require.NoError(t, builder.Commit(genesis, rootSigs))

	// An anchor entry the real audit log will never match: a fabricated head
	// hash at the log's real sequence.
	anchorEntry, input := builder.Prepare(2, bedrock.OpAnchor, bedrock.AnchorBody([]byte("fabricated-audit-head"), auditSeq))
	authSigs, err := bedrock.SignAuthorities(input, bedrock.AuthoritySigner{Index: 0, Key: authority})
	require.NoError(t, err)
	require.NoError(t, builder.Commit(anchorEntry, authSigs))

	// Imported directly rather than through the bootstrap-import endpoint,
	// which only accepts a single genesis entry — this test needs the anchor
	// entry in the store too, not just the genesis.
	require.NoError(t, chain.Import(ctx, "account-a", builder.Entries()))

	router := mux.NewRouter()
	RegisterEndpoints(fakeNodes{}, fakePeers{}, nil, auditLog, nil, nil, nil, nil, chain, scanPermissions{role: types.UserRoleOwner}, router)
	user := auth.UserAuth{AccountId: "account-a", UserId: "admin"}

	auditRequest := httptest.NewRequest(http.MethodGet, "/karst/v1/audit?limit=10", nil)
	auditRequest = nbcontext.SetUserAuthInRequest(auditRequest, user)
	auditResponse := httptest.NewRecorder()
	router.ServeHTTP(auditResponse, auditRequest)
	require.Equal(t, http.StatusOK, auditResponse.Code, auditResponse.Body.String())
	var auditPage struct {
		Anchor struct {
			Sequence    *int `json:"last_anchored_sequence"`
			Contradicts bool `json:"contradicts_anchor"`
		} `json:"anchor"`
	}
	require.NoError(t, json.Unmarshal(auditResponse.Body.Bytes(), &auditPage))
	require.NotNil(t, auditPage.Anchor.Sequence)
	require.Equal(t, int(auditSeq), *auditPage.Anchor.Sequence)
	require.True(t, auditPage.Anchor.Contradicts, "a fabricated anchor head must be reported as a contradiction")
}

func TestAllRegisteredResponsesExcludeSecretSentinels(t *testing.T) {
	secrets := []string{"scan-psk", "scan-disco", "scan-setup"}
	spec := loadKarstOpenAPISchemas(t)
	db, err := gorm.Open(sqlite.Open("file:api-scan?mode=memory&cache=shared"), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	bedrockStore, err := bedrock.NewStore(db)
	require.NoError(t, err)
	for _, role := range []types.UserRole{types.UserRoleOwner, types.UserRoleAdmin, types.UserRoleNetworkAdmin, types.UserRoleAuditor, types.UserRoleUser} {
		router := mux.NewRouter()
		RegisterEndpoints(fakeNodes{"handle-a": {Handle: "handle-a", PublicKey: []byte(secrets[0]), KemPublicKey: []byte(secrets[1])}}, fakePeers{{ID: "peer-a", Key: "handle-a", Name: "node", UserID: "user-a", SSHKey: secrets[2]}}, nil, scanAudit{}, scanPolicy{}, scanRelays{}, scanTurns{}, bedrockStore, nil, scanPermissions{role: role}, router)
		require.NoError(t, router.Walk(func(route *mux.Route, _ *mux.Router, _ []*mux.Route) error {
			template, err := route.GetPathTemplate()
			if err != nil || !strings.HasPrefix(template, "/karst/v1/") {
				return nil
			}
			methods, err := route.GetMethods()
			if err != nil {
				return nil // mux emits the /me subrouter prefix without methods.
			}
			path := strings.NewReplacer("{handle}", "handle-a", "{version}", "1", "{relayId}", "relay-a", "{turnId}", "turn-a").Replace(template)
			for _, method := range methods {
				if method == http.MethodOptions {
					continue
				}
				body := strings.NewReader(`{"document":"{\"acls\":[]}","mode":"off","acknowledged_cut_off_handles":[],"kind":"webhook","endpoint":"https://example.test"}`)
				req := httptest.NewRequest(method, path, body)
				req.Header.Set("If-Match", "0")
				req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{AccountId: "account-a", UserId: "user-a"})
				response := httptest.NewRecorder()
				router.ServeHTTP(response, req)
				for _, secret := range secrets {
					require.NotContainsf(t, response.Body.String(), secret, "%s %s %s", role, method, path)
				}
				if method != http.MethodGet || response.Code < http.StatusOK || response.Code >= http.StatusMultipleChoices || response.Body.Len() == 0 {
					continue
				}
				schema := responseSchema(spec, strings.TrimPrefix(template, "/karst/v1"), method, fmt.Sprint(response.Code))
				if schema == nil {
					continue // No JSON body is declared for this successful response.
				}
				var decoded any
				require.NoErrorf(t, json.Unmarshal(response.Body.Bytes(), &decoded), "%s %s", method, path)
				assertDeclaredResponseFields(t, spec, schema, decoded, method+" "+template)
			}
			return nil
		}))
	}
}

func TestAuditExportRequiresAndStreamsRequestedFormat(t *testing.T) {
	entries := []audit.Entry{{
		Seq:       7,
		CreatedAt: time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC),
		Actor:     "admin",
		Action:    "policy.write",
		Target:    "default",
		Detail:    "approved",
		PrevHash:  "previous",
		Hash:      "current",
	}}
	router := mux.NewRouter()
	RegisterEndpoints(fakeNodes{}, fakePeers{}, nil, exportAudit{entries: entries}, nil, nil, nil, nil, nil, scanPermissions{role: types.UserRoleAdmin}, router)
	request := func(query string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/karst/v1/audit/export"+query, nil)
		req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{AccountId: "account-a", UserId: "admin"})
		response := httptest.NewRecorder()
		router.ServeHTTP(response, req)
		return response
	}

	missing := request("")
	require.Equal(t, http.StatusUnprocessableEntity, missing.Code)

	jsonExport := request("?format=json")
	require.Equal(t, http.StatusOK, jsonExport.Code, jsonExport.Body.String())
	require.Contains(t, jsonExport.Header().Get("Content-Type"), "application/json")
	var got []map[string]any
	require.NoError(t, json.Unmarshal(jsonExport.Body.Bytes(), &got))
	require.Len(t, got, 1)
	require.Equal(t, float64(7), got[0]["sequence"])
	require.Equal(t, "current", got[0]["hash"])

	csvExport := request("?format=csv")
	require.Equal(t, http.StatusOK, csvExport.Code, csvExport.Body.String())
	require.Contains(t, csvExport.Header().Get("Content-Type"), "text/csv")
	require.Contains(t, csvExport.Header().Get("Content-Disposition"), "karst-audit.csv")
	require.Equal(t, "sequence,created_at,actor,action,target,detail,previous_hash,hash\n7,2026-08-28T12:00:00Z,admin,policy.write,default,approved,previous,current\n", csvExport.Body.String())
}

func TestSuccessfulMutationAppendsToTheAuditLog(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:audit-mutation?mode=memory&cache=shared"), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	auditLog, err := audit.New(db)
	require.NoError(t, err)
	router := mux.NewRouter()
	RegisterEndpoints(fakeNodes{}, fakePeers{}, nil, auditLog, nil, nil, nil, nil, nil, scanPermissions{role: types.UserRoleAdmin}, router)
	req := httptest.NewRequest(http.MethodPost, "/karst/v1/audit/sinks", strings.NewReader(`{"kind":"webhook","endpoint":"https://siem.example.test/ingest"}`))
	req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{AccountId: "account-a", UserId: "admin"})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, req)
	require.Equal(t, http.StatusCreated, response.Code, response.Body.String())
	entries, err := auditLog.List(context.Background(), 0, 10)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	require.Equal(t, "admin", entries[0].Actor)
	require.Equal(t, "karst.post", entries[0].Action)
	require.Equal(t, "audit/sinks", entries[0].Target)
}

// Every Karst route is discovered from mux rather than copied into this test.
// A route added without a KarstControl role entry therefore fails closed here.
func TestRoleMatrixCoversEveryKarstRoute(t *testing.T) {
	router := mux.NewRouter()
	RegisterEndpoints(fakeNodes{}, fakePeers{}, nil, nil, nil, nil, nil, nil, nil, scanPermissions{role: types.UserRoleOwner}, router)
	var routes []struct {
		method    string
		operation operations.Operation
	}
	require.NoError(t, router.Walk(func(route *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		template, err := route.GetPathTemplate()
		if err != nil || !strings.HasPrefix(template, "/karst/v1/") || strings.HasPrefix(template, "/karst/v1/me/") {
			return nil
		}
		methods, err := route.GetMethods()
		if err != nil {
			return nil // mux emits the /me subrouter prefix without methods.
		}
		for _, method := range methods {
			if method == http.MethodOptions {
				continue
			}
			operation := operationForRequest(method, template)
			routes = append(routes, struct {
				method    string
				operation operations.Operation
			}{method, operation})
		}
		return nil
	}))
	require.NotEmpty(t, routes)
	for _, role := range []types.UserRole{types.UserRoleOwner, types.UserRoleAdmin, types.UserRoleNetworkAdmin, types.UserRoleAuditor, types.UserRoleUser} {
		permissions, ok := roles.RolesMap[role].Permissions[modules.KarstControl]
		require.Truef(t, ok, "%s has no KarstControl permission entry", role)
		for _, route := range routes {
			allowed, listed := permissions[route.operation]
			require.Truef(t, listed, "%s %s has no %s matrix entry", role, route.method, route.operation)
			want := role == types.UserRoleOwner || role == types.UserRoleAdmin || role == types.UserRoleNetworkAdmin || (role == types.UserRoleAuditor && route.operation == operations.Read)
			require.Equalf(t, want, allowed, "%s %s permission", role, route.method)
		}
	}
}

// The DB-backed TURN registry's CRUD surface, driven against a real
// turncred.Store rather than a fake — list/create/delete happy path, a
// duplicate URI, and deleting a server that does not exist.
func TestTurnServerCRUD(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:api-turns?mode=memory&cache=shared"), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	require.NoError(t, db.Exec("DROP TABLE IF EXISTS karst_turn_servers").Error)
	store, err := turncred.NewStore(db)
	require.NoError(t, err)

	router := mux.NewRouter()
	RegisterEndpoints(fakeNodes{}, fakePeers{}, nil, nil, nil, nil, store, nil, nil, scanPermissions{role: types.UserRoleOwner}, router)
	user := auth.UserAuth{AccountId: "account-a", UserId: "admin"}

	doRequest := func(method, path, requestBody string) *httptest.ResponseRecorder {
		var reader *strings.Reader
		if requestBody != "" {
			reader = strings.NewReader(requestBody)
		} else {
			reader = strings.NewReader("")
		}
		req := httptest.NewRequest(method, path, reader)
		req = nbcontext.SetUserAuthInRequest(req, user)
		response := httptest.NewRecorder()
		router.ServeHTTP(response, req)
		return response
	}

	// An empty registry lists as an empty array, not an error.
	list := doRequest(http.MethodGet, "/karst/v1/turns", "")
	require.Equal(t, http.StatusOK, list.Code, list.Body.String())
	require.JSONEq(t, `[]`, list.Body.String())

	// Create round-trips with lowercase field names — the regression guard
	// for the relayreg.StoredRelay bug this package must not repeat.
	created := doRequest(http.MethodPost, "/karst/v1/turns", `{"uri":"turn:turn.example.test:3478","region":"eu"}`)
	require.Equal(t, http.StatusCreated, created.Code, created.Body.String())
	var turn struct {
		ID     string `json:"id"`
		URI    string `json:"uri"`
		Region string `json:"region"`
	}
	require.NoError(t, json.Unmarshal(created.Body.Bytes(), &turn))
	require.NotEmpty(t, turn.ID)
	require.Equal(t, "turn:turn.example.test:3478", turn.URI)
	require.Equal(t, "eu", turn.Region)

	list = doRequest(http.MethodGet, "/karst/v1/turns", "")
	require.Equal(t, http.StatusOK, list.Code, list.Body.String())
	require.Contains(t, list.Body.String(), `"turn:turn.example.test:3478"`)

	// A duplicate URI within the account is a precondition failure, not a
	// second row.
	duplicate := doRequest(http.MethodPost, "/karst/v1/turns", `{"uri":"turn:turn.example.test:3478","region":"us"}`)
	require.Equal(t, http.StatusPreconditionFailed, duplicate.Code, duplicate.Body.String())

	// Deleting an unknown id is a 404, and does not disturb the real row.
	missing := doRequest(http.MethodDelete, "/karst/v1/turns/does-not-exist", "")
	require.Equal(t, http.StatusNotFound, missing.Code, missing.Body.String())

	// Deleting the real row succeeds and is reflected in a subsequent list.
	deleted := doRequest(http.MethodDelete, "/karst/v1/turns/"+turn.ID, "")
	require.Equal(t, http.StatusNoContent, deleted.Code, deleted.Body.String())

	list = doRequest(http.MethodGet, "/karst/v1/turns", "")
	require.Equal(t, http.StatusOK, list.Code, list.Body.String())
	require.JSONEq(t, `[]`, list.Body.String())
}

// A router with no turn store configured answers every /turns route with a
// precondition failure rather than a panic or a silently empty registry.
func TestTurnServerRoutesRequireAConfiguredStore(t *testing.T) {
	router := mux.NewRouter()
	RegisterEndpoints(fakeNodes{}, fakePeers{}, nil, nil, nil, nil, nil, nil, nil, scanPermissions{role: types.UserRoleOwner}, router)
	user := auth.UserAuth{AccountId: "account-a", UserId: "admin"}

	req := httptest.NewRequest(http.MethodGet, "/karst/v1/turns", nil)
	req = nbcontext.SetUserAuthInRequest(req, user)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, req)
	require.Equal(t, http.StatusPreconditionFailed, response.Code, response.Body.String())
}
