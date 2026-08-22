// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/karst/audit"
	"github.com/netbirdio/netbird/management/internals/karst/bedrock"
	"github.com/netbirdio/netbird/management/internals/karst/node"
	karstpolicy "github.com/netbirdio/netbird/management/internals/karst/policy"
	"github.com/netbirdio/netbird/management/internals/karst/relayreg"
	"github.com/netbirdio/netbird/management/server/account"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/permissions/roles"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/auth"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

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

type scanAudit struct{}

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
		"handle-a": {Handle: "handle-a", PublicKey: []byte("identity-public-material"), KemPublicKey: []byte("kem-public-material"), DhPublicKey: []byte("dh-public-material"), CreatedAt: created},
	}, fakePeers{
		{Key: "fork-only-peer", Name: "not-karst", UserID: "user-a"},
		{Key: "handle-a", Name: "karst-node", UserID: "user-a", Status: &peer.PeerStatus{LastSeen: created}},
	}, nil, nil, nil, nil, nil, scanPermissions{role: types.UserRoleOwner}, router)

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
	RegisterEndpoints(fakeNodes{"handle-a": {Handle: "handle-a", PublicKey: []byte(secrets[0]), KemPublicKey: []byte(secrets[1]), DhPublicKey: []byte(secrets[2])}}, fakePeers{{Key: "handle-a", Name: "node", UserID: "user-a", SSHKey: secrets[2]}}, nil, nil, nil, nil, nil, scanPermissions{role: types.UserRoleOwner}, router)
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
	}, fakePeers{{Key: "handle-a", Name: "visible", UserID: "user-a"}}, nil, nil, nil, nil, nil, scanPermissions{role: types.UserRoleOwner}, router)

	req := httptest.NewRequest(http.MethodGet, "/karst/v1/nodes/handle-b", nil)
	req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{AccountId: "account-a", UserId: "user-a"})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, req)

	require.Equal(t, http.StatusNotFound, response.Code, response.Body.String())
}

func TestUserRoleIsDeniedByKarstAuthorization(t *testing.T) {
	router := mux.NewRouter()
	RegisterEndpoints(fakeNodes{}, fakePeers{}, nil, nil, nil, nil, nil, scanPermissions{role: types.UserRoleUser}, router)
	req := httptest.NewRequest(http.MethodGet, "/karst/v1/nodes", nil)
	req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{AccountId: "account-a", UserId: "user-a"})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, req)
	require.Equal(t, http.StatusForbidden, response.Code, response.Body.String())
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
	RegisterEndpoints(nodes, peers, nil, nil, scanPolicy{}, nil, nil, scanPermissions{role: types.UserRoleOwner}, router)
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

func TestBedrockEnforcingStaleAcknowledgementReturnsConflict(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:api-bedrock-409?mode=memory&cache=shared"), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	store, err := bedrock.NewStore(db)
	require.NoError(t, err)
	router := mux.NewRouter()
	RegisterEndpoints(fakeNodes{"node-a": {Handle: "node-a"}, "node-b": {Handle: "node-b"}}, fakePeers{{Key: "node-a", UserID: "user-a"}, {Key: "node-b", UserID: "user-a"}}, nil, nil, nil, nil, store, scanPermissions{role: types.UserRoleOwner}, router)
	req := httptest.NewRequest(http.MethodPut, "/karst/v1/bedrock/mode", strings.NewReader(`{"mode":"enforcing","acknowledged_cut_off_handles":["node-a"]}`))
	req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{AccountId: "account-a", UserId: "user-a"})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, req)
	require.Equal(t, http.StatusConflict, response.Code, response.Body.String())
	require.JSONEq(t, `{"code":"acknowledgement_mismatch","message":"bedrock: acknowledgement list does not match uncovered nodes: required [node-a node-b]","required_cut_off_handles":["node-a","node-b"]}`, response.Body.String())
}

func TestAllRegisteredResponsesExcludeSecretSentinels(t *testing.T) {
	secrets := []string{"scan-psk", "scan-disco", "scan-setup"}
	db, err := gorm.Open(sqlite.Open("file:api-scan?mode=memory&cache=shared"), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	bedrockStore, err := bedrock.NewStore(db)
	require.NoError(t, err)
	for _, role := range []types.UserRole{types.UserRoleOwner, types.UserRoleAdmin, types.UserRoleNetworkAdmin, types.UserRoleAuditor, types.UserRoleUser} {
		router := mux.NewRouter()
		RegisterEndpoints(fakeNodes{"handle-a": {Handle: "handle-a", PublicKey: []byte(secrets[0]), KemPublicKey: []byte(secrets[1]), DhPublicKey: []byte(secrets[2])}}, fakePeers{{ID: "peer-a", Key: "handle-a", Name: "node", UserID: "user-a", SSHKey: secrets[2]}}, nil, scanAudit{}, scanPolicy{}, scanRelays{}, bedrockStore, scanPermissions{role: role}, router)
		require.NoError(t, router.Walk(func(route *mux.Route, _ *mux.Router, _ []*mux.Route) error {
			template, err := route.GetPathTemplate()
			if err != nil || !strings.HasPrefix(template, "/karst/v1/") {
				return nil
			}
			methods, err := route.GetMethods()
			if err != nil {
				return err
			}
			path := strings.NewReplacer("{handle}", "handle-a", "{version}", "1", "{relayId}", "relay-a").Replace(template)
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
			}
			return nil
		}))
	}
}

// Every Karst route is discovered from mux rather than copied into this test.
// A route added without a KarstControl role entry therefore fails closed here.
func TestRoleMatrixCoversEveryKarstRoute(t *testing.T) {
	router := mux.NewRouter()
	RegisterEndpoints(fakeNodes{}, fakePeers{}, nil, nil, nil, nil, nil, scanPermissions{role: types.UserRoleOwner}, router)
	var routes []struct {
		method    string
		operation operations.Operation
	}
	require.NoError(t, router.Walk(func(route *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		template, err := route.GetPathTemplate()
		if err != nil || !strings.HasPrefix(template, "/karst/v1/") {
			return nil
		}
		methods, err := route.GetMethods()
		if err != nil {
			return err
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
