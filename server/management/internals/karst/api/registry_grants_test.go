// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package api

import (
	"context"
	"github.com/gorilla/mux"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/shared/auth"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/netbirdio/netbird/management/internals/karst/policy"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/stretchr/testify/require"
)

type registryAccounts struct{ account *types.Account }

func (r registryAccounts) GetAccount(context.Context, string) (*types.Account, error) {
	return r.account, nil
}
func (r registryAccounts) UpdateAccountPeers(context.Context, string, types.UpdateReason) {}

func TestRegistryGrantReferencesAndPreviewMembership(t *testing.T) {
	account := &types.Account{Id: "a", Groups: map[string]*types.Group{"g": {ID: "g", AccountID: "a", Name: "Engineering", Peers: []string{"p"}}}, Peers: map[string]*nbpeer.Peer{"p": {ID: "p", AccountID: "a", Key: "laptop"}}}
	h := handler{accounts: registryAccounts{account}}
	valid := `{"grants":[{"id":"grant","name":"Web","source_groups":["g"],"target_nodes":["laptop"],"ports":"443"}]}`
	require.NoError(t, h.validateRegistryGrants(context.Background(), "a", valid))
	require.Error(t, h.validateRegistryGrants(context.Background(), "b", valid))
	require.Error(t, h.validateRegistryGrants(context.Background(), "a", `{"grants":[{"id":"grant","name":"Web","source_groups":["foreign"],"target_nodes":["laptop"],"ports":"443"}]}`))
	require.Error(t, h.validateRegistryGrants(context.Background(), "a", `{"grants":[{"id":"grant","name":"Web","source_groups":["g"],"target_nodes":["foreign"],"ports":"443"}]}`))
	nodes := []policy.Node{{Handle: "laptop"}, {Handle: "outsider"}}
	require.NoError(t, h.addRegistryMembership(context.Background(), "a", nodes))
	require.Equal(t, []string{"g"}, nodes[0].GroupIDs)
	require.Empty(t, nodes[1].GroupIDs)
	account.Groups["g"].Peers = nil
	require.NoError(t, h.addRegistryMembership(context.Background(), "a", nodes))
	require.Empty(t, nodes[0].GroupIDs)
}

type registryRollbackPolicy struct {
	scanPolicy
	document string
	writes   int
}

func (p *registryRollbackPolicy) Get(context.Context, uint64) (*policy.Version, error) {
	return &policy.Version{Version: 1, Document: p.document}, nil
}
func (p *registryRollbackPolicy) Write(context.Context, string, string, uint64) (*policy.Version, error) {
	p.writes++
	return &policy.Version{}, nil
}

func TestPolicyRollbackRejectsDeletedGroup(t *testing.T) {
	p := &registryRollbackPolicy{document: `{"grants":[{"id":"web","name":"Web","source_groups":["deleted"],"target_groups":["servers"],"ports":"443"}]}`}
	h := handler{policy: p, accounts: registryAccounts{&types.Account{Id: "a", Groups: map[string]*types.Group{"servers": {ID: "servers", AccountID: "a"}}}}}
	req := httptest.NewRequest(http.MethodPost, "/policy/rollback/1", nil)
	req = mux.SetURLVars(req, map[string]string{"version": "1"})
	req.Header.Set("If-Match", `"1"`)
	req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{AccountId: "a", UserId: "admin"})
	response := httptest.NewRecorder()
	h.policyRollback(response, req)
	require.Equal(t, http.StatusUnprocessableEntity, response.Code, response.Body.String())
	require.Contains(t, response.Body.String(), "selected group is unavailable")
	require.Zero(t, p.writes)
}
