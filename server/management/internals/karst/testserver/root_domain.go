// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package main

import (
	"context"
	"net/http"

	"github.com/gorilla/mux"
	karstapi "github.com/netbirdio/netbird/management/internals/karst/api"
	"github.com/netbirdio/netbird/management/internals/modules/meshdomain"
	domainmanager "github.com/netbirdio/netbird/management/internals/modules/meshdomain/manager"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/mock_server"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/auth"
)

type rootDomainFixture struct{ api http.Handler }

// Opt-in cross-language fixture: production root store, permissions, domain
// manager, REST handlers and DNS projection, with the existing in-memory peer
// source for the datapath. The explicitly enabled local control listener acts
// as one fixture owner; it is not a production authentication endpoint.
func installRootDomainFixture(r *router, directory string) error {
	ctx := context.Background()
	s, _, err := store.NewTestStoreFromSQL(ctx, "", directory)
	if err != nil {
		return err
	}
	root, err := meshdomain.NewRoot("fixture-account", "karst")
	if err != nil {
		return err
	}
	if err := s.SaveAccount(ctx, &types.Account{Id: "fixture-account", RootDomainID: root.ID, RootDomain: root, Settings: &types.Settings{DNSDomain: "karst"}, Network: &types.Network{Dns: "karst"}}); err != nil {
		return err
	}
	owner := types.NewAdminUser("fixture-owner")
	owner.AccountID = "fixture-account"
	owner.Role = types.UserRoleOwner
	if err := s.SaveUser(ctx, owner); err != nil {
		return err
	}
	child := meshdomain.NewDomain("fixture-account", root.ID, "engineering", "")
	if err := s.CreateDomain(ctx, child); err != nil {
		return err
	}
	for _, p := range r.account.peers {
		p.DomainID = child.ID
		p.DNSLabel += ".engineering"
		if err := s.AddPeerToAccount(ctx, p.Copy()); err != nil {
			return err
		}
	}
	permissionManager := permissions.NewManager(s)
	am := &mock_server.MockAccountManager{}
	mgr := domainmanager.NewManager(s, am, permissionManager)
	apiRouter := mux.NewRouter()
	karstapi.RegisterEndpoints(r.nodes, nil, nil, nil, nil, nil, nil, nil, nil, am, permissionManager, mgr, nil, nil, "", nil, nil, nil, nil, nil, nil, nil, nil, nil, apiRouter)
	r.rootDomains = &rootDomainFixture{api: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{AccountId: "fixture-account", UserId: owner.Id})
		apiRouter.ServeHTTP(w, req)
	})}
	r.netmap.DNS = s
	r.netmap.DNSZone = ""
	return nil
}
