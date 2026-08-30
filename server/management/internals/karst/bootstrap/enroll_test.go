// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package bootstrap_test

import (
	"context"
	"runtime"
	"testing"
	"time"

	"github.com/golang/mock/gomock"

	"github.com/netbirdio/netbird/management/internals/controllers/network_map/controller"
	"github.com/netbirdio/netbird/management/internals/controllers/network_map/update_channel"
	"github.com/netbirdio/netbird/management/internals/karst/bootstrap"
	"github.com/netbirdio/netbird/management/internals/modules/peers"
	ephemeral_manager "github.com/netbirdio/netbird/management/internals/modules/peers/ephemeral/manager"
	"github.com/netbirdio/netbird/management/internals/server/config"
	nbserver "github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/activity"
	nbcache "github.com/netbirdio/netbird/management/server/cache"
	"github.com/netbirdio/netbird/management/server/geolocation"
	"github.com/netbirdio/netbird/management/server/integrations/port_forwarding"
	"github.com/netbirdio/netbird/management/server/job"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/settings"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/telemetry"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/auth"
)

// userAuthFor is what MintBootstrapKey passes and what a verified JWT reduces
// to: a subject and nothing else. The domain is left empty on purpose — in
// single-account mode the manager fills it in, and that filling-in is the
// behaviour TestAnIdPUserLandsInTheBootstrapAccount exists to pin.
func userAuthFor(subject string) auth.UserAuth {
	return auth.UserAuth{UserId: subject}
}

// The bootstrap key is only worth anything if the *real* account manager
// accepts it, so these tests build one rather than a stub — the same argument
// TestRegistrationAgainstTheRealAccountManager makes for the login path. A
// fake here would be written against the interface this package imagines and
// would pass whether or not a self-hoster could ever enroll a node.
//
// The store starts **empty**, because that is the situation the whole feature
// is for: a deployment on its first boot, with no account, no user, and no
// identity provider to make either.
func emptyAccountManager(t *testing.T, singleAccountModeDomain string) *nbserver.DefaultAccountManager {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the SQLite store is not properly supported on Windows")
	}
	ctx := context.Background()

	s, cleanup, err := store.NewTestStoreFromSQL(ctx, "", t.TempDir())
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(cleanup)

	metrics, err := telemetry.NewDefaultAppMetrics(ctx)
	if err != nil {
		t.Fatalf("metrics: %v", err)
	}

	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)
	settingsManager := settings.NewMockManager(ctrl)
	settingsManager.EXPECT().GetExtraSettings(gomock.Any(), gomock.Any()).
		Return(&types.ExtraSettings{}, nil).AnyTimes()

	permissionsManager := permissions.NewManager(s)
	peersManager := peers.NewManager(s, permissionsManager)

	cacheStore, err := nbcache.NewStore(ctx, 100*time.Millisecond, 300*time.Millisecond, 100)
	if err != nil {
		t.Fatalf("cache: %v", err)
	}
	updateManager := update_channel.NewPeersUpdateManager(metrics)
	requestBuffer := nbserver.NewAccountRequestBuffer(ctx, s)
	networkMapController := controller.NewController(ctx, s, metrics, updateManager, requestBuffer,
		nbserver.MockIntegratedValidator{}, settingsManager, "netbird.cloud",
		port_forwarding.NewControllerMock(),
		ephemeral_manager.NewEphemeralManager(s, peers.NewManager(s, permissionsManager)),
		&config.Config{})

	am, err := nbserver.BuildManager(ctx, nil, s, networkMapController,
		job.NewJobManager(nil, s, peersManager), nil, singleAccountModeDomain,
		&activity.InMemoryEventStore{}, geolocation.Geolocation(nil), false,
		nbserver.MockIntegratedValidator{}, metrics, port_forwarding.NewControllerMock(),
		settingsManager, permissionsManager, false, cacheStore)
	if err != nil {
		t.Fatalf("BuildManager: %v", err)
	}
	return am
}

// The claim GETTING-STARTED.md §8 now makes: a deployment with no identity
// provider, no account and no user can still produce a key a node can enroll
// with.
func TestMintBootstrapKeyOnAnEmptyDeployment(t *testing.T) {
	am := emptyAccountManager(t, "karst.selfhosted")
	ctx := context.Background()

	key, err := bootstrap.MintBootstrapKey(ctx, am, bootstrap.BootstrapKeyOptions{})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if key == "" {
		t.Fatal("minted an empty key; a node would fail to enroll with no way to see why")
	}

	// The account it landed in must be real and must hold the key, or the key
	// is a string that authenticates against nothing.
	accountID, userID, err := am.GetAccountIDFromUserAuth(ctx, userAuthFor(bootstrap.BootstrapUserID))
	if err != nil {
		t.Fatalf("resolve the bootstrap account: %v", err)
	}
	keys, err := am.ListSetupKeys(ctx, accountID, userID)
	if err != nil {
		t.Fatalf("list setup keys: %v", err)
	}
	var found bool
	for _, k := range keys {
		if k.Name != bootstrap.BootstrapKeyName {
			continue
		}
		found = true
		if k.Revoked {
			t.Error("the key was born revoked")
		}
		if k.ExpiresAt != nil {
			t.Errorf("the key expires at %s; the file holding it would go stale silently", k.ExpiresAt)
		}
		if k.UsageLimit != 0 {
			t.Errorf("usage limit %d; the deployment's Nth node would be refused "+
				"against a console that does not exist yet", k.UsageLimit)
		}
	}
	if !found {
		t.Fatalf("no setup key named %q in account %s; got %d keys",
			bootstrap.BootstrapKeyName, accountID, len(keys))
	}
}

// The plaintext exists in exactly one place. Two calls must not return the
// same string, or the "key" is a constant and every deployment shares it.
func TestEachBootstrapKeyIsDistinct(t *testing.T) {
	am := emptyAccountManager(t, "karst.selfhosted")
	ctx := context.Background()

	first, err := bootstrap.MintBootstrapKey(ctx, am, bootstrap.BootstrapKeyOptions{})
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	second, err := bootstrap.MintBootstrapKey(ctx, am, bootstrap.BootstrapKeyOptions{})
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if first == second {
		t.Fatal("two mints returned the same key")
	}
}

// The reason MintBootstrapKey resolves the account through the login path
// rather than creating one directly.
//
// In single-account mode the first user an identity provider later
// authenticates is routed into the account that already exists. If the
// bootstrap user were put somewhere else, every node enrolled before
// authentication worked would be invisible from the console afterwards — a
// deployment that appears to have lost its whole fleet on the day it gained a
// login page.
func TestAnIdPUserLandsInTheBootstrapAccount(t *testing.T) {
	am := emptyAccountManager(t, "karst.selfhosted")
	ctx := context.Background()

	if _, err := bootstrap.MintBootstrapKey(ctx, am, bootstrap.BootstrapKeyOptions{}); err != nil {
		t.Fatalf("mint: %v", err)
	}
	bootstrapAccount, _, err := am.GetAccountIDFromUserAuth(ctx, userAuthFor(bootstrap.BootstrapUserID))
	if err != nil {
		t.Fatalf("bootstrap account: %v", err)
	}

	// A subject an OIDC provider would issue, arriving for the first time.
	operatorAccount, _, err := am.GetAccountIDFromUserAuth(ctx, userAuthFor("auth0|63bcd0a1"))
	if err != nil {
		t.Fatalf("operator account: %v", err)
	}
	if operatorAccount != bootstrapAccount {
		t.Fatalf("the first IdP user landed in account %s, not the bootstrap account %s; "+
			"every node enrolled with the bootstrap key would be invisible to them",
			operatorAccount, bootstrapAccount)
	}
}

func TestMintBootstrapKeyWithoutAnAccountManager(t *testing.T) {
	if _, err := bootstrap.MintBootstrapKey(context.Background(), nil,
		bootstrap.BootstrapKeyOptions{}); err == nil {
		t.Fatal("a nil account manager was accepted")
	}
}
