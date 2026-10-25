// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package server

import (
	"context"
	"testing"
	"time"

	"github.com/netbirdio/netbird/management/internals/karst/policy"
	"github.com/netbirdio/netbird/management/internals/karst/relayservice"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Use the transaction database without requiring unrelated native services.
type karstDeletionStore struct {
	store.Store
	db *gorm.DB
}

func (s karstDeletionStore) GetDB() *gorm.DB { return s.db }

func TestKarstGroupDeletionDependencies(t *testing.T) {
	tests := []struct {
		name, document, resource string
		service                  *relayservice.Service
		backend                  *relayservice.BackendAccess
	}{
		{name: "source", document: `{"grants":[{"id":"web","name":"Web","source_groups":["g"],"target_groups":["other"],"ports":"443"}]}`, resource: "access grant"},
		{name: "target", document: `{"grants":[{"id":"web","name":"Web","source_groups":["other"],"target_groups":["g"],"ports":"443"}]}`, resource: "access grant"},
		{name: "binding", document: `{"groups":{"group:legacy":["alice"]},"groupBindings":{"group:legacy":"g"}}`, resource: "legacy membership mapping"},
		{name: "relay", resource: "relay", service: &relayservice.Service{AccountID: "a", ID: "Denver", AllowedGroups: []string{"g"}}},
		{name: "disabled relay", resource: "relay", service: &relayservice.Service{AccountID: "a", ID: "Denver", PonorDisabled: true, AllowedGroups: []string{"g"}}},
		{name: "retained admission", resource: "relay admission", backend: &relayservice.BackendAccess{AccountID: "a", RelayID: "backend", Groups: []string{"g"}}},
		{name: "unbound legacy group is not a registry reference", document: `{"groups":{"group:g":["alice"]},"acls":[{"action":"accept","src":["group:g"],"dst":["*:443"]}]}`},
		{name: "unrelated grant", document: `{"grants":[{"id":"web","name":"Web","source_groups":["other"],"target_groups":["elsewhere"],"ports":"443"}]}`},
		{name: "other tenant relay", service: &relayservice.Service{AccountID: "b", ID: "Denver", AllowedGroups: []string{"g"}}},
		{name: "empty deny admission", backend: &relayservice.BackendAccess{AccountID: "a", RelayID: "backend"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
			require.NoError(t, err)
			raw, err := db.DB()
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, raw.Close()) })
			require.NoError(t, db.AutoMigrate(&policy.Version{}, &relayservice.Service{}, &relayservice.BackendAccess{}))
			if test.document != "" {
				require.NoError(t, db.Create(&policy.Version{AccountID: "a", Version: 1, Document: test.document}).Error)
			}
			if test.service != nil {
				require.NoError(t, db.Create(test.service).Error)
			}
			if test.backend != nil {
				require.NoError(t, db.Create(test.backend).Error)
			}
			err = validateKarstGroupDeletion(context.Background(), karstDeletionStore{db: db}, &types.Group{AccountID: "a", ID: "g"})
			if test.resource == "" {
				require.NoError(t, err)
			} else {
				var linked *GroupLinkError
				err = validateDeleteGroup(context.Background(), karstDeletionStore{db: db}, &types.Group{AccountID: "a", ID: "g", Name: "Engineering"}, "admin", nil)
				require.ErrorAs(t, err, &linked)
				require.Equal(t, test.resource, linked.Resource)
			}
		})
	}
}

func TestKarstGroupDeletionCurrentAccountAndMalformedPolicy(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	raw, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, raw.Close()) })
	require.NoError(t, db.AutoMigrate(&policy.Version{}))
	old := `{"grants":[{"id":"web","name":"Web","source_groups":["g"],"target_groups":["other"],"ports":"443"}]}`
	require.NoError(t, db.Create(&policy.Version{AccountID: "a", Version: 1, Document: old}).Error)
	require.NoError(t, db.Create(&policy.Version{AccountID: "a", Version: 2, Document: `{}`}).Error)
	require.NoError(t, db.Create(&policy.Version{AccountID: "b", Version: 3, Document: old}).Error)
	s := karstDeletionStore{db: db}
	group := &types.Group{AccountID: "a", ID: "g"}
	require.NoError(t, validateKarstGroupDeletion(context.Background(), s, group))
	require.NoError(t, db.Create(&policy.Version{AccountID: "a", Version: 3, Document: `malformed`}).Error)
	require.ErrorContains(t, validateKarstGroupDeletion(context.Background(), s, group), "cannot check current group access dependencies")
}

type groupInvitationStore struct {
	store.Store
	keys []*types.SetupKey
}

func (s groupInvitationStore) GetAccountSetupKeys(context.Context, store.LockingStrength, string) ([]*types.SetupKey, error) {
	return s.keys, nil
}
func TestGroupDeletionInvitationHistory(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	for _, test := range []struct {
		name                string
		invitation, revoked bool
		used                int
		expires             *time.Time
		want                bool
	}{
		{name: "active invitation", invitation: true, want: true},
		{name: "revoked history", invitation: true, revoked: true},
		{name: "expired history", invitation: true, expires: &past},
		{name: "exhausted history", invitation: true, used: 1},
		{name: "legacy revoked setup key preserves existing behavior", revoked: true, want: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			key := &types.SetupKey{Id: "invite", Type: types.SetupKeyOneOff, AutoGroups: []string{"g"}, Revoked: test.revoked, UsedTimes: test.used, ExpiresAt: test.expires}
			if test.invitation {
				key.InvitationIssuerID = "admin"
			}
			linked, _ := isGroupLinkedToSetupKey(context.Background(), groupInvitationStore{keys: []*types.SetupKey{key}}, "a", "g")
			require.Equal(t, test.want, linked)
		})
	}
}

func TestKarstGroupDeletionDependencyReadFailure(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	raw, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, raw.Close()) })
	require.NoError(t, db.AutoMigrate(&relayservice.Service{}))
	require.NoError(t, db.Migrator().DropColumn(&relayservice.Service{}, "allowed_groups"))
	s := karstDeletionStore{db: db}
	g := &types.Group{AccountID: "a", ID: "g"}
	require.ErrorContains(t, validateKarstGroupDeletion(context.Background(), s, g), "cannot check relay group dependencies")
	require.NoError(t, raw.Close())
	require.ErrorContains(t, validateKarstGroupDeletion(context.Background(), s, g), "cannot check group dependency tables")
}
