// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package karstusage_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/netbirdio/netbird/management/cmd/karstusage"
	"github.com/netbirdio/netbird/management/internals/karst/audit"
	"github.com/netbirdio/netbird/management/internals/karst/identity"
	"github.com/netbirdio/netbird/management/internals/karst/relayusage"
	"github.com/netbirdio/netbird/management/internals/karst/usage"
	"github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
)

func fixture(t *testing.T) *store.SqlStore {
	t.Helper()
	s, err := store.NewSqliteStore(context.Background(), t.TempDir(), nil, false)
	require.NoError(t, err)
	db, err := s.GetDB().DB()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	require.NoError(t, s.InitializeDeviceUsage())
	_, err = audit.New(s.GetDB())
	require.NoError(t, err)
	for _, id := range []string{"a", "b"} {
		require.NoError(t, s.SaveAccount(context.Background(), &types.Account{Id: id, Network: types.NewNetwork()}))
	}
	require.NoError(t, s.AddPeerToAccount(context.Background(), &peer.Peer{ID: "one", AccountID: "a", Key: "key-one", DNSLabel: "one", IP: netip.MustParseAddr("100.64.0.1")}))
	return s
}

func execute(s *store.SqlStore, args ...string) (usage.CollectionStatus, error) {
	var output bytes.Buffer
	command := karstusage.NewCommands(func(cmd *cobra.Command, fn func(context.Context, store.Store) error) error {
		return fn(cmd.Context(), s)
	})
	command.SetArgs(args)
	command.SetOut(&output)
	command.SetErr(io.Discard)
	var state usage.CollectionStatus
	if err := command.Execute(); err != nil {
		return state, err
	}
	return state, json.Unmarshal(output.Bytes(), &state)
}

func executeRaw(s *store.SqlStore, args ...string) (string, error) {
	var output bytes.Buffer
	command := karstusage.NewCommands(func(cmd *cobra.Command, fn func(context.Context, store.Store) error) error {
		return fn(cmd.Context(), s)
	})
	command.SetArgs(args)
	command.SetOut(&output)
	command.SetErr(io.Discard)
	err := command.Execute()
	return output.String(), err
}

func TestCollectionCommandsScopeAndAudit(t *testing.T) {
	s := fixture(t)
	state, err := execute(s, "devices", "status", "--account-id", "a")
	require.NoError(t, err)
	require.False(t, state.Enabled)
	state, err = execute(s, "devices", "enable", "--account-id", "a", "--actor", "operator-one", "--all-writers-instrumented")
	require.NoError(t, err)
	require.True(t, state.Enabled)
	firstPeriod := state.PeriodID
	state, err = execute(s, "devices", "enable", "--account-id", "a", "--actor", "operator-one", "--all-writers-instrumented")
	require.NoError(t, err)
	require.Equal(t, firstPeriod, state.PeriodID)
	other, err := execute(s, "devices", "status", "--account-id", "b")
	require.NoError(t, err)
	require.False(t, other.Enabled)
	state, err = execute(s, "devices", "disable", "--account-id", "a", "--actor", "operator-two")
	require.NoError(t, err)
	require.False(t, state.Enabled)
	_, err = s.GetPeerByID(context.Background(), store.LockingStrengthNone, "a", "one")
	require.NoError(t, err, "disabling collection does not revoke the device")
	var entries []audit.Entry
	require.NoError(t, s.GetDB().Order("seq").Find(&entries).Error)
	require.Len(t, entries, 3)
	for _, entry := range entries {
		require.Equal(t, "a", entry.AccountID)
		require.Equal(t, "a", entry.Target)
	}
	require.Equal(t, "operator:operator-two", entries[2].Actor)
	require.Equal(t, "karst.usage.collection.disable", entries[2].Action)
	coverage, err := usage.Coverage(context.Background(), s.GetDB(), "a")
	require.NoError(t, err)
	require.Len(t, coverage, 1)
	require.NotNil(t, coverage[0].EndUS)
}

func TestCommandValidationPrecedesDatabaseAccess(t *testing.T) {
	for _, args := range [][]string{
		{"devices", "enable", "--account-id", "a", "--actor", "operator"},
		{"devices", "enable", "--account-id", "a", "--all-writers-instrumented"},
		{"devices", "disable", "--actor", "operator"},
		{"devices", "status", "--account-id", " a"},
		{"devices", "disable", "--account-id", "a", "--actor", "operator\nforged"},
	} {
		command := karstusage.NewCommands(func(*cobra.Command, func(context.Context, store.Store) error) error {
			t.Fatal("invalid command must not open storage")
			return nil
		})
		command.SetArgs(args)
		command.SetOut(io.Discard)
		command.SetErr(io.Discard)
		require.Error(t, command.Execute())
	}
}

func TestAuditFailureRollsBackActivation(t *testing.T) {
	s := fixture(t)
	failure := errors.New("injected audit failure")
	require.NoError(t, s.GetDB().Callback().Create().Before("gorm:create").Register("fail_operator_audit", func(tx *gorm.DB) {
		if tx.Statement.Table == (audit.Entry{}).TableName() {
			tx.AddError(failure)
		}
	}))
	_, err := execute(s, "devices", "enable", "--account-id", "a", "--actor", "operator", "--all-writers-instrumented")
	require.ErrorIs(t, err, failure)
	require.NoError(t, s.GetDB().Callback().Create().Remove("fail_operator_audit"))
	state, err := usage.ReadCollection(context.Background(), s.GetDB(), "a")
	require.NoError(t, err)
	require.False(t, state.Enabled)
	coverage, err := usage.Coverage(context.Background(), s.GetDB(), "a")
	require.NoError(t, err)
	require.Empty(t, coverage)
	var events int64
	require.NoError(t, s.GetDB().Table("karst_usage_device_events").Count(&events).Error)
	require.Zero(t, events)
}

func TestOperatorReconciliationRecordsIncompleteCoverage(t *testing.T) {
	s := fixture(t)
	_, err := execute(s, "devices", "enable", "--account-id", "a", "--actor", "operator", "--all-writers-instrumented")
	require.NoError(t, err)
	require.NoError(t, s.GetDB().Delete(&peer.Peer{ID: "one"}).Error)
	state, err := execute(s, "devices", "reconcile", "--account-id", "a", "--actor", "operator")
	require.NoError(t, err)
	require.True(t, state.Enabled)
	coverage, err := usage.Coverage(context.Background(), s.GetDB(), "a")
	require.NoError(t, err)
	require.Len(t, coverage, 2)
	require.False(t, coverage[0].Complete)
	require.True(t, coverage[1].Complete)
	var entry audit.Entry
	require.NoError(t, s.GetDB().Order("seq DESC").Take(&entry).Error)
	require.Equal(t, "karst.usage.collection.reconcile", entry.Action)
	_, err = execute(s, "devices", "enable", "--account-id", "missing", "--actor", "operator", "--all-writers-instrumented")
	require.Error(t, err)
}

func TestManagedRelayAuthorizationIsExplicitAuditedAndRevocable(t *testing.T) {
	s := fixture(t)
	key, err := identity.FromSeed(bytes.Repeat([]byte{8}, identity.SeedSize))
	require.NoError(t, err)
	mapping, err := usage.PersistRelayMapping(context.Background(), s.GetDB(), "deployment-a", "aquifer-a", "a")
	require.NoError(t, err)
	_, err = relayusage.NewStore(s.GetDB())
	require.NoError(t, err)

	output, err := executeRaw(s, "relays", "authorize", "--identity-key", base64.StdEncoding.EncodeToString(key.Public()), "--deployment-id", "deployment-a", "--actor", "operator-one")
	require.NoError(t, err)
	var authorized struct {
		RelayID string `json:"relay_id"`
	}
	require.NoError(t, json.Unmarshal([]byte(output), &authorized))
	require.NotEmpty(t, authorized.RelayID)

	_, err = executeRaw(s, "relays", "allow-mapping", "--relay-id", authorized.RelayID, "--deployment-id", mapping.DeploymentID, "--mapping-version", mapping.Version, "--actor", "operator-one")
	require.NoError(t, err)
	var allowed int64
	require.NoError(t, s.GetDB().Table("karst_usage_producer_mappings").Where("relay_id = ? AND enabled = ?", authorized.RelayID, true).Count(&allowed).Error)
	require.EqualValues(t, 1, allowed)

	_, err = executeRaw(s, "relays", "revoke-mapping", "--relay-id", authorized.RelayID, "--deployment-id", mapping.DeploymentID, "--mapping-version", mapping.Version, "--actor", "operator-two")
	require.NoError(t, err)
	_, err = executeRaw(s, "relays", "revoke", "--relay-id", authorized.RelayID, "--actor", "operator-two")
	require.NoError(t, err)
	var enabled int64
	require.NoError(t, s.GetDB().Table("karst_usage_managed_producers").Where("relay_id = ? AND enabled = ?", authorized.RelayID, true).Count(&enabled).Error)
	require.Zero(t, enabled)
	var entries []audit.Entry
	require.NoError(t, s.GetDB().Order("seq").Find(&entries).Error)
	require.Len(t, entries, 4)
	require.Equal(t, "karst.usage.relay.authorize", entries[0].Action)
	require.Equal(t, "karst.usage.relay.allow-mapping", entries[1].Action)
	require.Equal(t, "operator:operator-two", entries[3].Actor)
	require.Equal(t, "karst.usage.relay.revoke", entries[3].Action)
}

func TestManagedRelayCommandsValidateBeforeOpeningStore(t *testing.T) {
	for _, args := range [][]string{
		{"relays", "authorize", "--identity-key", "not-base64", "--deployment-id", "deployment-a", "--actor", "operator"},
		{"relays", "authorize", "--identity-key", base64.StdEncoding.EncodeToString(make([]byte, identity.PublicKeySize)), "--deployment-id", "deployment-a"},
		{"relays", "revoke", "--relay-id", "bad", "--actor", "operator"},
		{"relays", "allow-mapping", "--relay-id", "bad", "--deployment-id", "deployment-a", "--mapping-version", "x", "--actor", "operator"},
	} {
		command := karstusage.NewCommands(func(*cobra.Command, func(context.Context, store.Store) error) error {
			t.Fatal("invalid relay command must not open storage")
			return nil
		})
		command.SetArgs(args)
		command.SetOut(io.Discard)
		command.SetErr(io.Discard)
		require.Error(t, command.Execute())
	}
}
