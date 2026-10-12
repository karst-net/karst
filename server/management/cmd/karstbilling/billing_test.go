// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package karstbilling_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/netbirdio/netbird/management/cmd/karstbilling"
	"github.com/netbirdio/netbird/management/internals/karst/audit"
	"github.com/netbirdio/netbird/management/internals/karst/billing"
	"github.com/netbirdio/netbird/management/internals/karst/usage"
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
	_, err = audit.New(s.GetDB())
	require.NoError(t, err)
	require.NoError(t, usage.Migrate(s.GetDB()))
	require.NoError(t, s.SaveAccount(context.Background(), &types.Account{Id: "account-a", Network: types.NewNetwork()}))
	return s
}

func execute(s *store.SqlStore, args ...string) (billing.Assignment, error) {
	var output bytes.Buffer
	command := karstbilling.NewCommands(func(cmd *cobra.Command, fn func(context.Context, store.Store) error) error {
		return fn(cmd.Context(), s)
	})
	command.SetArgs(args)
	command.SetOut(&output)
	command.SetErr(io.Discard)
	if err := command.Execute(); err != nil {
		return billing.Assignment{}, err
	}
	var assignment billing.Assignment
	err := json.Unmarshal(output.Bytes(), &assignment)
	return assignment, err
}

func validArgs() []string {
	return []string{
		"assign-pilot", "--account-id", "account-a", "--actor", "pilot-operator",
		"--period-start", "2026-10-01T00:00:00Z", "--period-end", "2026-11-01T00:00:00Z",
	}
}

func TestAssignPilotIsExplicitScopedAndAudited(t *testing.T) {
	s := fixture(t)
	assignment, err := execute(s, validArgs()...)
	require.NoError(t, err)
	require.Equal(t, "account-a", assignment.AccountID)
	require.Equal(t, "pilot-2026-10-12-v1", assignment.ScheduleVersion)
	require.Equal(t, time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), assignment.PeriodStart)
	require.Equal(t, time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), assignment.PeriodEnd)

	stored, err := billing.NewStore(s.GetDB())
	require.NoError(t, err)
	got, err := stored.AssignedSchedule(billing.WithAccount(context.Background(), "account-a"), assignment.PeriodStart, assignment.PeriodEnd)
	require.NoError(t, err)
	require.Equal(t, "USD", got.Currency)
	require.EqualValues(t, 250, got.DeviceTiers[0].MinorPerPeriod)

	var entries []audit.Entry
	require.NoError(t, s.GetDB().Order("seq").Find(&entries).Error)
	require.Len(t, entries, 1)
	require.Equal(t, "account-a", entries[0].AccountID)
	require.Equal(t, "operator:pilot-operator", entries[0].Actor)
	require.Equal(t, "karst.billing.schedule.assign", entries[0].Action)
	require.Equal(t, "account-a", entries[0].Target)
	var detail billing.Assignment
	require.NoError(t, json.Unmarshal([]byte(entries[0].Detail), &detail))
	require.Equal(t, assignment, detail)

	_, err = stored.Assignment(billing.WithAccount(context.Background(), "account-b"), assignment.PeriodStart, assignment.PeriodEnd)
	require.ErrorIs(t, err, billing.ErrScheduleUnassigned)
}

func TestAssignPilotValidatesBeforeOpeningStore(t *testing.T) {
	for _, args := range [][]string{
		{"assign-pilot", "--account-id", "account-a", "--actor", "ops", "--period-start", "2026-10-01T00:00:00Z"},
		{"assign-pilot", "--account-id", " account-a", "--actor", "ops", "--period-start", "2026-10-01T00:00:00Z", "--period-end", "2026-11-01T00:00:00Z"},
		{"assign-pilot", "--account-id", "account-a", "--actor", "ops\nforged", "--period-start", "2026-10-01T00:00:00Z", "--period-end", "2026-11-01T00:00:00Z"},
		{"assign-pilot", "--account-id", "account-a", "--actor", "ops", "--period-start", "2026-11-01T00:00:00Z", "--period-end", "2026-10-01T00:00:00Z"},
	} {
		command := karstbilling.NewCommands(func(*cobra.Command, func(context.Context, store.Store) error) error {
			t.Fatal("invalid command must not open storage")
			return nil
		})
		command.SetArgs(args)
		command.SetOut(io.Discard)
		command.SetErr(io.Discard)
		require.Error(t, command.Execute())
	}
}

func TestAssignPilotRollsBackWhenAuditFails(t *testing.T) {
	s := fixture(t)
	failure := errors.New("injected audit failure")
	require.NoError(t, s.GetDB().Callback().Create().Before("gorm:create").Register("fail_billing_audit", func(tx *gorm.DB) {
		if tx.Statement.Table == (audit.Entry{}).TableName() {
			tx.AddError(failure)
		}
	}))
	_, err := execute(s, validArgs()...)
	require.ErrorIs(t, err, failure)
	require.NoError(t, s.GetDB().Callback().Create().Remove("fail_billing_audit"))

	stored, err := billing.NewStore(s.GetDB())
	require.NoError(t, err)
	_, err = stored.Schedule(context.Background(), billing.PilotRateSchedule().Version)
	require.ErrorIs(t, err, billing.ErrScheduleNotFound)
	start := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	_, err = stored.Assignment(billing.WithAccount(context.Background(), "account-a"), start, start.AddDate(0, 1, 0))
	require.ErrorIs(t, err, billing.ErrScheduleUnassigned)
	var entries int64
	require.NoError(t, s.GetDB().Model(&audit.Entry{}).Count(&entries).Error)
	require.Zero(t, entries)
}

func TestFinalizeInvoiceRefusesIncompleteUsageAndCreatesNoCharge(t *testing.T) {
	s := fixture(t)
	_, err := executeCommand(s, "finalize-invoice", "--account-id", "account-a", "--actor", "pilot-operator",
		"--period-start", "2026-01-01T00:00:00Z", "--period-end", "2026-02-01T00:00:00Z")
	require.ErrorIs(t, err, billing.ErrScheduleUnassigned)

	_, err = execute(s, "assign-pilot", "--account-id", "account-a", "--actor", "pilot-operator",
		"--period-start", "2026-01-01T00:00:00Z", "--period-end", "2026-02-01T00:00:00Z")
	require.NoError(t, err)
	_, err = executeCommand(s, "finalize-invoice", "--account-id", "account-a", "--actor", "pilot-operator",
		"--period-start", "2026-01-01T00:00:00Z", "--period-end", "2026-02-01T00:00:00Z")
	require.ErrorIs(t, err, billing.ErrInvoiceIncomplete)

	stored, err := billing.NewStore(s.GetDB())
	require.NoError(t, err)
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	_, err = stored.Invoice(billing.WithAccount(context.Background(), "account-a"), start, start.AddDate(0, 1, 0))
	require.ErrorIs(t, err, billing.ErrInvoiceNotFound)
	var finalized, charged int64
	require.NoError(t, s.GetDB().Model(&audit.Entry{}).Where("action = ?", "karst.billing.invoice.finalize").Count(&finalized).Error)
	require.NoError(t, s.GetDB().Model(&paymentOutboxModelForTest{}).Count(&charged).Error)
	require.Zero(t, finalized)
	require.Zero(t, charged)
}

func TestConfigurePaddleIsExplicitScopedAndAudited(t *testing.T) {
	s := fixture(t)
	output, err := executeCommand(s, "configure-paddle", "--account-id", "account-a", "--actor", "pilot-operator", "--enabled",
		"--paddle-customer-id", "ctm_01grnn4zta5a1mf02jjze7y2ys", "--paddle-product-id", "pro_01grnn4zta5a1mf02jjze7y2ys")
	require.NoError(t, err)
	var configured billing.PaddleAccount
	require.NoError(t, json.Unmarshal([]byte(output), &configured))
	require.True(t, configured.Enabled)
	require.Equal(t, "account-a", configured.AccountID)

	store, err := billing.NewStore(s.GetDB())
	require.NoError(t, err)
	account, err := store.PaddleAccount(billing.WithAccount(context.Background(), "account-a"))
	require.NoError(t, err)
	require.Equal(t, "ctm_01grnn4zta5a1mf02jjze7y2ys", account.CustomerID)
	_, err = store.PaddleAccount(billing.WithAccount(context.Background(), "account-b"))
	require.ErrorIs(t, err, billing.ErrPaddleAccountNotConfigured)

	_, err = executeCommand(s, "configure-paddle", "--account-id", "account-a", "--actor", "pilot-operator")
	require.NoError(t, err)
	_, err = store.PaddleAccount(billing.WithAccount(context.Background(), "account-a"))
	require.ErrorIs(t, err, billing.ErrPaddleAccountNotConfigured)

	var entries []audit.Entry
	require.NoError(t, s.GetDB().Where("action = ?", "karst.billing.paddle.configure").Order("seq").Find(&entries).Error)
	require.Len(t, entries, 2)
	require.Equal(t, "operator:pilot-operator", entries[0].Actor)
	require.Equal(t, "account-a", entries[0].AccountID)
	var detail struct {
		Enabled bool `json:"enabled"`
	}
	require.NoError(t, json.Unmarshal([]byte(entries[1].Detail), &detail))
	require.False(t, detail.Enabled)
}

type paymentOutboxModelForTest struct {
	InvoiceRef string `gorm:"primaryKey;size:67"`
}

func (paymentOutboxModelForTest) TableName() string { return "karst_billing_payment_outbox" }

func executeCommand(s *store.SqlStore, args ...string) (string, error) {
	var output bytes.Buffer
	command := karstbilling.NewCommands(func(cmd *cobra.Command, fn func(context.Context, store.Store) error) error {
		return fn(cmd.Context(), s)
	})
	command.SetArgs(args)
	command.SetOut(&output)
	command.SetErr(io.Discard)
	err := command.Execute()
	return output.String(), err
}
