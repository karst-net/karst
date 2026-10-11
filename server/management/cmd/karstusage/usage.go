// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// Package karstusage provides operator-only collection controls. Authority is
// possession of the server's configuration and database access, just like the
// existing admin token/proxy commands; no customer API changes collection state.
package karstusage

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"unicode"

	"github.com/spf13/cobra"

	"github.com/netbirdio/netbird/management/internals/karst/audit"
	"github.com/netbirdio/netbird/management/internals/karst/usage"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
)

type StoreOpener func(*cobra.Command, func(context.Context, store.Store) error) error

// NewCommands adds status, enable, disable, and explicit reconciliation under
// `admin usage devices`. It uses the store-only opener, never an IdP session.
func NewCommands(opener StoreOpener) *cobra.Command {
	root := &cobra.Command{Use: "usage", Short: "Manage optional Karst usage collection"}
	devices := &cobra.Command{Use: "devices", Short: "Manage enrolled-device collection by account"}
	for _, action := range []string{"status", "enable", "disable", "reconcile"} {
		var accountID, actor string
		var instrumented bool
		command := &cobra.Command{
			Use: action, Short: action + " device usage collection for one account", Args: cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				if !validLabel(accountID) {
					return fmt.Errorf("provide --account-id (1–128 non-control characters without surrounding whitespace)")
				}
				if action != "status" && !validLabel(actor) {
					return fmt.Errorf("provide --actor to identify the operator in the audit record")
				}
				if action == "enable" && !instrumented {
					return fmt.Errorf("enable requires --all-writers-instrumented: every replica and membership writer must run the collection hooks")
				}
				return opener(cmd, func(ctx context.Context, raw store.Store) error {
					sql, ok := raw.(*store.SqlStore)
					if !ok {
						return fmt.Errorf("device collection requires a SQL store")
					}
					if !sql.GetDB().Migrator().HasTable("karst_usage_device_collection") {
						return fmt.Errorf("collection schema is missing; start the updated control plane before using these commands")
					}
					var account types.Account
					if err := sql.GetDB().WithContext(ctx).Select("id").Where("id = ?", accountID).Take(&account).Error; err != nil {
						return fmt.Errorf("find account: %w", err)
					}
					if action != "status" {
						if err := mutate(ctx, sql, accountID, actor, action); err != nil {
							return err
						}
					}
					state, err := usage.ReadCollection(ctx, sql.GetDB(), accountID)
					if err != nil {
						return err
					}
					return json.NewEncoder(cmd.OutOrStdout()).Encode(state)
				})
			},
		}
		command.Flags().StringVar(&accountID, "account-id", "", "Account whose collection state is being managed")
		if action != "status" {
			command.Flags().StringVar(&actor, "actor", "", "Operator identity recorded as operator:<actor> (a label, not user-session authentication)")
		}
		if action == "enable" {
			command.Flags().BoolVar(&instrumented, "all-writers-instrumented", false, "Confirm every database writer runs the collection hooks before activation")
		}
		devices.AddCommand(command)
	}
	root.AddCommand(devices)
	return root
}

func validLabel(s string) bool {
	return len(s) > 0 && len(s) <= 128 && strings.TrimSpace(s) == s && strings.IndexFunc(s, unicode.IsControl) < 0
}

func mutate(ctx context.Context, sql *store.SqlStore, accountID, actor, action string) error {
	if err := sql.InitializeDeviceUsage(); err != nil {
		return err
	}
	log, err := audit.New(sql.GetDB())
	if err != nil {
		return err
	}
	return sql.ExecuteInTransaction(ctx, func(tx store.Store) error {
		transaction, ok := tx.(*store.SqlStore)
		if !ok {
			return fmt.Errorf("device collection requires a SQL transaction")
		}
		if action == "reconcile" {
			err = transaction.ReconcileDeviceUsage(ctx, accountID)
		} else {
			err = transaction.SetDeviceUsageCollection(ctx, accountID, action == "enable")
		}
		if err != nil {
			return err
		}
		_, err = log.AppendInTransaction(audit.WithAccount(ctx, accountID), transaction.GetDB(),
			"operator:"+actor, "karst.usage.collection."+action, accountID, "")
		return err
	})
}
