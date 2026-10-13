// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// Package karstbilling provides explicit schedule assignment and finalized
// invoice operations for deployment operators. It does not charge customers.
package karstbilling

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/spf13/cobra"

	"github.com/netbirdio/netbird/management/internals/karst/audit"
	"github.com/netbirdio/netbird/management/internals/karst/billing"
	"github.com/netbirdio/netbird/management/internals/karst/relayusage"
	"github.com/netbirdio/netbird/management/internals/karst/usage"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
)

type StoreOpener func(*cobra.Command, func(context.Context, store.Store) error) error

// NewCommands adds an explicit, audited assignment of the approved pilot rate
// schedule to one account and caller-supplied period. Nothing is assigned by
// default, and the command does not finalize invoices or create charges.
func NewCommands(opener StoreOpener) *cobra.Command {
	root := &cobra.Command{Use: "billing", Short: "Manage explicit Karst billing schedule assignments"}
	var accountID, actor, startText, endText string
	assign := &cobra.Command{
		Use: "assign-pilot", Short: "Assign the approved pilot rates to one account and exact period",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !validLabel(accountID) {
				return fmt.Errorf("provide --account-id (1–128 non-control characters without surrounding whitespace)")
			}
			if !validLabel(actor) {
				return fmt.Errorf("provide --actor to identify the operator in the audit record")
			}
			start, err := time.Parse(time.RFC3339Nano, startText)
			if err != nil {
				return fmt.Errorf("parse --period-start as RFC3339: %w", err)
			}
			end, err := time.Parse(time.RFC3339Nano, endText)
			if err != nil {
				return fmt.Errorf("parse --period-end as RFC3339: %w", err)
			}
			if !start.Before(end) || start.Nanosecond()%1000 != 0 || end.Nanosecond()%1000 != 0 {
				return fmt.Errorf("period must have start before end and microsecond-or-coarser precision")
			}

			var assignment billing.Assignment
			if err := opener(cmd, func(ctx context.Context, raw store.Store) error {
				sql, ok := raw.(*store.SqlStore)
				if !ok {
					return fmt.Errorf("billing assignment requires a SQL store")
				}
				db := sql.GetDB()
				billingStore, err := billing.NewStore(db)
				if err != nil {
					return err
				}
				log, err := audit.New(db)
				if err != nil {
					return err
				}
				return sql.ExecuteInTransaction(ctx, func(tx store.Store) error {
					sqlTx, ok := tx.(*store.SqlStore)
					if !ok {
						return fmt.Errorf("billing assignment requires a SQL transaction")
					}
					var account types.Account
					if err := sqlTx.GetDB().WithContext(ctx).Select("id").Where("id = ?", accountID).Take(&account).Error; err != nil {
						return fmt.Errorf("find account: %w", err)
					}
					ctx := billing.WithAccount(ctx, accountID)
					transactionalStore := billingStore.WithDB(sqlTx.GetDB())
					if err := transactionalStore.PutSchedule(ctx, billing.PilotRateSchedule()); err != nil {
						return err
					}
					if err := transactionalStore.AssignSchedule(ctx, start, end, billing.PilotRateSchedule().Version); err != nil {
						return err
					}
					assignment, err = transactionalStore.Assignment(ctx, start, end)
					if err != nil {
						return err
					}
					detail, err := json.Marshal(assignment)
					if err != nil {
						return fmt.Errorf("encode audit detail: %w", err)
					}
					_, err = log.AppendInTransaction(audit.WithAccount(ctx, accountID), sqlTx.GetDB(),
						"operator:"+actor, "karst.billing.schedule.assign", accountID, string(detail))
					return err
				})
			}); err != nil {
				return err
			}
			return json.NewEncoder(cmd.OutOrStdout()).Encode(assignment)
		},
	}
	assign.Flags().StringVar(&accountID, "account-id", "", "Account whose pilot rate schedule is being assigned")
	assign.Flags().StringVar(&actor, "actor", "", "Operator identity recorded as operator:<actor>")
	assign.Flags().StringVar(&startText, "period-start", "", "Exact period start in RFC3339 format")
	assign.Flags().StringVar(&endText, "period-end", "", "Exact period end in RFC3339 format")
	_ = assign.MarkFlagRequired("account-id")
	_ = assign.MarkFlagRequired("actor")
	_ = assign.MarkFlagRequired("period-start")
	_ = assign.MarkFlagRequired("period-end")
	root.AddCommand(assign)
	root.AddCommand(newFinalizeCommand(opener))
	root.AddCommand(newConfigurePaddleCommand(opener))
	return root
}

func newConfigurePaddleCommand(opener StoreOpener) *cobra.Command {
	var accountID, actor, customerID, productID string
	var enabled bool
	command := &cobra.Command{
		Use: "configure-paddle", Short: "Explicitly enable or disable Paddle collection for one account", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !validLabel(accountID) || !validLabel(actor) {
				return fmt.Errorf("provide valid --account-id and --actor values")
			}
			if enabled && (customerID == "" || productID == "") {
				return fmt.Errorf("--enabled requires --paddle-customer-id and --paddle-product-id")
			}
			var configured billing.PaddleAccount
			if err := opener(cmd, func(ctx context.Context, raw store.Store) error {
				sql, ok := raw.(*store.SqlStore)
				if !ok {
					return fmt.Errorf("Paddle configuration requires a SQL store")
				}
				billingStore, err := billing.NewStore(sql.GetDB())
				if err != nil {
					return err
				}
				log, err := audit.New(sql.GetDB())
				if err != nil {
					return err
				}
				return sql.ExecuteInTransaction(ctx, func(tx store.Store) error {
					sqlTx, ok := tx.(*store.SqlStore)
					if !ok {
						return fmt.Errorf("Paddle configuration requires a SQL transaction")
					}
					var account types.Account
					if err := sqlTx.GetDB().WithContext(ctx).Select("id").Where("id = ?", accountID).Take(&account).Error; err != nil {
						return fmt.Errorf("find account: %w", err)
					}
					accountCtx := billing.WithAccount(ctx, accountID)
					configured, err = billingStore.WithDB(sqlTx.GetDB()).ConfigurePaddleAccount(accountCtx, enabled, customerID, productID)
					if err != nil {
						return err
					}
					detail, err := json.Marshal(struct {
						Enabled    bool   `json:"enabled"`
						CustomerID string `json:"customer_id,omitempty"`
						ProductID  string `json:"product_id,omitempty"`
					}{configured.Enabled, configured.CustomerID, configured.ProductID})
					if err != nil {
						return err
					}
					_, err = log.AppendInTransaction(audit.WithAccount(accountCtx, accountID), sqlTx.GetDB(), "operator:"+actor, "karst.billing.paddle.configure", accountID, string(detail))
					return err
				})
			}); err != nil {
				return err
			}
			return json.NewEncoder(cmd.OutOrStdout()).Encode(configured)
		},
	}
	command.Flags().StringVar(&accountID, "account-id", "", "Account whose Paddle collection configuration is changing")
	command.Flags().StringVar(&actor, "actor", "", "Operator identity recorded in the audit log")
	command.Flags().BoolVar(&enabled, "enabled", false, "Explicitly enable Paddle collection; omit to disable")
	command.Flags().StringVar(&customerID, "paddle-customer-id", "", "Paddle customer ID for the account")
	command.Flags().StringVar(&productID, "paddle-product-id", "", "Approved Paddle product ID for non-catalog invoice prices")
	for _, flag := range []string{"account-id", "actor"} {
		_ = command.MarkFlagRequired(flag)
	}
	return command
}

func newFinalizeCommand(opener StoreOpener) *cobra.Command {
	var accountID, actor, startText, endText string
	command := &cobra.Command{
		Use: "finalize-invoice", Short: "Finalize one complete assigned UTC-month invoice without collecting payment", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !validLabel(accountID) || !validLabel(actor) {
				return fmt.Errorf("provide valid --account-id and --actor values")
			}
			start, err := time.Parse(time.RFC3339Nano, startText)
			if err != nil {
				return fmt.Errorf("parse --period-start as RFC3339: %w", err)
			}
			end, err := time.Parse(time.RFC3339Nano, endText)
			if err != nil {
				return fmt.Errorf("parse --period-end as RFC3339: %w", err)
			}
			if !start.Before(end) || start.Nanosecond()%1000 != 0 || end.Nanosecond()%1000 != 0 {
				return fmt.Errorf("period must have start before end and microsecond-or-coarser precision")
			}
			var invoice billing.FinalInvoice
			if err := opener(cmd, func(ctx context.Context, raw store.Store) error {
				sql, ok := raw.(*store.SqlStore)
				if !ok {
					return fmt.Errorf("invoice finalization requires a SQL store")
				}
				billingStore, err := billing.NewStore(sql.GetDB())
				if err != nil {
					return err
				}
				relayUsageStore, err := relayusage.NewStore(sql.GetDB())
				if err != nil {
					return err
				}
				log, err := audit.New(sql.GetDB())
				if err != nil {
					return err
				}
				return sql.ExecuteInTransaction(ctx, func(tx store.Store) error {
					sqlTx, ok := tx.(*store.SqlStore)
					if !ok {
						return fmt.Errorf("invoice finalization requires a SQL transaction")
					}
					var account types.Account
					if err := sqlTx.GetDB().WithContext(ctx).Select("id").Where("id = ?", accountID).Take(&account).Error; err != nil {
						return fmt.Errorf("find account: %w", err)
					}
					accountCtx := billing.WithAccount(ctx, accountID)
					devices, err := (usage.Reporter{DB: sqlTx.GetDB()}).Devices(ctx, accountID, start, end)
					if err != nil {
						return fmt.Errorf("read device usage: %w", err)
					}
					relays, err := relayUsageStore.WithDB(sqlTx.GetDB()).Report(ctx, accountID, start, end)
					if err != nil {
						return fmt.Errorf("read managed relay usage: %w", err)
					}
					invoice, err = billingStore.WithDB(sqlTx.GetDB()).FinalizeInvoice(accountCtx, devices, relays)
					if err != nil {
						return err
					}
					detail, err := json.Marshal(struct {
						DeviceInputSHA256 string    `json:"device_input_sha256"`
						RelayInputSHA256  string    `json:"relay_input_sha256"`
						TotalMinor        int64     `json:"total_minor"`
						Currency          string    `json:"currency"`
						PeriodStart       time.Time `json:"period_start"`
						PeriodEnd         time.Time `json:"period_end"`
					}{invoice.DeviceInputHash, invoice.RelayInputHash, invoice.TotalMinor, invoice.Currency, invoice.PeriodStart, invoice.PeriodEnd})
					if err != nil {
						return fmt.Errorf("encode audit detail: %w", err)
					}
					_, err = log.AppendInTransaction(audit.WithAccount(accountCtx, accountID), sqlTx.GetDB(), "operator:"+actor, "karst.billing.invoice.finalize", accountID, string(detail))
					return err
				})
			}); err != nil {
				return err
			}
			return json.NewEncoder(cmd.OutOrStdout()).Encode(invoice)
		},
	}
	command.Flags().StringVar(&accountID, "account-id", "", "Account whose invoice is being finalized")
	command.Flags().StringVar(&actor, "actor", "", "Operator identity recorded in the audit log")
	command.Flags().StringVar(&startText, "period-start", "", "UTC month start in RFC3339 format")
	command.Flags().StringVar(&endText, "period-end", "", "Next UTC month start in RFC3339 format")
	for _, flag := range []string{"account-id", "actor", "period-start", "period-end"} {
		_ = command.MarkFlagRequired(flag)
	}
	return command
}

func validLabel(s string) bool {
	return len(s) > 0 && len(s) <= 128 && strings.TrimSpace(s) == s && strings.IndexFunc(s, unicode.IsControl) < 0
}
