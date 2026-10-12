// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// Package karstbilling provides explicit pilot billing schedule assignment
// for self-hosted deployment operators. It does not issue invoices or charges.
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
	return root
}

func validLabel(s string) bool {
	return len(s) > 0 && len(s) <= 128 && strings.TrimSpace(s) == s && strings.IndexFunc(s, unicode.IsControl) < 0
}
