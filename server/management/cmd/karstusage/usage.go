// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// Package karstusage provides operator-only collection controls. Authority is
// possession of the server's configuration and database access, just like the
// existing admin token/proxy commands; no customer API changes collection state.
package karstusage

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"unicode"

	"github.com/spf13/cobra"

	"github.com/netbirdio/netbird/management/internals/karst/audit"
	"github.com/netbirdio/netbird/management/internals/karst/identity"
	"github.com/netbirdio/netbird/management/internals/karst/relayusage"
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
	root.AddCommand(newRelayCommands(opener))
	return root
}

func newRelayCommands(opener StoreOpener) *cobra.Command {
	root := &cobra.Command{Use: "relays", Short: "Authorize managed relay usage producers and mapping scope"}
	authorize := &cobra.Command{Use: "authorize", Short: "Authorize a relay identity for managed usage", Args: cobra.NoArgs}
	var publicKeyText, deployment, actor string
	authorize.Flags().StringVar(&publicKeyText, "identity-key", "", "Base64 ML-DSA-87 relay public identity key")
	authorize.Flags().StringVar(&deployment, "deployment-id", "", "Managed deployment this relay may report for")
	authorize.Flags().StringVar(&actor, "actor", "", "Operator identity recorded in the audit log")
	authorize.RunE = func(cmd *cobra.Command, _ []string) error {
		publicKey, err := base64.StdEncoding.DecodeString(publicKeyText)
		if err != nil || base64.StdEncoding.EncodeToString(publicKey) != publicKeyText || len(publicKey) != identity.PublicKeySize {
			return fmt.Errorf("provide --identity-key as the canonical base64 ML-DSA-87 public key")
		}
		if !validLabel(deployment) || !validLabel(actor) {
			return fmt.Errorf("provide valid --deployment-id and --actor labels")
		}
		relayID, err := runRelayMutation(cmd, opener, actor, "authorize", "", "deployment="+deployment,
			func(relays *relayusage.Store) (string, error) {
				return relays.AuthorizeProducer(cmd.Context(), publicKey, deployment)
			})
		if err != nil {
			return err
		}
		return json.NewEncoder(cmd.OutOrStdout()).Encode(struct {
			RelayID      string `json:"relay_id"`
			DeploymentID string `json:"deployment_id"`
			Enabled      bool   `json:"enabled"`
		}{RelayID: relayID, DeploymentID: deployment, Enabled: true})
	}

	revoke := &cobra.Command{Use: "revoke", Short: "Revoke managed usage reporting for a relay", Args: cobra.NoArgs}
	var revokeID, revokeActor string
	revoke.Flags().StringVar(&revokeID, "relay-id", "", "Derived relay identity ID")
	revoke.Flags().StringVar(&revokeActor, "actor", "", "Operator identity recorded in the audit log")
	revoke.RunE = func(cmd *cobra.Command, _ []string) error {
		if !validRelayID(revokeID) || !validLabel(revokeActor) {
			return fmt.Errorf("provide a valid --relay-id and --actor")
		}
		_, err := runRelayMutation(cmd, opener, revokeActor, "revoke", revokeID, "",
			func(relays *relayusage.Store) (string, error) {
				return revokeID, relays.RevokeProducer(cmd.Context(), revokeID)
			})
		return err
	}

	allow := &cobra.Command{Use: "allow-mapping", Short: "Allow one exact account mapping reference for a relay", Args: cobra.NoArgs}
	var mappingRelay, mappingDeployment, mappingVersion, mappingActor string
	allow.Flags().StringVar(&mappingRelay, "relay-id", "", "Derived relay identity ID")
	allow.Flags().StringVar(&mappingDeployment, "deployment-id", "", "Deployment owning the mapping")
	allow.Flags().StringVar(&mappingVersion, "mapping-version", "", "Immutable mapping version from the roster ledger")
	allow.Flags().StringVar(&mappingActor, "actor", "", "Operator identity recorded in the audit log")
	allow.RunE = func(cmd *cobra.Command, _ []string) error {
		if !validRelayID(mappingRelay) || !validLabel(mappingDeployment) || !validMappingVersion(mappingVersion) || !validLabel(mappingActor) {
			return fmt.Errorf("provide valid --relay-id, --deployment-id, --mapping-version and --actor values")
		}
		detail := "deployment=" + mappingDeployment + " mapping=" + mappingVersion
		_, err := runRelayMutation(cmd, opener, mappingActor, "allow-mapping", mappingRelay, detail,
			func(relays *relayusage.Store) (string, error) {
				return mappingRelay, relays.AllowMapping(cmd.Context(), mappingRelay, mappingDeployment, mappingVersion)
			})
		return err
	}

	revokeMapping := &cobra.Command{Use: "revoke-mapping", Short: "Revoke one exact account mapping reference for a relay", Args: cobra.NoArgs}
	var revokeMappingRelay, revokeMappingDeployment, revokeMappingVersion, revokeMappingActor string
	revokeMapping.Flags().StringVar(&revokeMappingRelay, "relay-id", "", "Derived relay identity ID")
	revokeMapping.Flags().StringVar(&revokeMappingDeployment, "deployment-id", "", "Deployment owning the mapping")
	revokeMapping.Flags().StringVar(&revokeMappingVersion, "mapping-version", "", "Immutable mapping version from the roster ledger")
	revokeMapping.Flags().StringVar(&revokeMappingActor, "actor", "", "Operator identity recorded in the audit log")
	revokeMapping.RunE = func(cmd *cobra.Command, _ []string) error {
		if !validRelayID(revokeMappingRelay) || !validLabel(revokeMappingDeployment) || !validMappingVersion(revokeMappingVersion) || !validLabel(revokeMappingActor) {
			return fmt.Errorf("provide valid --relay-id, --deployment-id, --mapping-version and --actor values")
		}
		detail := "deployment=" + revokeMappingDeployment + " mapping=" + revokeMappingVersion
		_, err := runRelayMutation(cmd, opener, revokeMappingActor, "revoke-mapping", revokeMappingRelay, detail,
			func(relays *relayusage.Store) (string, error) {
				return revokeMappingRelay, relays.RevokeMapping(cmd.Context(), revokeMappingRelay, revokeMappingDeployment, revokeMappingVersion)
			})
		return err
	}
	root.AddCommand(authorize, revoke, allow, revokeMapping)
	return root
}

func runRelayMutation(cmd *cobra.Command, opener StoreOpener, actor, action, target, detail string, mutate func(*relayusage.Store) (string, error)) (string, error) {
	var result string
	err := opener(cmd, func(ctx context.Context, raw store.Store) error {
		sql, ok := raw.(*store.SqlStore)
		if !ok {
			return fmt.Errorf("managed relay usage requires a SQL store")
		}
		base, err := relayusage.NewStore(sql.GetDB())
		if err != nil {
			return err
		}
		log, err := audit.New(sql.GetDB())
		if err != nil {
			return err
		}
		return sql.ExecuteInTransaction(ctx, func(tx store.Store) error {
			transaction, ok := tx.(*store.SqlStore)
			if !ok {
				return fmt.Errorf("managed relay usage requires a SQL transaction")
			}
			id, err := mutate(base.WithDB(transaction.GetDB()))
			if err != nil {
				return err
			}
			result = id
			if target == "" {
				target = id
			}
			_, err = log.AppendInTransaction(ctx, transaction.GetDB(), "operator:"+actor, "karst.usage.relay."+action, target, detail)
			return err
		})
	})
	return result, err
}

func validRelayID(id string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(id)
	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == id
}

func validMappingVersion(version string) bool {
	decoded, err := hex.DecodeString(version)
	return err == nil && len(decoded) == 32 && hex.EncodeToString(decoded) == version
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
