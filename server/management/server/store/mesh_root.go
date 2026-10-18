// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package store

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/netbirdio/netbird/management/internals/modules/meshdomain"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

func (s *SqlStore) GetAccountRootDomain(ctx context.Context, lock LockingStrength, accountID string) (*meshdomain.Domain, error) {
	var account types.Account
	query := s.db.WithContext(ctx).Select("id", "root_domain_id")
	if lock != LockingStrengthNone {
		query = query.Clauses(clause.Locking{Strength: string(lock)})
	}
	if err := query.Where("id = ?", accountID).Take(&account).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.NewAccountNotFoundError(accountID)
		}
		return nil, fmt.Errorf("read account root reference: %w", err)
	}
	if account.RootDomainID == "" {
		return nil, nil
	}
	root, err := s.GetDomainByID(ctx, lock, accountID, account.RootDomainID)
	if err != nil {
		return nil, err
	}
	if !root.IsRoot() {
		return nil, fmt.Errorf("account %s root reference does not name a root", accountID)
	}
	if err := root.Validate(); err != nil {
		return nil, err
	}
	return root, nil
}

// InitializeMeshDomains runs before any management warmup or request handling.
// Each account commits independently; restart safely resumes after a failure.
// Mixed old/new management writers are unsupported during this migration.
func (s *SqlStore) InitializeMeshDomains(ctx context.Context, legacyDNSSuffix string) error {
	var ids []string
	if err := s.db.WithContext(ctx).Model(&types.Account{}).Order("id").Pluck("id", &ids).Error; err != nil {
		return err
	}
	for _, id := range ids {
		if err := s.migrateAccountRoot(ctx, id, legacyDNSSuffix); err != nil {
			return fmt.Errorf("mesh domain migration blocked for account %s: %w; reconcile the named DNS settings/references and restart before serving requests", id, err)
		}
	}
	return nil
}

func (s *SqlStore) migrateAccountRoot(ctx context.Context, accountID, fallback string) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var account types.Account
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("id = ?", accountID).Take(&account).Error; err != nil {
			return err
		}
		if account.RootDomainID != "" {
			// A restarted replica must not re-scan mutable child resources while
			// another current-version replica is serving requests. Only the stable
			// root and its account-row DNS projections need checking after migration.
			var root meshdomain.Domain
			if err := tx.Where("account_id = ? AND id = ?", accountID, account.RootDomainID).Take(&root).Error; err != nil {
				return fmt.Errorf("invalid root_domain_id reference: %w", err)
			}
			if !root.IsRoot() {
				return errors.New("root_domain_id does not reference a root")
			}
			if err := root.Validate(); err != nil {
				return err
			}
			if account.Settings == nil || account.Settings.DNSDomain != root.DNSSuffix || account.Network == nil || account.Network.Dns != root.DNSSuffix {
				return errors.New("account DNS projections disagree with the existing root suffix")
			}
			return nil
		}
		var domains []*meshdomain.Domain
		var peers []*nbpeer.Peer
		var keys []*types.SetupKey
		var bindings []*meshdomain.DomainRoleBinding
		for _, rows := range []any{&domains, &peers, &keys, &bindings} {
			if err := tx.Where("account_id = ?", accountID).Find(rows).Error; err != nil {
				return err
			}
		}
		byID := make(map[string]*meshdomain.Domain, len(domains))
		var root *meshdomain.Domain
		for _, d := range domains {
			if d.IsRoot() {
				if root != nil {
					return errors.New("multiple root domains")
				}
				root = d
			}
			if err := d.Validate(); err != nil {
				return fmt.Errorf("domain %s: %w", d.ID, err)
			}
			byID[d.ID] = d
		}
		if root != nil {
			return errors.New("root exists without its account root_domain_id reference")
		}

		suffix := ""
		sources := []struct{ name, value string }{}
		settingsSuffix := ""
		if account.Settings != nil {
			settingsSuffix = account.Settings.DNSDomain
		}
		loginSuffix := settingsSuffix
		if loginSuffix == "" {
			loginSuffix = fallback
		}
		sources = append(sources, struct{ name, value string }{"settings.dns_domain (or server --dns-domain fallback)", loginSuffix})
		if account.Network != nil {
			sources = append(sources, struct{ name, value string }{"network.dns", account.Network.Dns})
		}
		firstSource := ""
		for _, source := range sources {
			if source.value == "" {
				continue
			}
			canonical, err := meshdomain.CanonicalSuffix(source.value)
			if err != nil {
				return fmt.Errorf("%s: %w", source.name, err)
			}
			if suffix != "" && suffix != canonical {
				return fmt.Errorf("conflicting active suffixes: %s=%q, %s=%q", firstSource, suffix, source.name, canonical)
			}
			suffix, firstSource = canonical, source.name
		}
		if suffix == "" {
			if len(peers) > 0 {
				return errors.New("devices exist but no usable DNS suffix is configured")
			}
			suffix = meshdomain.DefaultRootSuffix
		}
		if root == nil {
			var err error
			root, err = meshdomain.NewRoot(accountID, suffix)
			if err != nil {
				return err
			}
		}
		// Validate the graph before changing a single persisted reference. Former
		// top-level domains keep their relative Path when attached to the root.
		for _, d := range domains {
			if d.IsRoot() {
				continue
			}
			expected := d.Label
			if d.ParentID != "" {
				parent := byID[d.ParentID]
				if parent == nil {
					return fmt.Errorf("domain %s has missing or foreign parent %s", d.ID, d.ParentID)
				}
				if parent.Path != "" {
					expected += "." + parent.Path
				}
			}
			if d.Path != expected {
				return fmt.Errorf("domain %s path %q disagrees with its parent graph", d.ID, d.Path)
			}
			seen := map[string]bool{}
			for current := d; current != nil; current = byID[current.ParentID] {
				if seen[current.ID] {
					return fmt.Errorf("domain %s has cyclic ancestry", d.ID)
				}
				seen[current.ID] = true
			}
		}
		siblings := map[string]bool{}
		for _, d := range domains {
			if d.IsRoot() {
				continue
			}
			parent := d.ParentID
			if parent == "" {
				parent = root.ID
			}
			key := parent + "/" + strings.ToLower(d.Label)
			if siblings[key] {
				return fmt.Errorf("domain %s has a duplicate sibling label", d.ID)
			}
			siblings[key] = true
		}
		labels := map[string]bool{}
		for _, peer := range peers {
			if peer.DomainID != "" {
				d := byID[peer.DomainID]
				if d == nil {
					return fmt.Errorf("device %s references missing or foreign domain %s", peer.ID, peer.DomainID)
				}
				if d.Path != "" && !strings.HasSuffix(peer.DNSLabel, "."+d.Path) {
					return fmt.Errorf("device %s name disagrees with its domain path", peer.ID)
				}
			}
			if err := meshdomain.ValidatePeerName(peer.DNSLabel, suffix); err != nil {
				return fmt.Errorf("device %s: %w", peer.ID, err)
			}
			label := strings.ToLower(peer.DNSLabel)
			if labels[label] {
				return fmt.Errorf("duplicate DNS label %q", label)
			}
			labels[label] = true
		}
		for _, key := range keys {
			if key.DomainID != "" && byID[key.DomainID] == nil && key.IsValid() {
				return fmt.Errorf("active enrollment key %s references missing or foreign domain %s", key.Id, key.DomainID)
			}
		}
		for _, binding := range bindings {
			if byID[binding.DomainID] == nil {
				return fmt.Errorf("delegation %s references missing or foreign domain %s; revoke it before migration", binding.ID, binding.DomainID)
			}
		}
		if err := tx.Create(root).Error; err != nil {
			return err
		}
		if err := tx.Model(&meshdomain.Domain{}).Where("account_id = ? AND (parent_id = '' OR parent_id IS NULL) AND id <> ?", accountID, root.ID).Update("parent_id", root.ID).Error; err != nil {
			return err
		}
		for _, model := range []any{&nbpeer.Peer{}, &types.SetupKey{}} {
			if err := tx.Model(model).Where("account_id = ? AND (domain_id = '' OR domain_id IS NULL)", accountID).Update("domain_id", root.ID).Error; err != nil {
				return err
			}
		}
		updates := map[string]any{"root_domain_id": root.ID, "settings_dns_domain": suffix, "network_dns": suffix}
		return tx.Model(&types.Account{}).Where("id = ?", accountID).Updates(updates).Error
	})
}

// saveRootInAccountTransaction is deliberately separate from GORM account
// associations: replacing an account snapshot must not delete its domain tree.
func saveRootInAccountTransaction(tx *gorm.DB, account *types.Account) error {
	var previous types.Account
	err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Select("id", "root_domain_id").Where("id = ?", account.Id).Take(&previous).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}
	if previous.RootDomainID != "" && account.RootDomainID != previous.RootDomainID {
		return errors.New("account root identity cannot be changed by SaveAccount")
	}
	if account.RootDomainID == "" {
		return nil
	} // legacy import; startup migration owns conversion
	var root meshdomain.Domain
	err = tx.Where("account_id = ? AND id = ?", account.Id, account.RootDomainID).Take(&root).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		if previous.RootDomainID != "" || account.RootDomain == nil {
			return errors.New("account root is missing")
		}
		root = *account.RootDomain
		if root.ID != account.RootDomainID || root.AccountID != account.Id || !root.IsRoot() {
			return errors.New("invalid new account root")
		}
		if err := root.Validate(); err != nil {
			return err
		}
		if err := tx.Create(&root).Error; err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if !root.IsRoot() {
		return errors.New("account root reference does not name a root")
	}
	if err := root.Validate(); err != nil {
		return err
	}
	if account.RootDomain != nil && account.RootDomain.DNSSuffix != root.DNSSuffix {
		return errors.New("root rename requires the root naming API")
	}
	if account.Settings == nil {
		account.Settings = &types.Settings{DNSDomain: root.DNSSuffix}
	}
	if account.Settings.DNSDomain != root.DNSSuffix {
		return errors.New("DNS suffix changes require the root naming API")
	}
	if account.Network == nil {
		account.Network = &types.Network{Dns: root.DNSSuffix}
	}
	if account.Network != nil && account.Network.Dns != root.DNSSuffix {
		return errors.New("network DNS suffix disagrees with account root")
	}
	account.RootDomain = &root
	return nil
}
