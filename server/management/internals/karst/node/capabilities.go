// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package node

import (
	"context"
	"fmt"
	"gorm.io/gorm"
)

// SetEstavelleLifecycleSchema records a declaration for an identity authenticated
// by the control channel. A later legacy declaration replaces an earlier one;
// upgrading once must not permanently claim support after a downgrade.
func (s *Store) SetEstavelleLifecycleSchema(ctx context.Context, handle string, schema uint32) error {
	result := s.db.WithContext(ctx).Model(&Identity{}).Where("handle = ?", handle).Update("estavelle_lifecycle_schema", schema)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		_, err := s.Get(handle)
		return err
	}
	return nil
}

// CheckEstavelleLifecycle covers every enrolled Karst peer in this account,
// including offline/unknown agents. Generic inherited peers without a Karst
// identity do not consume Karst transport configuration and are excluded.
func (s *Store) CheckEstavelleLifecycle(ctx context.Context, account string, transaction *gorm.DB) error {
	count, err := s.CountEstavelleLifecycleBelow(ctx, account, 1, transaction)
	if err != nil {
		return err
	}
	if count != 0 {
		return fmt.Errorf("%d enrolled Karst agents have not reported Relay lifecycle schema 1; upgrade them and refresh their netmaps, or remove retired agents", count)
	}
	return nil
}

// SetAvenIngressSchema records a declaration for an identity
// authenticated by the control channel, mirroring SetEstavelleLifecycleSchema
// above exactly: a later legacy declaration replaces an earlier one, so
// upgrading once must not permanently claim support after a downgrade.
func (s *Store) SetAvenIngressSchema(ctx context.Context, handle string, schema uint32) error {
	result := s.db.WithContext(ctx).Model(&Identity{}).Where("handle = ?", handle).Update("aven_ingress_schema", schema)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		_, err := s.Get(handle)
		return err
	}
	return nil
}

// CountEstavelleLifecycleBelow counts enrolled Karst peers (as CheckEstavelleLifecycle
// above) whose reported relay_lifecycle_schema is below required. Parameterized
// rather than hardcoded so callers outside this package -- a rollout plan's
// cross-component compatibility preview, in particular -- can ask "how many
// fleet members would be incompatible with this target schema" for a schema
// value that is not yet, and may never be, the account-wide minimum
// CheckEstavelleLifecycle itself enforces.
func (s *Store) CountEstavelleLifecycleBelow(ctx context.Context, account string, required uint32, transaction *gorm.DB) (int64, error) {
	return s.countCapabilityBelow(ctx, account, "estavelle_lifecycle_schema", required, transaction)
}

// CountAvenIngressBelow is CountEstavelleLifecycleBelow's gateway_ingress_schema
// counterpart.
func (s *Store) CountAvenIngressBelow(ctx context.Context, account string, required uint32, transaction *gorm.DB) (int64, error) {
	return s.countCapabilityBelow(ctx, account, "aven_ingress_schema", required, transaction)
}

// SetDnsZoneAffinitySchema records a declaration for an identity
// authenticated by the control channel, mirroring SetAvenIngressSchema
// above exactly: a later legacy declaration replaces an earlier one, so
// upgrading once must not permanently claim support after a downgrade.
func (s *Store) SetDnsZoneAffinitySchema(ctx context.Context, handle string, schema uint32) error {
	result := s.db.WithContext(ctx).Model(&Identity{}).Where("handle = ?", handle).Update("dns_zone_affinity_schema", schema)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		_, err := s.Get(handle)
		return err
	}
	return nil
}

// CountDnsZoneAffinityBelow is CountEstavelleLifecycleBelow's dns_zone_affinity_schema
// counterpart.
func (s *Store) CountDnsZoneAffinityBelow(ctx context.Context, account string, required uint32, transaction *gorm.DB) (int64, error) {
	return s.countCapabilityBelow(ctx, account, "dns_zone_affinity_schema", required, transaction)
}

func (s *Store) countCapabilityBelow(ctx context.Context, account, column string, required uint32, transaction *gorm.DB) (int64, error) {
	db := s.db
	if transaction != nil {
		db = transaction
	}
	if account == "" {
		return 0, fmt.Errorf("agent capability check requires an account")
	}
	var count int64
	err := db.WithContext(ctx).Table("karst_node_identities AS identity").
		Joins("JOIN peers AS peer ON peer.key = identity.handle").
		Where("peer.account_id = ? AND identity."+column+" < ?", account, required).Count(&count).Error
	if err != nil {
		return 0, err
	}
	return count, nil
}
