// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package relayservice

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/netip"
	"time"

	"github.com/netbirdio/netbird/management/internals/karst/policy"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/route"
	"github.com/netbirdio/netbird/shared/management/proto"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// AdmissionLease advertises a live, identity-bound roster writer. It is written
// only by the operator's local refresher, never by an administrative API.
type actorKey struct{}

func WithActor(ctx context.Context, actor string) context.Context {
	return context.WithValue(ctx, actorKey{}, actor)
}

type AdmissionLease struct {
	RelayID     string    `gorm:"primaryKey" json:"relay_id"`
	RefreshedAt time.Time `json:"refreshed_at"`
}

func (AdmissionLease) TableName() string { return "karst_relay_admission_leases" }

const AdmissionLeaseAge = 50 * time.Second

func (s *Store) RefreshAdmissionLease(relayID string) error {
	value := AdmissionLease{RelayID: relayID, RefreshedAt: time.Now().UTC()}
	return s.db.Clauses(clause.OnConflict{UpdateAll: true}).Create(&value).Error
}
func (s *Store) AdmissionTargets(ctx context.Context) ([]AdmissionLease, error) {
	account, err := accountFromContext(ctx)
	if err != nil {
		return nil, err
	}
	var targets []AdmissionLease
	err = s.db.WithContext(ctx).Table("karst_relay_admission_leases AS lease").Select("lease.*").Joins("JOIN karst_relays AS relay ON relay.id = lease.relay_id").Where("relay.account_id = ? AND lease.refreshed_at > ?", account, time.Now().Add(-AdmissionLeaseAge)).Scan(&targets).Error
	return targets, err
}

func (s *Store) configureAccess(ctx context.Context, tx *gorm.DB, service Service) error {
	if !service.AccessManaged {
		return nil
	}
	if len(service.AllowedGroups) == 0 {
		return fmt.Errorf("%w: choose at least one allowed group", ErrInvalid)
	}
	var lease AdmissionLease
	if err := tx.Where("relay_id = ? AND refreshed_at > ?", service.PonorID, time.Now().Add(-AdmissionLeaseAge)).First(&lease).Error; err != nil {
		return fmt.Errorf("%w: this relay has no live identity-bound admission writer", ErrInvalid)
	}
	mode, err := publication(tx, service.AccountID)
	if err != nil {
		return err
	}
	if mode.Mode != "services" {
		return fmt.Errorf("%w: preview and enable service publication before configuring group access", ErrInvalid)
	}
	var existing int64
	if err := tx.Model(&Service{}).Where("account_id = ? AND ponor_id = ? AND id <> ?", service.AccountID, service.PonorID, service.ID).Count(&existing).Error; err != nil {
		return err
	}
	if existing != 0 {
		return fmt.Errorf("%w: backend is shared by another service; consolidate its association first", ErrInvalid)
	}
	for _, id := range service.AllowedGroups {
		var count int64
		if err := tx.Model(&types.Group{}).Where("account_id = ? AND id = ?", service.AccountID, id).Count(&count).Error; err != nil {
			return err
		}
		if count != 1 {
			return fmt.Errorf("%w: selected group is unavailable in this account", ErrInvalid)
		}
	}
	access := BackendAccess{AccountID: service.AccountID, RelayID: service.PonorID, Groups: service.AllowedGroups}
	if err := tx.Clauses(clause.OnConflict{UpdateAll: true}).Create(&access).Error; err != nil {
		return err
	}
	if mode.SchemaVersion != 3 {
		marker := Publication{AccountID: service.AccountID, Mode: mode.Mode + "-v3"}
		if err := tx.Clauses(clause.OnConflict{UpdateAll: true}).Create(&marker).Error; err != nil {
			return err
		}
	}
	if !service.ExitIPv4 && !service.ExitIPv6 {
		return nil
	}
	if service.GatewayHandle == "" {
		return fmt.Errorf("%w: select the enrolled Gateway machine explicitly", ErrInvalid)
	}
	var gateway nbpeer.Peer
	if err := tx.Where("account_id = ? AND key = ?", service.AccountID, service.GatewayHandle).First(&gateway).Error; err != nil {
		return fmt.Errorf("%w: Gateway machine is unavailable in this account", ErrInvalid)
	}
	if gateway.Meta.GoOS != "linux" {
		return fmt.Errorf("%w: internet egress requires a Linux Gateway machine", ErrInvalid)
	}
	if len(service.ID) > 40 {
		return fmt.Errorf("%w: exit service name must fit within 40 characters", ErrInvalid)
	}
	metric := service.Metric
	if metric == 0 {
		metric = 9999
	}
	if metric < 1 || metric > 9999 {
		return fmt.Errorf("%w: priority must be between 1 and 9999", ErrInvalid)
	}
	var prefixes []string
	if service.ExitIPv4 {
		prefixes = append(prefixes, "0.0.0.0/0")
	}
	if service.ExitIPv6 {
		prefixes = append(prefixes, "::/0")
	}
	doc, version, err := currentDocument(tx, service.AccountID)
	if err != nil {
		return err
	}
	grant := policy.Grant{ID: "relay-exit-" + service.ID, Name: service.ID + " internet egress", SourceGroups: service.AllowedGroups, Gateway: service.GatewayHandle, Networks: prefixes, Ports: "*"}
	doc.Grants = append(doc.Grants, grant)
	for i, p := range prefixes {
		prefix, _ := netip.ParsePrefix(p)
		kind := route.IPv4Network
		if prefix.Addr().Is6() {
			kind = route.IPv6Network
		}
		r := route.Route{ID: route.ID(fmt.Sprintf("relay-exit-%s-%d", service.ID, i)), AccountID: service.AccountID, NetID: route.NetID(service.ID), Description: "Managed internet egress", Network: prefix, NetworkType: kind, Peer: gateway.ID, Groups: service.AllowedGroups, AccessControlGroups: service.AllowedGroups, Enabled: true, Masquerade: true, Metric: metric, SkipAutoApply: true}
		if err := tx.Create(&r).Error; err != nil {
			return err
		}
	}
	return writeDocument(tx, service.AccountID, doc, version)
}

func currentDocument(tx *gorm.DB, account string) (*policy.Document, uint64, error) {
	var current policy.Version
	err := tx.Where("account_id = ?", account).Order("version DESC").First(&current).Error
	if err == gorm.ErrRecordNotFound {
		return &policy.Document{}, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}
	doc, err := policy.Parse([]byte(current.Document))
	return doc, current.Version, err
}
func writeDocument(tx *gorm.DB, account string, doc *policy.Document, version uint64) error {
	data, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	// Use the existing immutable ledger and optimistic concurrency contract,
	// on the same transaction as association and route creation.
	author, _ := tx.Statement.Context.Value(actorKey{}).(string)
	if author == "" {
		author = "resource-allocation"
	}
	_, err = policy.TransactionStore(tx).Write(policy.WithAccount(tx.Statement.Context, account), string(data), author, version)
	return err
}

// BackendAccess survives deletion of the association: removing a managed
// service must withdraw access rather than reopen legacy account-wide admission.
type BackendAccess struct {
	AccountID string   `gorm:"primaryKey"`
	RelayID   string   `gorm:"primaryKey"`
	Groups    []string `gorm:"serializer:json"`
}

func (BackendAccess) TableName() string { return "karst_relay_backend_access" }

// AllowedOnManagedRelay is the installation writer's default-deny variant.
// Legacy/unconfigured tenants never inherit account-wide admission here.
func (s *Store) AllowedOnManagedRelay(ctx context.Context, relayID, account, handle string) (bool, error) {
	var count int64
	if err := s.db.WithContext(ctx).Model(&BackendAccess{}).Where("account_id = ? AND relay_id = ?", account, relayID).Count(&count).Error; err != nil {
		return false, err
	}
	if count == 0 {
		return false, nil
	}
	return s.AllowedOnRelay(ctx, relayID, account, handle)
}

func (s *Store) AllowedOnRelay(ctx context.Context, relayID, account, handle string) (bool, error) {
	var access BackendAccess
	err := s.db.WithContext(ctx).Where("account_id = ? AND relay_id = ?", account, relayID).First(&access).Error
	if err == gorm.ErrRecordNotFound {
		var managed int64
		if err := s.db.WithContext(ctx).Model(&BackendAccess{}).Where("relay_id = ?", relayID).Count(&managed).Error; err != nil {
			return false, err
		}
		if managed == 0 {
			return true, nil
		}
		var registered int64
		err := s.db.WithContext(ctx).Table("karst_relays").Where("account_id = ? AND id = ?", account, relayID).Count(&registered).Error
		return registered > 0, err
	}
	if err != nil {
		return false, err
	}
	var enabled int64
	if err := s.db.WithContext(ctx).Model(&Service{}).Where("account_id = ? AND ponor_id = ? AND access_managed = ? AND ponor_disabled = ?", account, relayID, true, false).Count(&enabled).Error; err != nil {
		return false, err
	}
	if enabled == 0 || len(access.Groups) == 0 {
		return false, nil
	}
	var infrastructure int64
	if err := s.db.WithContext(ctx).Model(&Service{}).Where("account_id = ? AND ponor_id = ? AND gateway_handle = ? AND access_managed = ? AND ponor_disabled = ? AND (exit_ipv4 = ? OR exit_ipv6 = ?)", account, relayID, handle, true, false, true, true).Count(&infrastructure).Error; err != nil {
		return false, err
	}
	if infrastructure > 0 {
		var active int64
		err := s.db.WithContext(ctx).Table("peers AS peer").Joins("JOIN users AS owner ON owner.id = peer.user_id AND owner.account_id = peer.account_id").Where("peer.account_id = ? AND peer.key = ? AND owner.blocked = ? AND owner.pending_approval = ?", account, handle, false, false).Count(&active).Error
		return active > 0, err
	}
	var count int64
	err = s.db.WithContext(ctx).Table("group_peers AS membership").Joins("JOIN groups AS grp ON grp.id = membership.group_id AND grp.account_id = membership.account_id").Joins("JOIN peers AS peer ON peer.id = membership.peer_id AND peer.account_id = membership.account_id").Joins("JOIN users AS owner ON owner.id = peer.user_id AND owner.account_id = peer.account_id").Where("owner.blocked = ? AND owner.pending_approval = ?", false, false).Where("membership.account_id = ? AND membership.group_id IN ? AND peer.key = ?", account, access.Groups, handle).Count(&count).Error
	return count > 0, err
}

func (s *Store) FilterForPeer(ctx context.Context, peerID string, relays []*proto.KarstRelay) ([]*proto.KarstRelay, error) {
	account, err := accountFromContext(ctx)
	if err != nil {
		return nil, err
	}
	var relayIDs []string
	for _, relay := range relays {
		relayIDs = append(relayIDs, base64.RawURLEncoding.EncodeToString(relay.RelayId))
	}
	if len(relayIDs) == 0 {
		return relays, nil
	}
	var scoped int64
	if err := s.db.WithContext(ctx).Model(&BackendAccess{}).Where("relay_id IN ?", relayIDs).Count(&scoped).Error; err != nil {
		return nil, err
	}
	if scoped == 0 {
		return relays, nil
	}
	var peer nbpeer.Peer
	if err := s.db.WithContext(ctx).Where("account_id = ? AND id = ?", account, peerID).First(&peer).Error; err != nil {
		return nil, err
	}
	out := make([]*proto.KarstRelay, 0, len(relays))
	for _, relay := range relays {
		ok, err := s.AllowedOnRelay(ctx, base64.RawURLEncoding.EncodeToString(relay.RelayId), account, peer.Key)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, relay)
		}
	}
	return out, nil
}

func clearManagedExit(tx *gorm.DB, service Service) error {
	if !service.AccessManaged {
		return nil
	}
	doc, version, err := currentDocument(tx, service.AccountID)
	if err != nil {
		return err
	}
	kept := make([]policy.Grant, 0, len(doc.Grants))
	changed := false
	for _, grant := range doc.Grants {
		if grant.ID == "relay-exit-"+service.ID {
			changed = true
		} else {
			kept = append(kept, grant)
		}
	}
	if changed {
		doc.Grants = kept
		if err := writeDocument(tx, service.AccountID, doc, version); err != nil {
			return err
		}
	}
	if tx.Migrator().HasTable(&route.Route{}) {
		return tx.Where("account_id = ? AND id IN ?", service.AccountID, []string{"relay-exit-" + service.ID + "-0", "relay-exit-" + service.ID + "-1"}).Delete(&route.Route{}).Error
	}
	return nil
}

func (s *Store) UpdateAccess(ctx context.Context, id string, desired Service) (*Service, error) {
	account, err := accountFromContext(ctx)
	if err != nil {
		return nil, err
	}
	var current Service
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("account_id = ? AND id = ?", account, id).First(&current).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				return ErrNotFound
			}
			return err
		}
		if desired.Revision != current.Revision {
			return fmt.Errorf("%w: service changed; reload before saving", ErrExists)
		}
		if err := clearManagedExit(tx, current); err != nil {
			return err
		}
		current.AccessManaged = true
		current.AllowedGroups = desired.AllowedGroups
		current.GatewayHandle = desired.GatewayHandle
		current.ExitIPv4 = desired.ExitIPv4
		current.ExitIPv6 = desired.ExitIPv6
		current.Metric = desired.Metric
		if err := s.configureAccess(ctx, tx, current); err != nil {
			return err
		}
		expected := current.Revision
		current.Revision++
		result := tx.Model(&Service{}).Where("account_id = ? AND id = ? AND revision = ?", account, id, expected).Select("access_managed", "allowed_groups", "gateway_handle", "exit_ipv4", "exit_ipv6", "metric", "revision").Updates(&current)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return ErrExists
		}
		return nil
	})
	return &current, err
}
