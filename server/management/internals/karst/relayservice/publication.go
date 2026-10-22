// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package relayservice

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/netbirdio/netbird/management/internals/karst/relayreg"
	"github.com/netbirdio/netbird/management/internals/karst/turncred"
	"github.com/netbirdio/netbird/shared/management/proto"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Publication is a durable account-level authority choice. An absent record
// preserves legacy behavior; an explicitly empty service set never does.
type Publication struct {
	AccountID     string `gorm:"primaryKey;size:64" json:"-"`
	Mode          string `gorm:"not null" json:"mode"`
	SchemaVersion int    `gorm:"-" json:"schema_version,omitempty"`
}

func (Publication) TableName() string { return "karst_relay_publication" }

func publication(tx *gorm.DB, account string) (Publication, error) {
	value := Publication{AccountID: account, Mode: "legacy"}
	err := tx.Where("account_id = ?", account).First(&value).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return value, nil
	}
	if err != nil {
		return Publication{}, err
	}
	if value.Mode == "legacy-v2" || value.Mode == "services-v2" {
		value.Mode = strings.TrimSuffix(value.Mode, "-v2")
		value.SchemaVersion = 2
	}
	if value.Mode != "legacy" && value.Mode != "services" {
		return Publication{}, fmt.Errorf("%w: unknown publication mode", ErrInvalid)
	}
	return value, nil
}

func (s *Store) Publication(ctx context.Context) (Publication, error) {
	account, err := accountFromContext(ctx)
	if err != nil {
		return Publication{}, err
	}
	return publication(s.db.WithContext(ctx), account)
}

// Preview validates every selected backend without mutating configuration.
// It returns only association metadata; credentials and public identity keys
// stay in their protocol-specific stores and projections.
func (s *Store) Preview(ctx context.Context, turnConfigured bool) ([]Service, error) {
	account, err := accountFromContext(ctx)
	if err != nil {
		return nil, err
	}
	var services []Service
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var turns []turncred.Entry
		services, _, turns, err = project(tx, account, true)
		if err == nil && len(turns) > 0 && !turnConfigured {
			return fmt.Errorf("%w: TURN credential minting is not configured", ErrInvalid)
		}
		return err
	})
	return services, err
}

func (s *Store) SetPublication(ctx context.Context, mode string, turnConfigured bool) (Publication, error) {
	account, err := accountFromContext(ctx)
	if err != nil {
		return Publication{}, err
	}
	if mode != "legacy" && mode != "services" {
		return Publication{}, fmt.Errorf("%w: mode must be legacy or services", ErrInvalid)
	}
	value := Publication{AccountID: account, Mode: mode}
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if mode == "services" {
			_, _, turns, err := project(tx, account, true)
			if err != nil {
				return err
			}
			if len(turns) > 0 && !turnConfigured {
				return fmt.Errorf("%w: TURN credential minting is not configured", ErrInvalid)
			}
		}
		var disabled int64
		if err := tx.Model(&Service{}).Where("account_id = ? AND (ponor_disabled = ? OR turn_disabled = ?)", account, true, true).Count(&disabled).Error; err != nil {
			return err
		}
		if disabled > 0 {
			value.Mode += "-v2"
		}
		return tx.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "account_id"}}, DoUpdates: clause.AssignmentColumns([]string{"mode"})}).Create(&value).Error
	})
	if strings.HasSuffix(value.Mode, "-v2") {
		value.Mode = strings.TrimSuffix(value.Mode, "-v2")
		value.SchemaVersion = 2
	}
	return value, err
}

// Version the authority marker before writing mode semantics that older
// service-aware control cannot honor. Those versions reject unknown markers
// instead of silently republishing a disabled endpoint. Explicit publication
// selection can clear the marker after all mode flags have been reset.
func protectModeSchema(tx *gorm.DB, account string, current Publication) error {
	var disabled int64
	if err := tx.Model(&Service{}).Where("account_id = ? AND (ponor_disabled = ? OR turn_disabled = ?)", account, true, true).Count(&disabled).Error; err != nil {
		return err
	}
	if disabled == 0 || current.SchemaVersion == 2 {
		return nil
	}
	record := Publication{AccountID: account, Mode: current.Mode + "-v2"}
	return tx.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "account_id"}}, DoUpdates: clause.AssignmentColumns([]string{"mode"})}).Create(&record).Error
}

// Netmap projects the service model into existing authenticated wire fields.
// The boolean distinguishes legacy authority from an empty service projection.
func (s *Store) Netmap(ctx context.Context) (bool, []*proto.KarstRelay, []turncred.Entry, error) {
	account, err := accountFromContext(ctx)
	if err != nil {
		return false, nil, nil, err
	}
	active := false
	var relays []*proto.KarstRelay
	var turns []turncred.Entry
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		value, err := publication(tx, account)
		if err != nil {
			return err
		}
		active = value.Mode == "services"
		if !active {
			return nil
		}
		_, relays, turns, err = project(tx, account, false)
		return err
	})
	return active, relays, turns, err
}

func project(tx *gorm.DB, account string, strict bool) ([]Service, []*proto.KarstRelay, []turncred.Entry, error) {
	services := make([]Service, 0)
	if err := tx.Where("account_id = ?", account).Order("id").Find(&services).Error; err != nil {
		return nil, nil, nil, err
	}
	relays := make([]*proto.KarstRelay, 0)
	turns := make([]turncred.Entry, 0)
	seenPonor := map[string]bool{}
	seenTurn := map[string]bool{}
	configuredPonor := false
	for _, service := range services {
		if err := validate(service); err != nil {
			return nil, nil, nil, err
		}
		if !service.PonorDisabled {
			configuredPonor = true
		}
		if !service.PonorDisabled && !seenPonor[service.PonorID] {
			var backend relayreg.StoredRelay
			lookup := tx.Where("account_id = ? AND id = ?", account, service.PonorID).First(&backend).Error
			if errors.Is(lookup, gorm.ErrRecordNotFound) && !strict {
				// Withdraw this mode only; never replace it with a global entry.
			} else if lookup != nil {
				return nil, nil, nil, fmt.Errorf("%w: service %s Ponor backend unavailable", ErrInvalid, service.ID)
			} else {
				entry := relayreg.Entry{Address: backend.Address, TLSServerName: backend.TLSServerName, IdentityKey: backend.IdentityKey, Region: backend.Region}
				if backend.LocationLat != nil && backend.LocationLon != nil {
					entry.Location = &relayreg.Location{Lat: *backend.LocationLat, Lon: *backend.LocationLon, Label: backend.LocationLabel}
				}
				relay, err := relayreg.Compile(entry)
				if err != nil {
					return nil, nil, nil, fmt.Errorf("%w: service %s Ponor configuration invalid", ErrInvalid, service.ID)
				}
				if base64.RawURLEncoding.EncodeToString(relay.RelayId) != service.PonorID {
					return nil, nil, nil, fmt.Errorf("%w: service %s Ponor identity changed", ErrInvalid, service.ID)
				}
				relays = append(relays, relay)
			}
			seenPonor[service.PonorID] = true
		}
		if service.TurnID != "" && !service.TurnDisabled && !seenTurn[service.TurnID] {
			var backend turncred.StoredTurnServer
			lookup := tx.Where("account_id = ? AND id = ?", account, service.TurnID).First(&backend).Error
			if errors.Is(lookup, gorm.ErrRecordNotFound) && !strict {
				continue
			}
			if lookup != nil {
				return nil, nil, nil, fmt.Errorf("%w: service %s TURN backend unavailable", ErrInvalid, service.ID)
			}
			// Reject unsupported topology rather than publishing a known-broken path.
			if len(turns) > 0 {
				return nil, nil, nil, fmt.Errorf("%w: service publication currently requires one shared TURN backend per account", ErrInvalid)
			}
			if base64.RawURLEncoding.EncodeToString([]byte(backend.URI)) != service.TurnID {
				return nil, nil, nil, fmt.Errorf("%w: service %s TURN identity changed", ErrInvalid, service.ID)
			}
			target, supported := strings.CutPrefix(backend.URI, "turn:")
			host, port, addressErr := net.SplitHostPort(target)
			number, portErr := strconv.Atoi(port)
			if !supported || addressErr != nil || host == "" || strings.ContainsAny(target, "/?#@ \t\r\n") || portErr != nil || number < 1 || number > 65535 {
				return nil, nil, nil, fmt.Errorf("%w: service %s requires a UDP turn:host:port endpoint supported by current agents", ErrInvalid, service.ID)
			}
			// Reuse the legacy registry validator, including its URI and
			// default-region rules, without duplicating credential handling.
			raw, err := json.Marshal(struct {
				Turn []turncred.Entry `json:"turn"`
			}{Turn: []turncred.Entry{{URI: backend.URI, Region: backend.Region}}})
			if err != nil {
				return nil, nil, nil, err
			}
			entries, err := turncred.Parse(raw)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("%w: service %s TURN configuration invalid", ErrInvalid, service.ID)
			}
			turns = append(turns, entries...)
			seenTurn[service.TurnID] = true
		}
	}
	if len(turns) > 0 && !configuredPonor {
		return nil, nil, nil, fmt.Errorf("%w: TURN publication requires enabled Ponor bootstrap", ErrInvalid)
	}
	return services, relays, turns, nil
}
