// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package usage

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var ErrMapping = errors.New("usage: invalid or unresolved relay mapping")

// RelayMapping is immutable attribution evidence, not authorization for a relay
// to submit usage. Managed producer authorization must separately allow this
// deployment and mapping. Historical records survive account/roster deletion.
type RelayMapping struct {
	DeploymentID string `gorm:"primaryKey;size:128"`
	Version      string `gorm:"primaryKey;size:64"`
	Aquifer      string `gorm:"size:1024;not null"`
	AccountID    string `gorm:"size:128;not null"`
}

func (RelayMapping) TableName() string { return "karst_usage_relay_mappings" }

// PersistRelayMapping must commit before a roster publishes the returned
// version. A mapping change produces a different reference; delayed reports
// resolve the old reference without consulting current membership or parsing
// an aquifer prefix. The caller supplies authoritative account ownership.
func PersistRelayMapping(ctx context.Context, db *gorm.DB, deployment, aquifer, account string) (RelayMapping, error) {
	m := RelayMapping{DeploymentID: deployment, Aquifer: aquifer, AccountID: account}
	if !mappingLabel(deployment, 128) || !mappingLabel(account, 128) || !mappingLabel(aquifer, 1024) {
		return RelayMapping{}, ErrMapping
	}
	h := sha256.New()
	h.Write([]byte("karst-relay-account-mapping-v1\x00"))
	for _, field := range []string{deployment, aquifer, account} {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(field)))
		h.Write(size[:])
		h.Write([]byte(field))
	}
	m.Version = hex.EncodeToString(h.Sum(nil))
	if err := db.WithContext(ctx).Clauses(clause.OnConflict{DoNothing: true}).Create(&m).Error; err != nil {
		return RelayMapping{}, err
	}
	stored, err := ResolveRelayMapping(ctx, db, deployment, m.Version)
	if err != nil {
		return RelayMapping{}, err
	}
	if stored != m {
		return RelayMapping{}, ErrMapping
	}
	return stored, nil
}

// ResolveRelayMapping performs an exact, deployment-scoped historical lookup.
// Missing references remain unresolved and must not be treated as zero usage.
func ResolveRelayMapping(ctx context.Context, db *gorm.DB, deployment, version string) (RelayMapping, error) {
	if !mappingLabel(deployment, 128) || len(version) != 64 {
		return RelayMapping{}, ErrMapping
	}
	decoded, err := hex.DecodeString(version)
	if err != nil || hex.EncodeToString(decoded) != version {
		return RelayMapping{}, ErrMapping
	}
	var m RelayMapping
	err = db.WithContext(ctx).Where("deployment_id = ? AND version = ?", deployment, version).Take(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return RelayMapping{}, ErrMapping
	}
	return m, err
}

func mappingLabel(value string, limit int) bool {
	return len(value) > 0 && len(value) <= limit && utf8.ValidString(value) && strings.TrimSpace(value) == value && strings.IndexFunc(value, unicode.IsControl) < 0
}
