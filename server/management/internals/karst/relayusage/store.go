// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package relayusage

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/netbirdio/netbird/management/internals/karst/identity"
	"github.com/netbirdio/netbird/management/internals/karst/relayreg"
	"github.com/netbirdio/netbird/management/internals/karst/usage"
)

const uploadFreshness = 5 * time.Minute

var (
	ErrProducerMissing   = errors.New("relay usage: managed producer not authorized")
	ErrProducerConflict  = errors.New("relay usage: managed producer identity conflict")
	ErrMappingNotAllowed = errors.New("relay usage: mapping reference not authorized")
	ErrRequestReplay     = errors.New("relay usage: upload request replayed")
	ErrBatchConflict     = errors.New("relay usage: batch identity has conflicting content")
)

// ManagedProducer is explicitly operator-authorized. The customer relay
// registry is deliberately not consulted for billing authority.
type ManagedProducer struct {
	RelayID      string `gorm:"primaryKey;size:64"`
	DeploymentID string `gorm:"size:128;not null;index"`
	IdentityKey  string `gorm:"size:4096;not null"`
	Enabled      bool   `gorm:"not null;index"`
	UpdatedAt    time.Time
}

func (ManagedProducer) TableName() string { return "karst_usage_managed_producers" }

// AllowedMapping grants one managed producer authority to submit one exact,
// historical deployment mapping reference. It never grants authority over an
// arbitrary account or aquifer supplied by the relay.
type AllowedMapping struct {
	RelayID      string `gorm:"primaryKey;size:64"`
	DeploymentID string `gorm:"primaryKey;size:128"`
	Version      string `gorm:"primaryKey;size:64"`
	Enabled      bool   `gorm:"not null;index"`
	AllowedAt    time.Time
	RevokedAt    *time.Time
}

func (AllowedMapping) TableName() string { return "karst_usage_producer_mappings" }

// producerMappingInterval is durable authorization evidence used to decide
// which account-minute windows an explicitly authorized managed producer was
// expected to report. Closed intervals are retained; this does not assert that
// every managed relay is enrolled.
type producerMappingInterval struct {
	ID           uint64 `gorm:"primaryKey"`
	RelayID      string `gorm:"size:64;not null;uniqueIndex:idx_relay_usage_authorization_period"`
	DeploymentID string `gorm:"size:128;not null;uniqueIndex:idx_relay_usage_authorization_period"`
	Version      string `gorm:"size:64;not null;uniqueIndex:idx_relay_usage_authorization_period"`
	AccountID    string `gorm:"size:128;not null;index"`
	StartUS      int64  `gorm:"not null;uniqueIndex:idx_relay_usage_authorization_period"`
	EndUS        *int64 `gorm:"index"`
}

func (producerMappingInterval) TableName() string { return "karst_usage_producer_mapping_periods" }

type authorizationHistory struct {
	ID          uint8 `gorm:"primaryKey"`
	StartedAtUS int64 `gorm:"not null"`
}

func (authorizationHistory) TableName() string { return "karst_usage_authorization_history" }

type receivedBatch struct {
	DeploymentID string    `gorm:"primaryKey;size:128"`
	RelayID      string    `gorm:"primaryKey;size:64"`
	Epoch        string    `gorm:"primaryKey;size:32"`
	Sequence     string    `gorm:"primaryKey;size:20"`
	Digest       []byte    `gorm:"size:32;not null"`
	StartUS      int64     `gorm:"not null;index"`
	EndUS        int64     `gorm:"not null;index"`
	Gaps         uint8     `gorm:"not null"`
	ReceivedAt   time.Time `gorm:"not null;index"`
}

func (receivedBatch) TableName() string { return "karst_usage_relay_batches" }

type receivedTotal struct {
	DeploymentID string `gorm:"primaryKey;size:128"`
	RelayID      string `gorm:"primaryKey;size:64"`
	Epoch        string `gorm:"primaryKey;size:32"`
	Sequence     string `gorm:"primaryKey;size:20"`
	MappingKey   string `gorm:"primaryKey;size:64"`
	Version      string `gorm:"size:64;not null"`
	Aquifer      string `gorm:"size:1024;not null"`
	AccountID    string `gorm:"size:128;not null;index"`
	BytesDecimal string `gorm:"size:20;not null"`
}

func (receivedTotal) TableName() string { return "karst_usage_relay_batch_totals" }

type receivedCoverage struct {
	DeploymentID string `gorm:"primaryKey;size:128"`
	RelayID      string `gorm:"primaryKey;size:64"`
	Epoch        string `gorm:"primaryKey;size:32"`
	Sequence     string `gorm:"primaryKey;size:20"`
	AccountID    string `gorm:"primaryKey;size:128"`
	StartUS      int64  `gorm:"not null;index"`
	EndUS        int64  `gorm:"not null;index"`
	Gaps         uint8  `gorm:"not null"`
}

func (receivedCoverage) TableName() string { return "karst_usage_relay_batch_coverage" }

type uploadNonce struct {
	RelayID   string    `gorm:"primaryKey;size:64"`
	Nonce     string    `gorm:"primaryKey;size:64"`
	ExpiresAt time.Time `gorm:"not null;index"`
}

func (uploadNonce) TableName() string { return "karst_usage_upload_nonces" }

// Store owns explicit managed-producer policy and replay-safe usage ingestion.
type Store struct{ db *gorm.DB }

// WithDB binds a Store value to a caller-owned GORM handle. Operator tooling
// uses it with the transaction supplied by SqlStore after startup migration.
func (s *Store) WithDB(db *gorm.DB) *Store {
	return &Store{db: db}
}

func NewStore(db *gorm.DB) (*Store, error) {
	if db == nil {
		return nil, errors.New("relay usage: nil database")
	}
	if err := db.AutoMigrate(&ManagedProducer{}, &AllowedMapping{}, &receivedBatch{}, &receivedTotal{}, &receivedCoverage{}, &producerMappingInterval{}, &authorizationHistory{}, &uploadNonce{}); err != nil {
		return nil, fmt.Errorf("relay usage: migrate: %w", err)
	}
	if err := initializeAuthorizationHistory(db); err != nil {
		return nil, fmt.Errorf("relay usage: initialize authorization history: %w", err)
	}
	return &Store{db: db}, nil
}

// initializeAuthorizationHistory marks when relay authorization history became
// trustworthy. Existing active producer/mapping pairs begin at this cutover;
// no earlier authorization period is inferred during migration.
func initializeAuthorizationHistory(db *gorm.DB) error {
	ctx := context.Background()
	nowUS := time.Now().UTC().Truncate(time.Microsecond).UnixMicro()
	return db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		history := authorizationHistory{ID: 1, StartedAtUS: nowUS}
		created := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&history)
		if created.Error != nil {
			return created.Error
		}
		if created.RowsAffected == 0 {
			return nil
		}
		var producers []ManagedProducer
		if err := tx.Where("enabled = ?", true).Find(&producers).Error; err != nil {
			return err
		}
		store := &Store{db: tx}
		cutover := time.UnixMicro(history.StartedAtUS).UTC()
		for _, producer := range producers {
			if err := store.startEnabledMappingIntervals(ctx, producer.RelayID, cutover); err != nil {
				return err
			}
		}
		return nil
	})
}

// AuthorizeProducer is for audited operator tooling only. It binds a key to a
// single deployment; callers must append an audit event in the same transaction.
func (s *Store) AuthorizeProducer(ctx context.Context, publicKey []byte, deployment string) (string, error) {
	if len(publicKey) != identity.PublicKeySize || !validText(deployment, 128) {
		return "", ErrProducerConflict
	}
	relayID := base64.RawURLEncoding.EncodeToString(relayreg.RelayID(publicKey))
	key := base64.StdEncoding.EncodeToString(publicKey)
	var existing ManagedProducer
	err := s.db.WithContext(ctx).Where("relay_id = ?", relayID).Take(&existing).Error
	if err == nil {
		if existing.IdentityKey != key || existing.DeploymentID != deployment {
			return "", ErrProducerConflict
		}
		now := time.Now().UTC().Truncate(time.Microsecond)
		if !existing.Enabled {
			if err := s.db.WithContext(ctx).Model(&existing).Updates(map[string]any{"enabled": true, "updated_at": now}).Error; err != nil {
				return "", err
			}
		}
		if err := s.startEnabledMappingIntervals(ctx, relayID, now); err != nil {
			return "", err
		}
		return relayID, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return "", err
	}
	producer := ManagedProducer{RelayID: relayID, DeploymentID: deployment, IdentityKey: key, Enabled: true, UpdatedAt: time.Now().UTC()}
	if err := s.db.WithContext(ctx).Create(&producer).Error; err != nil {
		return "", err
	}
	return relayID, nil
}

// AllowMapping grants a producer one mapping version already present in the
// immutable attribution ledger. The same mapping must match the chosen deployment.
func (s *Store) AllowMapping(ctx context.Context, relayID, deployment, version string) error {
	var producer ManagedProducer
	if err := s.db.WithContext(ctx).Where("relay_id = ? AND enabled = ?", relayID, true).Take(&producer).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrProducerMissing
		}
		return err
	}
	if producer.DeploymentID != deployment {
		return ErrMappingNotAllowed
	}
	mapping, err := usage.ResolveRelayMapping(ctx, s.db, deployment, version)
	if err != nil {
		return err
	}
	var existing AllowedMapping
	err = s.db.WithContext(ctx).Where("relay_id = ? AND deployment_id = ? AND version = ?", relayID, deployment, version).Take(&existing).Error
	if err == nil && existing.Enabled {
		return s.startMappingInterval(ctx, relayID, mapping, time.Now().UTC().Truncate(time.Microsecond))
	}
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	row := AllowedMapping{RelayID: relayID, DeploymentID: deployment, Version: version, Enabled: true, AllowedAt: now}
	if err := s.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "relay_id"}, {Name: "deployment_id"}, {Name: "version"}},
		DoUpdates: clause.Assignments(map[string]any{"enabled": true, "allowed_at": now, "revoked_at": nil}),
	}).Create(&row).Error; err != nil {
		return err
	}
	return s.startMappingInterval(ctx, relayID, mapping, now)
}

func (s *Store) RevokeMapping(ctx context.Context, relayID, deployment, version string) error {
	var mapping AllowedMapping
	if err := s.db.WithContext(ctx).Where("relay_id = ? AND deployment_id = ? AND version = ?", relayID, deployment, version).Take(&mapping).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrMappingNotAllowed
		}
		return err
	}
	if !mapping.Enabled {
		return nil
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	if err := s.closeMappingInterval(ctx, relayID, deployment, version, now); err != nil {
		return err
	}
	return s.db.WithContext(ctx).Model(&mapping).Updates(map[string]any{"enabled": false, "revoked_at": now}).Error
}

func (s *Store) RevokeProducer(ctx context.Context, relayID string) error {
	var producer ManagedProducer
	if err := s.db.WithContext(ctx).Where("relay_id = ?", relayID).Take(&producer).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrProducerMissing
		}
		return err
	}
	if !producer.Enabled {
		return nil
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	if err := s.closeProducerIntervals(ctx, relayID, now); err != nil {
		return err
	}
	return s.db.WithContext(ctx).Model(&producer).Updates(map[string]any{"enabled": false, "updated_at": now}).Error
}

func (s *Store) startEnabledMappingIntervals(ctx context.Context, relayID string, at time.Time) error {
	var mappings []AllowedMapping
	if err := s.db.WithContext(ctx).Where("relay_id = ? AND enabled = ?", relayID, true).Find(&mappings).Error; err != nil {
		return err
	}
	for _, allowed := range mappings {
		mapping, err := usage.ResolveRelayMapping(ctx, s.db, allowed.DeploymentID, allowed.Version)
		if err != nil {
			return err
		}
		if err := s.startMappingInterval(ctx, relayID, mapping, at); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) startMappingInterval(ctx context.Context, relayID string, mapping usage.RelayMapping, at time.Time) error {
	var active producerMappingInterval
	err := s.db.WithContext(ctx).Where("relay_id = ? AND deployment_id = ? AND version = ? AND end_us IS NULL", relayID, mapping.DeploymentID, mapping.Version).Take(&active).Error
	if err == nil {
		if active.AccountID != mapping.AccountID {
			return ErrMappingNotAllowed
		}
		return nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}
	return s.db.WithContext(ctx).Clauses(clause.OnConflict{DoNothing: true}).Create(&producerMappingInterval{
		RelayID: relayID, DeploymentID: mapping.DeploymentID, Version: mapping.Version,
		AccountID: mapping.AccountID, StartUS: at.UnixMicro(),
	}).Error
}

func (s *Store) closeMappingInterval(ctx context.Context, relayID, deployment, version string, at time.Time) error {
	return s.closeAuthorizationIntervals(ctx, at, "relay_id = ? AND deployment_id = ? AND version = ?", relayID, deployment, version)
}

func (s *Store) closeProducerIntervals(ctx context.Context, relayID string, at time.Time) error {
	return s.closeAuthorizationIntervals(ctx, at, "relay_id = ?", relayID)
}

func (s *Store) closeAuthorizationIntervals(ctx context.Context, at time.Time, where string, args ...any) error {
	var active []producerMappingInterval
	if err := s.db.WithContext(ctx).Where(where+" AND end_us IS NULL", args...).Find(&active).Error; err != nil {
		return err
	}
	endUS := at.UnixMicro()
	for _, interval := range active {
		if endUS <= interval.StartUS {
			return errors.New("relay usage: authorization clock regressed")
		}
		if err := s.db.WithContext(ctx).Model(&interval).Update("end_us", endUS).Error; err != nil {
			return err
		}
	}
	return nil
}

type IngestResult struct {
	Duplicate bool
}

// Ingest verifies both the immutable batch and fresh request signature, checks
// operator scope, reserves the nonce, and persists batch identity and resolved
// account totals in one database transaction.
func (s *Store) Ingest(ctx context.Context, method, path string, auth UploadAuthorization, body []byte, now time.Time) (IngestResult, error) {
	var result IngestResult
	if now.IsZero() || now.UnixMicro() < 0 || !freshTimestamp(auth.TimestampMicros, uint64(now.UnixMicro())) {
		return result, ErrUnauthorized
	}
	batch, err := Parse(body)
	if err != nil {
		return result, err
	}
	maxWindowEnd := uint64(now.UnixMicro()) + uint64(uploadFreshness/time.Microsecond)
	if batch.Window.EndMicros > maxWindowEnd || batch.Window.StartMicros > math.MaxInt64 || batch.Window.EndMicros > math.MaxInt64 {
		return result, ErrInvalidBatch
	}
	transcript, err := UploadSigningInput(method, path, auth.TimestampMicros, auth.Nonce, body)
	if err != nil {
		return result, err
	}
	now = now.UTC().Truncate(time.Microsecond)
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var producer ManagedProducer
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("relay_id = ? AND enabled = ?", auth.RelayID, true).Take(&producer).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrProducerMissing
			}
			return err
		}
		publicKey, err := base64.StdEncoding.DecodeString(producer.IdentityKey)
		if err != nil || len(publicKey) != identity.PublicKeySize {
			return ErrProducerMissing
		}
		idBytes, err := base64.RawURLEncoding.DecodeString(auth.RelayID)
		if err != nil || subtle.ConstantTimeCompare(idBytes, relayreg.RelayID(publicKey)) != 1 {
			return ErrUnauthorized
		}
		if !identity.Verify(publicKey, []byte(identity.RelayUsageUploadContext), transcript, auth.Signature) {
			return ErrUnauthorized
		}
		if !identity.Verify(publicKey, []byte(identity.RelayUsageContext), batch.SigningInput(), batch.Signature) {
			return ErrUnauthorized
		}
		var allMappings []AllowedMapping
		if err := tx.Where("relay_id = ?", auth.RelayID).Order("deployment_id, version").Limit(maxMappings + 1).Find(&allMappings).Error; err != nil {
			return err
		}
		if len(allMappings) > maxMappings {
			return ErrMappingNotAllowed
		}
		resolvedScopes := make(map[string]usage.RelayMapping, len(allMappings))
		accounts := make(map[string]struct{}, len(allMappings))
		for _, allowed := range allMappings {
			if allowed.DeploymentID != producer.DeploymentID {
				return ErrMappingNotAllowed
			}
			if !allowed.Enabled && (allowed.RevokedAt == nil || batch.Window.EndMicros > uint64(allowed.RevokedAt.UnixMicro())) {
				continue
			}
			resolved, err := usage.ResolveRelayMapping(ctx, tx, allowed.DeploymentID, allowed.Version)
			if err != nil {
				if errors.Is(err, usage.ErrMapping) {
					return ErrMappingNotAllowed
				}
				return err
			}
			var periodCount int64
			if err := tx.Model(&producerMappingInterval{}).
				Where("relay_id = ? AND deployment_id = ? AND version = ? AND start_us < ? AND (end_us IS NULL OR end_us > ?)",
					auth.RelayID, allowed.DeploymentID, allowed.Version, int64(batch.Window.EndMicros), int64(batch.Window.StartMicros)).
				Count(&periodCount).Error; err != nil {
				return err
			}
			if periodCount == 0 {
				continue
			}
			resolvedScopes[allowed.Version] = resolved
			accounts[resolved.AccountID] = struct{}{}
		}
		for _, mapping := range batch.Window.Mappings {
			resolved, ok := resolvedScopes[mapping.Version]
			if !ok || mapping.Deployment != producer.DeploymentID || resolved.DeploymentID != mapping.Deployment || resolved.Aquifer != mapping.Aquifer {
				return ErrMappingNotAllowed
			}
		}

		nonceText := hex.EncodeToString(auth.Nonce[:])
		if err := tx.Where("relay_id = ? AND expires_at <= ?", auth.RelayID, now).Delete(&uploadNonce{}).Error; err != nil {
			return err
		}
		ttlMicros := uint64(uploadFreshness / time.Microsecond)
		if auth.TimestampMicros > uint64(math.MaxInt64)-ttlMicros {
			return ErrUnauthorized
		}
		expiresMicros := auth.TimestampMicros + ttlMicros
		nonceResult := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&uploadNonce{
			RelayID: auth.RelayID, Nonce: nonceText, ExpiresAt: time.UnixMicro(int64(expiresMicros)).UTC(),
		})
		if nonceResult.Error != nil {
			return nonceResult.Error
		}
		if nonceResult.RowsAffected == 0 {
			return ErrRequestReplay
		}

		epoch := hex.EncodeToString(batch.Epoch[:])
		sequence := fmt.Sprintf("%020d", batch.Sequence)
		var existing receivedBatch
		err = tx.Where("deployment_id = ? AND relay_id = ? AND epoch = ? AND sequence = ?", producer.DeploymentID, auth.RelayID, epoch, sequence).Take(&existing).Error
		if err == nil {
			if len(existing.Digest) != len(batch.Digest) || subtle.ConstantTimeCompare(existing.Digest, batch.Digest[:]) != 1 {
				return ErrBatchConflict
			}
			result.Duplicate = true
			return nil
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		received := receivedBatch{DeploymentID: producer.DeploymentID, RelayID: auth.RelayID, Epoch: epoch, Sequence: sequence,
			Digest: batch.Digest[:], StartUS: int64(batch.Window.StartMicros), EndUS: int64(batch.Window.EndMicros), Gaps: batch.Window.Gaps, ReceivedAt: now}
		inserted := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&received)
		if inserted.Error != nil {
			return inserted.Error
		}
		if inserted.RowsAffected == 0 {
			err := tx.Where("deployment_id = ? AND relay_id = ? AND epoch = ? AND sequence = ?", producer.DeploymentID, auth.RelayID, epoch, sequence).Take(&existing).Error
			if err != nil {
				return err
			}
			if len(existing.Digest) != len(batch.Digest) || subtle.ConstantTimeCompare(existing.Digest, batch.Digest[:]) != 1 {
				return ErrBatchConflict
			}
			result.Duplicate = true
			return nil
		}
		for accountID := range accounts {
			coverage := receivedCoverage{DeploymentID: producer.DeploymentID, RelayID: auth.RelayID, Epoch: epoch, Sequence: sequence,
				AccountID: accountID, StartUS: int64(batch.Window.StartMicros), EndUS: int64(batch.Window.EndMicros), Gaps: batch.Window.Gaps}
			if err := tx.Create(&coverage).Error; err != nil {
				return err
			}
		}
		for _, mapping := range batch.Window.Mappings {
			resolved := resolvedScopes[mapping.Version]
			row := receivedTotal{DeploymentID: producer.DeploymentID, RelayID: auth.RelayID, Epoch: epoch, Sequence: sequence,
				MappingKey: mappingKey(mapping.Deployment, mapping.Version, mapping.Aquifer), Version: mapping.Version,
				Aquifer: mapping.Aquifer, AccountID: resolved.AccountID, BytesDecimal: strconv.FormatUint(mapping.Bytes, 10)}
			if err := tx.Create(&row).Error; err != nil {
				return err
			}
		}
		return nil
	})
	return result, err
}

func freshTimestamp(timestamp, now uint64) bool {
	window := uint64(uploadFreshness / time.Microsecond)
	if timestamp > now {
		return timestamp-now <= window
	}
	return now-timestamp <= window
}

func validText(value string, limit int) bool {
	return len(value) > 0 && len(value) <= limit && utf8.ValidString(value) && strings.TrimSpace(value) == value && strings.IndexFunc(value, unicode.IsControl) < 0
}

func mappingKey(deployment, version, aquifer string) string {
	digest := sha256.Sum256([]byte(deployment + "\x00" + version + "\x00" + aquifer))
	return hex.EncodeToString(digest[:])
}
