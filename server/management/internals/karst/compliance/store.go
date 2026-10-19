// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package compliance

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const ChallengeLifetime = 60 * time.Second
const EvidenceRetention = 24 * time.Hour // after evidence expiry

var (
	ErrInvalidReport  = errors.New("compliance: invalid report")
	ErrInvalidSubject = errors.New("compliance: invalid subject")
	ErrNotEnrolled    = errors.New("compliance: device is not enrolled")
	ErrChallenge      = errors.New("compliance: challenge invalid, expired or consumed")
	ErrNoEvidence     = errors.New("compliance: no retained evidence")
)

// Report contains observations only. Authentication supplies subject and handle;
// ingestion supplies provenance and receipt time. No client timestamp is trusted.
type Report struct {
	CollectorVersion string
	Platform         Platform
	Distribution     string
	ClientVersion    Observation
	OSVersion        Observation
}

func (r Report) Validate() error {
	if r.CollectorVersion == "" || len(r.CollectorVersion) > 128 || len(r.Platform) > 64 || len(r.Distribution) > 64 || len(r.ClientVersion.Version) > 128 || len(r.OSVersion.Version) > 128 || len(r.ClientVersion.Status) > 64 || len(r.OSVersion.Status) > 64 {
		return ErrInvalidReport
	}
	return nil
}

// One row per enrollment and authenticated identity; no report history. Only a
// hash of an outstanding challenge is persisted. A new challenge replaces the
// old one without extending freshness of the last accepted evidence.
type evidenceRow struct {
	TenantID            string `gorm:"primaryKey;size:64"`
	DeviceID            string `gorm:"primaryKey;size:64"`
	Handle              string `gorm:"primaryKey;size:64"`
	ChallengeHash       string `gorm:"size:64;not null"`
	IssuedAt            time.Time
	ChallengeExpiresAt  time.Time
	EvidenceJSON        string     `gorm:"not null"`
	EvidenceRetainUntil *time.Time `gorm:"index"`
	CollectorVersion    string     `gorm:"size:128;not null"`
	Generation          uint64     `gorm:"not null"`
	RetainUntil         time.Time  `gorm:"index"`
}

func (evidenceRow) TableName() string { return "karst_device_compliance" }

type Store struct{ db *gorm.DB }

func NewStore(db *gorm.DB) (*Store, error) {
	if db == nil {
		return nil, errors.New("compliance: nil database")
	}
	if err := db.AutoMigrate(&evidenceRow{}); err != nil {
		return nil, fmt.Errorf("compliance: migrate: %w", err)
	}
	return &Store{db: db}, nil
}

type Challenge struct {
	Token     []byte
	ExpiresAt time.Time
}
type AcceptedEvidence struct {
	Evidence         Evidence
	CollectorVersion string
	Generation       uint64
}

func scope(subject Subject, handle string) map[string]any {
	return map[string]any{"tenant_id": subject.TenantID, "device_id": subject.DeviceID, "handle": handle}
}
func validSubject(subject Subject, handle string) bool {
	return subject.TenantID != "" && len(subject.TenantID) <= 64 && subject.DeviceID != "" && len(subject.DeviceID) <= 64 && handle != "" && len(handle) <= 64
}

// enrolled locks the authoritative peer until this transaction completes, so
// deletion/key replacement cannot race an accepted report in PostgreSQL. This
// also makes old enrollment IDs unusable after reenrollment with the same key.
func enrolled(tx *gorm.DB, subject Subject, handle string) error {
	var peer struct{ ID string }
	err := tx.Table("peers").Select("id").Where(map[string]any{"id": subject.DeviceID, "account_id": subject.TenantID, "key": handle}).Clauses(clause.Locking{Strength: "SHARE"}).Take(&peer).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ErrNotEnrolled
	}
	return err
}

// Issue replaces any outstanding challenge. now must come from the server.
func (s *Store) Issue(ctx context.Context, subject Subject, handle string, now time.Time) (Challenge, error) {
	if !validSubject(subject, handle) || now.IsZero() {
		return Challenge{}, ErrInvalidSubject
	}
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return Challenge{}, err
	}
	deadline := now.UTC().Add(ChallengeLifetime)
	row := evidenceRow{TenantID: subject.TenantID, DeviceID: subject.DeviceID, Handle: handle, ChallengeHash: challengeHash(token), IssuedAt: now.UTC(), ChallengeExpiresAt: deadline, RetainUntil: deadline}
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := enrolled(tx, subject, handle); err != nil {
			return err
		}
		// Challenge refresh must not retain expired evidence indefinitely.
		if err := clearExpiredEvidence(tx.Where(scope(subject, handle)), now); err != nil {
			return err
		}
		return tx.Clauses(clause.OnConflict{
			Columns: []clause.Column{{Name: "tenant_id"}, {Name: "device_id"}, {Name: "handle"}},
			DoUpdates: clause.Assignments(map[string]any{
				"challenge_hash": row.ChallengeHash, "issued_at": row.IssuedAt, "challenge_expires_at": deadline,
				"retain_until": gorm.Expr("CASE WHEN karst_device_compliance.retain_until > ? THEN karst_device_compliance.retain_until ELSE ? END", deadline, deadline),
			}),
		}).Create(&row).Error
	})
	if err != nil {
		return Challenge{}, err
	}
	return Challenge{Token: token, ExpiresAt: deadline}, nil
}

// Submit consumes the challenge and replaces the latest evidence in one
// conditional UPDATE. Concurrent replicas cannot both consume it. Failure
// observations replace old passing values; they are not discarded on ingest.
func (s *Store) Submit(ctx context.Context, subject Subject, handle string, token []byte, report Report, now time.Time) error {
	if !validSubject(subject, handle) || now.IsZero() {
		return ErrInvalidSubject
	}
	if len(token) != 32 {
		return ErrChallenge
	}
	if err := report.Validate(); err != nil {
		return err
	}
	evidence := Evidence{Subject: subject, ReceivedAt: now.UTC(), Provenance: SelfReported, Platform: report.Platform, Distribution: report.Distribution, ClientVersion: report.ClientVersion, OSVersion: report.OSVersion}
	data, err := json.Marshal(evidence)
	if err != nil {
		return err
	}
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := enrolled(tx, subject, handle); err != nil {
			return err
		}
		result := tx.Model(&evidenceRow{}).Where(scope(subject, handle)).Where("challenge_hash = ? AND issued_at <= ? AND challenge_expires_at > ?", challengeHash(token), now.UTC(), now.UTC()).Updates(map[string]any{
			"challenge_hash": "", "evidence_json": string(data), "collector_version": report.CollectorVersion,
			"generation": gorm.Expr("generation + 1"), "retain_until": now.UTC().Add(EvidenceLifetime + EvidenceRetention),
			"evidence_retain_until": now.UTC().Add(EvidenceLifetime + EvidenceRetention),
		})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return ErrChallenge
		}
		return nil
	})
}

// Latest returns retained evidence, which may already be stale. Evaluate it
// against the current requirements/time before using it; this is not a verdict.
func (s *Store) Latest(ctx context.Context, subject Subject, handle string, now time.Time) (AcceptedEvidence, error) {
	if !validSubject(subject, handle) || now.IsZero() {
		return AcceptedEvidence{}, ErrInvalidSubject
	}
	var row evidenceRow
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := enrolled(tx, subject, handle); err != nil {
			return err
		}
		return tx.Where(scope(subject, handle)).Take(&row).Error
	})
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return AcceptedEvidence{}, ErrNoEvidence
	}
	if err != nil {
		return AcceptedEvidence{}, err
	}
	if row.EvidenceJSON == "" {
		return AcceptedEvidence{}, ErrNoEvidence
	}
	var e Evidence
	if err := json.Unmarshal([]byte(row.EvidenceJSON), &e); err != nil {
		return AcceptedEvidence{}, fmt.Errorf("compliance: decode stored evidence: %w", err)
	}
	if !now.Before(e.ReceivedAt.Add(EvidenceLifetime + EvidenceRetention)) {
		return AcceptedEvidence{}, ErrNoEvidence
	}
	return AcceptedEvidence{Evidence: e, CollectorVersion: row.CollectorVersion, Generation: row.Generation}, nil
}

func challengeHash(token []byte) string {
	sum := sha256.Sum256(token)
	return hex.EncodeToString(sum[:])
}

// Prune removes expired retention rows and deleted/replaced enrollments.
func (s *Store) Prune(ctx context.Context, now time.Time) error {
	if now.IsZero() {
		return ErrInvalidSubject
	}
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := clearExpiredEvidence(tx, now); err != nil {
			return err
		}
		return tx.Where("retain_until <= ? OR NOT EXISTS (SELECT 1 FROM peers WHERE peers.id = karst_device_compliance.device_id AND peers.account_id = karst_device_compliance.tenant_id AND peers.key = karst_device_compliance.handle)", now.UTC()).Delete(&evidenceRow{}).Error
	})
}

func clearExpiredEvidence(tx *gorm.DB, now time.Time) error {
	return tx.Model(&evidenceRow{}).Where("evidence_retain_until <= ?", now.UTC()).Updates(map[string]any{"evidence_json": "", "collector_version": "", "evidence_retain_until": nil}).Error
}

// StartRetentionWorker prunes at startup and hourly. It is safe on each replica.
func (s *Store) StartRetentionWorker(ctx context.Context, onError func(error)) {
	prune := func() {
		if err := s.Prune(ctx, time.Now().UTC()); err != nil && onError != nil {
			onError(err)
		}
	}
	prune()
	go func() {
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				prune()
			}
		}
	}()
}
