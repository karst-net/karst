// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package compliance_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/netbirdio/netbird/management/internals/karst/compliance"
)

type enrollment struct {
	ID        string `gorm:"primaryKey"`
	AccountID string
	Key       string
}

func (enrollment) TableName() string { return "peers" }

func ingestionDB(t *testing.T) (*gorm.DB, *compliance.Store, *compliance.Store) {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), "compliance.db") + "?_busy_timeout=5000&_journal_mode=WAL"
	open := func() *gorm.DB {
		db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{Logger: logger.Discard})
		require.NoError(t, err)
		sqlDB, err := db.DB()
		require.NoError(t, err)
		t.Cleanup(func() { _ = sqlDB.Close() })
		return db
	}
	db := open()
	require.NoError(t, db.AutoMigrate(&enrollment{}))
	require.NoError(t, db.Create(&enrollment{ID: subject.DeviceID, AccountID: subject.TenantID, Key: "identity-a"}).Error)
	first, err := compliance.NewStore(db)
	require.NoError(t, err)
	second, err := compliance.NewStore(open())
	require.NoError(t, err)
	return db, first, second
}
func report() compliance.Report {
	return compliance.Report{CollectorVersion: "v0.1.0", Platform: compliance.MacOS, ClientVersion: compliance.Observation{Status: compliance.Collected, Version: "v0.1.0"}, OSVersion: compliance.Observation{Status: compliance.Collected, Version: "15.1"}}
}

func TestChallengeAndEvidenceSurviveReplicaRestart(t *testing.T) {
	db, a, b := ingestionDB(t)
	ctx := context.Background()
	challenge, err := a.Issue(ctx, subject, "identity-a", now)
	require.NoError(t, err)
	require.Len(t, challenge.Token, 32)
	require.Equal(t, now.Add(time.Minute), challenge.ExpiresAt)
	var row struct{ ChallengeHash string }
	require.NoError(t, db.Table("karst_device_compliance").Take(&row).Error)
	digest := sha256.Sum256(challenge.Token)
	require.Equal(t, hex.EncodeToString(digest[:]), row.ChallengeHash)
	require.NotEqual(t, hex.EncodeToString(challenge.Token), row.ChallengeHash)
	_, err = b.Latest(ctx, subject, "identity-a", now)
	require.ErrorIs(t, err, compliance.ErrNoEvidence)
	received := now.Add(time.Second)
	require.NoError(t, b.Submit(ctx, subject, "identity-a", challenge.Token, report(), received))
	accepted, err := a.Latest(ctx, subject, "identity-a", received)
	require.NoError(t, err)
	require.Equal(t, uint64(1), accepted.Generation)
	require.Equal(t, received, accepted.Evidence.ReceivedAt)
	require.Equal(t, subject, accepted.Evidence.Subject)
	require.Equal(t, compliance.SelfReported, accepted.Evidence.Provenance)
	require.Equal(t, "v0.1.0", accepted.CollectorVersion)
	evaluated, err := compliance.Evaluate([]compliance.Requirement{clientRequirement()}, subject, &accepted.Evidence, received)
	require.NoError(t, err)
	require.True(t, evaluated.Satisfied())
	require.ErrorIs(t, a.Submit(ctx, subject, "identity-a", challenge.Token, report(), received), compliance.ErrChallenge)
	replacement, err := a.Issue(ctx, subject, "identity-a", received.Add(time.Second))
	require.NoError(t, err)
	require.False(t, bytes.Equal(challenge.Token, replacement.Token))
	unchanged, err := b.Latest(ctx, subject, "identity-a", received.Add(time.Second))
	require.NoError(t, err)
	require.Equal(t, accepted, unchanged)
	failed := report()
	failed.ClientVersion = compliance.Observation{Status: compliance.CollectionError}
	require.NoError(t, b.Submit(ctx, subject, "identity-a", replacement.Token, failed, received.Add(2*time.Second)))
	latest, err := a.Latest(ctx, subject, "identity-a", received.Add(2*time.Second))
	require.NoError(t, err)
	require.Equal(t, uint64(2), latest.Generation)
	evaluated, err = compliance.Evaluate([]compliance.Requirement{clientRequirement()}, subject, &latest.Evidence, received.Add(2*time.Second))
	require.NoError(t, err)
	require.False(t, evaluated.Satisfied())
	require.Equal(t, compliance.EvaluationError, evaluated.Results[0].State)
}

func TestChallengeReplacementExpiryAndBindings(t *testing.T) {
	db, a, b := ingestionDB(t)
	ctx := context.Background()
	challenge, err := a.Issue(ctx, subject, "identity-a", now)
	require.NoError(t, err)
	newer, err := b.Issue(ctx, subject, "identity-a", now.Add(time.Second))
	require.NoError(t, err)
	require.ErrorIs(t, a.Submit(ctx, subject, "identity-a", challenge.Token, report(), now.Add(2*time.Second)), compliance.ErrChallenge)
	require.ErrorIs(t, b.Submit(ctx, subject, "identity-a", newer.Token, report(), newer.ExpiresAt), compliance.ErrChallenge)
	require.ErrorIs(t, b.Submit(ctx, subject, "identity-a", newer.Token, report(), now), compliance.ErrChallenge)
	require.ErrorIs(t, b.Submit(ctx, subject, "identity-a", nil, report(), now), compliance.ErrChallenge)
	for _, peer := range []enrollment{{ID: "device-b", AccountID: subject.TenantID, Key: "identity-b"}, {ID: "device-c", AccountID: "tenant-b", Key: "identity-c"}} {
		require.NoError(t, db.Create(&peer).Error)
		other := compliance.Subject{TenantID: peer.AccountID, DeviceID: peer.ID}
		require.ErrorIs(t, b.Submit(ctx, other, peer.Key, newer.Token, report(), now.Add(2*time.Second)), compliance.ErrChallenge)
	}
	require.ErrorIs(t, b.Submit(ctx, subject, "identity-b", newer.Token, report(), now.Add(2*time.Second)), compliance.ErrNotEnrolled)
	require.NoError(t, b.Submit(ctx, subject, "identity-a", newer.Token, report(), newer.ExpiresAt.Add(-time.Nanosecond)))
	require.NoError(t, db.Model(&enrollment{}).Where("id = ?", subject.DeviceID).Update("key", "rotated").Error)
	_, err = a.Latest(ctx, subject, "identity-a", now)
	require.ErrorIs(t, err, compliance.ErrNotEnrolled)
	_, err = a.Issue(ctx, subject, "identity-a", now)
	require.ErrorIs(t, err, compliance.ErrNotEnrolled)
	_, err = a.Latest(ctx, subject, "rotated", now)
	require.ErrorIs(t, err, compliance.ErrNoEvidence)
	require.NoError(t, a.Prune(ctx, now))
	var count int64
	require.NoError(t, db.Table("karst_device_compliance").Count(&count).Error)
	require.Zero(t, count)
}

func TestAtomicChallengeConsumption(t *testing.T) {
	_, a, b := ingestionDB(t)
	ctx := context.Background()
	challenge, err := a.Issue(ctx, subject, "identity-a", now)
	require.NoError(t, err)
	var wg sync.WaitGroup
	start := make(chan struct{})
	results := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			store := a
			if i%2 == 1 {
				store = b
			}
			results <- store.Submit(ctx, subject, "identity-a", challenge.Token, report(), now.Add(time.Second))
		}(i)
	}
	close(start)
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		}
	}
	require.Equal(t, 1, successes, "exactly one replica may consume a challenge")
	// SQLite may fail a contending read/write transaction with BUSY; retrying
	// after the winner commits must still reject the consumed challenge.
	require.ErrorIs(t, a.Submit(ctx, subject, "identity-a", challenge.Token, report(), now.Add(time.Second)), compliance.ErrChallenge)
	latest, err := b.Latest(ctx, subject, "identity-a", now.Add(time.Second))
	require.NoError(t, err)
	require.Equal(t, uint64(1), latest.Generation)
}

func TestStorageFailureDoesNotConsumeChallenge(t *testing.T) {
	db, a, b := ingestionDB(t)
	ctx := context.Background()
	challenge, err := a.Issue(ctx, subject, "identity-a", now)
	require.NoError(t, err)
	require.NoError(t, db.Exec("CREATE TRIGGER reject_evidence BEFORE UPDATE OF evidence_json ON karst_device_compliance BEGIN SELECT RAISE(ABORT, 'test failure'); END").Error)
	require.Error(t, a.Submit(ctx, subject, "identity-a", challenge.Token, report(), now.Add(time.Second)))
	_, err = b.Latest(ctx, subject, "identity-a", now.Add(time.Second))
	require.ErrorIs(t, err, compliance.ErrNoEvidence)
	require.NoError(t, db.Exec("DROP TRIGGER reject_evidence").Error)
	require.NoError(t, b.Submit(ctx, subject, "identity-a", challenge.Token, report(), now.Add(time.Second)))
}

func TestEvidenceExpiryRetentionAndEnrollmentDeletion(t *testing.T) {
	db, a, b := ingestionDB(t)
	ctx := context.Background()
	challenge, err := a.Issue(ctx, subject, "identity-a", now)
	require.NoError(t, err)
	require.NoError(t, a.Submit(ctx, subject, "identity-a", challenge.Token, report(), now))
	expiry := now.Add(compliance.EvidenceLifetime)
	retained, err := b.Latest(ctx, subject, "identity-a", expiry)
	require.NoError(t, err)
	evaluated, err := compliance.Evaluate([]compliance.Requirement{clientRequirement()}, subject, &retained.Evidence, expiry)
	require.NoError(t, err)
	require.Equal(t, compliance.Stale, evaluated.Results[0].State)
	cutoff := expiry.Add(compliance.EvidenceRetention)
	_, err = a.Latest(ctx, subject, "identity-a", cutoff)
	require.ErrorIs(t, err, compliance.ErrNoEvidence)
	require.NoError(t, a.Prune(ctx, cutoff))
	var count int64
	require.NoError(t, db.Table("karst_device_compliance").Count(&count).Error)
	require.Zero(t, count)
	challenge, err = a.Issue(ctx, subject, "identity-a", now)
	require.NoError(t, err)
	require.NoError(t, db.Delete(&enrollment{}, "id = ?", subject.DeviceID).Error)
	require.ErrorIs(t, b.Submit(ctx, subject, "identity-a", challenge.Token, report(), now.Add(time.Second)), compliance.ErrNotEnrolled)
	require.NoError(t, db.Create(&enrollment{ID: "replacement-device", AccountID: subject.TenantID, Key: "identity-a"}).Error)
	replacement := compliance.Subject{TenantID: subject.TenantID, DeviceID: "replacement-device"}
	require.ErrorIs(t, b.Submit(ctx, replacement, "identity-a", challenge.Token, report(), now.Add(time.Second)), compliance.ErrChallenge)
	require.NoError(t, a.Prune(ctx, now))
	require.NoError(t, db.Table("karst_device_compliance").Count(&count).Error)
	require.Zero(t, count)
}

func TestIngestionValidation(t *testing.T) {
	_, a, _ := ingestionDB(t)
	ctx := context.Background()
	_, err := compliance.NewStore(nil)
	require.Error(t, err)
	for _, s := range []compliance.Subject{{}, {TenantID: subject.TenantID}, {DeviceID: subject.DeviceID}} {
		_, err := a.Issue(ctx, s, "identity-a", now)
		require.ErrorIs(t, err, compliance.ErrInvalidSubject)
		require.ErrorIs(t, a.Submit(ctx, s, "identity-a", make([]byte, 32), report(), now), compliance.ErrInvalidSubject)
		_, err = a.Latest(ctx, s, "identity-a", now)
		require.ErrorIs(t, err, compliance.ErrInvalidSubject)
	}
	_, err = a.Issue(ctx, subject, "identity-a", time.Time{})
	require.ErrorIs(t, err, compliance.ErrInvalidSubject)
	require.ErrorIs(t, a.Prune(ctx, time.Time{}), compliance.ErrInvalidSubject)
	challenge, err := a.Issue(ctx, subject, "identity-a", now)
	require.NoError(t, err)
	bad := report()
	bad.CollectorVersion = ""
	require.ErrorIs(t, a.Submit(ctx, subject, "identity-a", challenge.Token, bad, now), compliance.ErrInvalidReport)
	require.NoError(t, a.Submit(ctx, subject, "identity-a", challenge.Token, report(), now))
	require.True(t, errors.Is(a.Submit(ctx, subject, "identity-a", challenge.Token, report(), now), compliance.ErrChallenge))
}

func TestChallengeRefreshDoesNotExtendEvidenceRetention(t *testing.T) {
	db, a, b := ingestionDB(t)
	ctx := context.Background()
	c, err := a.Issue(ctx, subject, "identity-a", now)
	require.NoError(t, err)
	require.NoError(t, a.Submit(ctx, subject, "identity-a", c.Token, report(), now))
	cutoff := now.Add(compliance.EvidenceLifetime + compliance.EvidenceRetention)
	c, err = b.Issue(ctx, subject, "identity-a", cutoff)
	require.NoError(t, err)
	var row struct {
		EvidenceJSON     string
		CollectorVersion string
		ChallengeHash    string
	}
	require.NoError(t, db.Table("karst_device_compliance").Take(&row).Error)
	require.Empty(t, row.EvidenceJSON)
	require.Empty(t, row.CollectorVersion)
	require.NotEmpty(t, row.ChallengeHash)
	require.NoError(t, a.Prune(ctx, cutoff))
	require.NoError(t, a.Submit(ctx, subject, "identity-a", c.Token, report(), cutoff.Add(time.Second)))
	_, err = b.Latest(ctx, subject, "identity-a", cutoff.Add(time.Second))
	require.NoError(t, err)
}
