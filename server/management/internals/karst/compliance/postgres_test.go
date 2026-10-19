// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package compliance_test

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/netbirdio/netbird/management/internals/karst/compliance"
)

// CI's existing Go job supplies Postgres. Each test uses an isolated schema,
// two independent pools and no process-wide mutex, matching separate replicas.
func postgresIngestionDB(t *testing.T) (*gorm.DB, *compliance.Store, *compliance.Store) {
	t.Helper()
	dsn := os.Getenv("KARST_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("KARST_TEST_POSTGRES_DSN is not set")
	}
	admin, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	adminSQL, err := admin.DB()
	require.NoError(t, err)
	t.Cleanup(func() { _ = adminSQL.Close() })
	schema := fmt.Sprintf("compliance_%d", time.Now().UnixNano())
	require.NoError(t, admin.Exec("CREATE SCHEMA "+schema).Error)
	t.Cleanup(func() { require.NoError(t, admin.Exec("DROP SCHEMA "+schema+" CASCADE").Error) })
	open := func() *gorm.DB {
		cfg, err := pgx.ParseConfig(dsn)
		require.NoError(t, err)
		cfg.RuntimeParams["search_path"] = schema
		pool := stdlib.OpenDB(*cfg)
		t.Cleanup(func() { _ = pool.Close() })
		db, err := gorm.Open(postgres.New(postgres.Config{Conn: pool}), &gorm.Config{Logger: logger.Discard})
		require.NoError(t, err)
		return db
	}
	db := open()
	require.NoError(t, db.AutoMigrate(&enrollment{}))
	require.NoError(t, db.Create(&enrollment{ID: subject.DeviceID, AccountID: subject.TenantID, Key: "identity-a"}).Error)
	a, err := compliance.NewStore(db)
	require.NoError(t, err)
	b, err := compliance.NewStore(open())
	require.NoError(t, err)
	return db, a, b
}

func TestPostgresComplianceReplayAcrossReplicas(t *testing.T) {
	_, a, b := postgresIngestionDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	challenge, err := a.Issue(ctx, subject, "identity-a", now)
	require.NoError(t, err)
	start := make(chan struct{})
	results := make(chan error, 20)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
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
		} else {
			require.ErrorIs(t, err, compliance.ErrChallenge)
		}
	}
	require.Equal(t, 1, successes)
	accepted, err := b.Latest(ctx, subject, "identity-a", now.Add(time.Second))
	require.NoError(t, err)
	require.Equal(t, uint64(1), accepted.Generation)
	// Concurrent issuance also resolves through the database unique key.
	challenges := make(chan compliance.Challenge, 2)
	errs := make(chan error, 2)
	for _, store := range []*compliance.Store{a, b} {
		wg.Add(1)
		go func(store *compliance.Store) {
			defer wg.Done()
			c, err := store.Issue(ctx, subject, "identity-a", now.Add(2*time.Second))
			challenges <- c
			errs <- err
		}(store)
	}
	wg.Wait()
	close(challenges)
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	successes = 0
	for c := range challenges {
		err := a.Submit(ctx, subject, "identity-a", c.Token, report(), now.Add(3*time.Second))
		if err == nil {
			successes++
		} else {
			require.ErrorIs(t, err, compliance.ErrChallenge)
		}
	}
	require.Equal(t, 1, successes)
}

func TestPostgresComplianceDeletionSerializesWithSubmission(t *testing.T) {
	db, a, b := postgresIngestionDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	challenge, err := a.Issue(ctx, subject, "identity-a", now)
	require.NoError(t, err)
	deletion := db.WithContext(ctx).Begin()
	require.NoError(t, deletion.Error)
	defer deletion.Rollback()
	require.NoError(t, deletion.Delete(&enrollment{}, "id = ?", subject.DeviceID).Error)
	result := make(chan error, 1)
	go func() {
		result <- b.Submit(ctx, subject, "identity-a", challenge.Token, report(), now.Add(time.Second))
	}()
	select {
	case err := <-result:
		t.Fatalf("submission did not wait for enrollment deletion: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	require.NoError(t, deletion.Commit().Error)
	require.ErrorIs(t, <-result, compliance.ErrNotEnrolled)
}

func TestPostgresComplianceExpiryCannotExpireARefreshedGeneration(t *testing.T) {
	db, a, b := postgresIngestionDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	acceptReport(t, a, subject, "identity-a", report(), now)
	require.NoError(t, a.ProcessInvalidations(ctx, now, func(context.Context, string) error { return nil }))
	deadline := now.Add(compliance.EvidenceLifetime)
	challenge, err := b.Issue(ctx, subject, "identity-a", deadline)
	require.NoError(t, err)
	start := make(chan struct{})
	results := make(chan error, 2)
	go func() { <-start; results <- a.Expire(ctx, deadline) }()
	go func() { <-start; results <- b.Submit(ctx, subject, "identity-a", challenge.Token, report(), deadline) }()
	close(start)
	require.NoError(t, <-results)
	require.NoError(t, <-results)
	var row struct {
		ExpiryNotified      bool
		EvidenceExpiresAt   time.Time
		Generation          uint64
		NotificationPending bool
	}
	require.NoError(t, db.Table("karst_device_compliance").Take(&row).Error)
	require.False(t, row.ExpiryNotified, "an expiry scan must not expire a newly accepted generation")
	require.Equal(t, deadline.Add(compliance.EvidenceLifetime), row.EvidenceExpiresAt)
	require.Equal(t, uint64(2), row.Generation)
	require.True(t, row.NotificationPending)
	var ids []string
	require.NoError(t, b.ProcessInvalidations(ctx, deadline, recorder(&ids)))
	require.Equal(t, []string{subject.DeviceID}, ids)
	require.Zero(t, pending(t, db, subject.TenantID))
}

func TestPostgresComplianceAckCannotLoseANewerFailure(t *testing.T) {
	db, a, b := postgresIngestionDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	acceptReport(t, a, subject, "identity-a", report(), now)
	failed := report()
	failed.ClientVersion = compliance.Observation{Status: compliance.CollectionError}
	require.NoError(t, a.ProcessInvalidations(ctx, now, func(context.Context, string) error {
		challenge, err := b.Issue(ctx, subject, "identity-a", now.Add(time.Second))
		if err != nil {
			return err
		}
		return b.Submit(ctx, subject, "identity-a", challenge.Token, failed, now.Add(time.Second))
	}))
	require.EqualValues(t, 1, pending(t, db, subject.TenantID))
	var ids []string
	require.NoError(t, b.ProcessInvalidations(ctx, now.Add(time.Second), recorder(&ids)))
	require.Equal(t, []string{subject.DeviceID}, ids)
	require.Zero(t, pending(t, db, subject.TenantID))
}
