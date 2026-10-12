// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package relayusage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/netbirdio/netbird/management/internals/karst/identity"
	"github.com/netbirdio/netbird/management/internals/karst/usage"
)

func ingestionFixture(t *testing.T) (*gorm.DB, *Store, *identity.Key, string, usage.RelayMapping) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "relayusage.db")), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { _ = sqlDB.Close() })
	require.NoError(t, usage.Migrate(db))
	store, err := NewStore(db)
	require.NoError(t, err)
	mapping, err := usage.PersistRelayMapping(context.Background(), db, "deployment-a", "aquifer-b", "account-1")
	require.NoError(t, err)
	key, err := identity.FromSeed(bytes.Repeat([]byte{9}, identity.SeedSize))
	require.NoError(t, err)
	relayID, err := store.AuthorizeProducer(context.Background(), key.Public(), "deployment-a")
	require.NoError(t, err)
	require.NoError(t, store.AllowMapping(context.Background(), relayID, mapping.DeploymentID, mapping.Version))
	return db, store, key, relayID, mapping
}

func TestIngestIsScopedReplaySafeAndDurable(t *testing.T) {
	db, store, key, relayID, mapping := ingestionFixture(t)
	ctx := context.Background()
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	body := makeSignedBatch(t, key, [16]byte{1, 2, 3}, 9, mappingPayload(mapping, 123))
	firstAuth := makeUploadAuth(t, key, relayID, body, now, [32]byte{1})

	result, err := store.Ingest(ctx, "POST", UploadPath, firstAuth, body, now)
	require.NoError(t, err)
	require.False(t, result.Duplicate)
	var batches []receivedBatch
	batches = nil
	require.NoError(t, db.Find(&batches).Error)
	require.Len(t, batches, 1)
	require.Equal(t, relayID, batches[0].RelayID)
	var totals []receivedTotal
	totals = nil
	require.NoError(t, db.Find(&totals).Error)
	require.Len(t, totals, 1)
	require.Equal(t, "account-1", totals[0].AccountID)
	require.Equal(t, "123", totals[0].BytesDecimal)
	var coverage []receivedCoverage
	coverage = nil
	require.NoError(t, db.Find(&coverage).Error)
	require.Len(t, coverage, 1)
	require.Equal(t, "account-1", coverage[0].AccountID)
	require.Zero(t, coverage[0].Gaps)

	if _, err := store.Ingest(ctx, "POST", UploadPath, firstAuth, body, now); err != ErrRequestReplay {
		t.Fatalf("replayed authorization error = %v, want %v", err, ErrRequestReplay)
	}
	retryAuth := makeUploadAuth(t, key, relayID, body, now, [32]byte{2})
	result, err = store.Ingest(ctx, "POST", UploadPath, retryAuth, body, now)
	require.NoError(t, err)
	require.True(t, result.Duplicate)
	batches = nil
	require.NoError(t, db.Find(&batches).Error)
	require.Len(t, batches, 1)
	totals = nil
	require.NoError(t, db.Find(&totals).Error)
	require.Len(t, totals, 1)
	coverage = nil
	require.NoError(t, db.Find(&coverage).Error)
	require.Len(t, coverage, 1)

	conflict := makeSignedBatch(t, key, [16]byte{1, 2, 3}, 9, mappingPayload(mapping, 124))
	conflictAuth := makeUploadAuth(t, key, relayID, conflict, now, [32]byte{3})
	if _, err := store.Ingest(ctx, "POST", UploadPath, conflictAuth, conflict, now); err != ErrBatchConflict {
		t.Fatalf("conflicting batch error = %v, want %v", err, ErrBatchConflict)
	}
	var nonceCount int64
	require.NoError(t, db.Model(&uploadNonce{}).Count(&nonceCount).Error)
	require.EqualValues(t, 2, nonceCount, "failed conflicts must not consume their nonce")

	require.NoError(t, store.RevokeProducer(ctx, relayID))
	revokedAuth := makeUploadAuth(t, key, relayID, body, now, [32]byte{4})
	if _, err := store.Ingest(ctx, "POST", UploadPath, revokedAuth, body, now); err != ErrProducerMissing {
		t.Fatalf("revoked producer error = %v, want %v", err, ErrProducerMissing)
	}
}

func TestIngestRejectsUnapprovedMappingAndStaleRequest(t *testing.T) {
	_, store, key, relayID, _ := ingestionFixture(t)
	ctx := context.Background()
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	unapproved, err := usage.PersistRelayMapping(ctx, store.db, "deployment-a", "aquifer-other", "account-2")
	require.NoError(t, err)
	body := makeSignedBatch(t, key, [16]byte{4}, 0, mappingPayload(unapproved, 25))
	auth := makeUploadAuth(t, key, relayID, body, now, [32]byte{5})
	if _, err := store.Ingest(ctx, "POST", UploadPath, auth, body, now); err != ErrMappingNotAllowed {
		t.Fatalf("unapproved mapping error = %v, want %v", err, ErrMappingNotAllowed)
	}
	stale := makeUploadAuth(t, key, relayID, body, now.Add(-uploadFreshness-time.Second), [32]byte{6})
	if _, err := store.Ingest(ctx, "POST", UploadPath, stale, body, now); err != ErrUnauthorized {
		t.Fatalf("stale upload error = %v, want %v", err, ErrUnauthorized)
	}
}

func TestRevokedMappingStillAcceptsHistoricalBacklogOnly(t *testing.T) {
	_, store, key, relayID, mapping := ingestionFixture(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	require.NoError(t, store.RevokeMapping(ctx, relayID, mapping.DeploymentID, mapping.Version))

	oldBody := makeSignedBatch(t, key, [16]byte{6}, 0, mappingPayload(mapping, 50))
	oldAuth := makeUploadAuth(t, key, relayID, oldBody, now, [32]byte{7})
	result, err := store.Ingest(ctx, "POST", UploadPath, oldAuth, oldBody, now)
	require.NoError(t, err, "a delayed batch sealed before mapping revocation must remain ingestible")
	require.False(t, result.Duplicate)

	var allowed AllowedMapping
	require.NoError(t, store.db.Where("relay_id = ? AND deployment_id = ? AND version = ?", relayID, mapping.DeploymentID, mapping.Version).Take(&allowed).Error)
	require.NotNil(t, allowed.RevokedAt)
	futureStart := uint64((allowed.RevokedAt.UnixMicro()/int64(minuteMicros) + 1) * int64(minuteMicros))
	futureBody := makeSignedBatch(t, key, [16]byte{7}, 0, mappingPayloadAt(mapping, 51, futureStart))
	futureAuth := makeUploadAuth(t, key, relayID, futureBody, now, [32]byte{8})
	if _, err := store.Ingest(ctx, "POST", UploadPath, futureAuth, futureBody, now); err != ErrMappingNotAllowed {
		t.Fatalf("post-revocation batch error = %v, want %v", err, ErrMappingNotAllowed)
	}
}

func mappingPayload(mapping usage.RelayMapping, bytes uint64) []byte {
	return mappingPayloadAt(mapping, bytes, 0)
}

func mappingPayloadAt(mapping usage.RelayMapping, bytes, start uint64) []byte {
	out := make([]byte, 24)
	copy(out[:4], "KRUM")
	binary.BigEndian.PutUint16(out[4:6], 1)
	binary.BigEndian.PutUint64(out[6:14], start)
	binary.BigEndian.PutUint64(out[14:22], start+minuteMicros)
	binary.BigEndian.PutUint16(out[22:24], 1)
	for _, value := range []string{mapping.DeploymentID, mapping.Version, mapping.Aquifer} {
		out = binary.BigEndian.AppendUint16(out, uint16(len(value)))
		out = append(out, value...)
	}
	out = binary.BigEndian.AppendUint64(out, bytes)
	return append(out, 0)
}

func makeSignedBatch(t *testing.T, key *identity.Key, epoch [16]byte, sequence uint64, payload []byte) []byte {
	t.Helper()
	batch := Batch{Epoch: epoch, Sequence: sequence, Payload: payload}
	batch.Digest = sha256.Sum256(payload)
	signature, err := key.Sign([]byte(identity.RelayUsageContext), batch.SigningInput())
	require.NoError(t, err)
	return encodeForTest(batch, signature)
}

func makeUploadAuth(t *testing.T, key *identity.Key, relayID string, body []byte, now time.Time, nonce [32]byte) UploadAuthorization {
	t.Helper()
	timestamp := uint64(now.UnixMicro())
	transcript, err := UploadSigningInput("POST", UploadPath, timestamp, nonce, body)
	require.NoError(t, err)
	signature, err := key.Sign([]byte(identity.RelayUsageUploadContext), transcript)
	require.NoError(t, err)
	return UploadAuthorization{RelayID: relayID, TimestampMicros: timestamp, Nonce: nonce, Signature: signature}
}
