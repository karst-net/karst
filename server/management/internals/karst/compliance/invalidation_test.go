// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package compliance_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/netbirdio/netbird/management/internals/karst/compliance"
)

func acceptReport(t *testing.T, s *compliance.Store, subject compliance.Subject, handle string, r compliance.Report, at time.Time) {
	t.Helper()
	ctx := context.Background()
	c, err := s.Issue(ctx, subject, handle, at)
	require.NoError(t, err)
	require.NoError(t, s.Submit(ctx, subject, handle, c.Token, r, at))
}
func pending(t *testing.T, db *gorm.DB, tenant string) int64 {
	t.Helper()
	var count int64
	require.NoError(t, db.Table("karst_device_compliance").Where("tenant_id = ? AND notification_pending = ?", tenant, true).Count(&count).Error)
	return count
}
func recorder(ids *[]string) func(context.Context, string) error {
	return func(_ context.Context, id string) error { *ids = append(*ids, id); return nil }
}

func TestEvidenceChangesExpiryAndRecoveryInvalidate(t *testing.T) {
	db, a, b := ingestionDB(t)
	ctx := context.Background()
	var ids []string
	acceptReport(t, a, subject, "identity-a", report(), now)
	require.EqualValues(t, 1, pending(t, db, subject.TenantID))
	require.NoError(t, b.ProcessInvalidations(ctx, now, recorder(&ids)))
	require.Equal(t, []string{subject.DeviceID}, ids)
	ids = nil
	// An identical report extends freshness without creating a push every poll.
	refresh := now.Add(30 * time.Second)
	acceptReport(t, b, subject, "identity-a", report(), refresh)
	require.NoError(t, a.ProcessInvalidations(ctx, refresh, recorder(&ids)))
	require.Empty(t, ids)
	deadline := refresh.Add(compliance.EvidenceLifetime)
	require.NoError(t, a.ProcessInvalidations(ctx, deadline.Add(-time.Nanosecond), recorder(&ids)))
	require.Empty(t, ids)
	require.NoError(t, b.ProcessInvalidations(ctx, deadline, recorder(&ids)))
	require.Equal(t, []string{subject.DeviceID}, ids)
	ids = nil
	require.NoError(t, a.ProcessInvalidations(ctx, deadline.Add(time.Second), recorder(&ids)))
	require.Empty(t, ids, "the same expired generation must not repeatedly notify")
	latest, err := a.Latest(ctx, subject, "identity-a", deadline)
	require.NoError(t, err)
	evaluation, err := compliance.Evaluate([]compliance.Requirement{clientRequirement()}, subject, &latest.Evidence, deadline)
	require.NoError(t, err)
	require.Equal(t, compliance.Stale, evaluation.Results[0].State)
	// A new passing generation after the old deadline is recovery even if its
	// observed values have not changed.
	recovery := deadline.Add(2 * time.Second)
	acceptReport(t, b, subject, "identity-a", report(), recovery)
	require.NoError(t, a.ProcessInvalidations(ctx, recovery, recorder(&ids)))
	require.Equal(t, []string{subject.DeviceID}, ids)
	ids = nil
	failed := report()
	failed.ClientVersion = compliance.Observation{Status: compliance.CollectionError}
	acceptReport(t, a, subject, "identity-a", failed, recovery.Add(time.Second))
	require.NoError(t, b.ProcessInvalidations(ctx, recovery.Add(time.Second), recorder(&ids)))
	require.Equal(t, []string{subject.DeviceID}, ids)
	latest, err = b.Latest(ctx, subject, "identity-a", recovery.Add(time.Second))
	require.NoError(t, err)
	evaluation, err = compliance.Evaluate([]compliance.Requirement{clientRequirement()}, subject, &latest.Evidence, recovery.Add(time.Second))
	require.NoError(t, err)
	require.False(t, evaluation.Satisfied())
}

func TestInvalidationsCoalescePerTenantAndRetryFailures(t *testing.T) {
	db, a, b := ingestionDB(t)
	ctx := context.Background()
	second := compliance.Subject{TenantID: subject.TenantID, DeviceID: "device-b"}
	other := compliance.Subject{TenantID: "tenant-b", DeviceID: "device-c"}
	require.NoError(t, db.Create(&[]enrollment{{ID: second.DeviceID, AccountID: second.TenantID, Key: "identity-b"}, {ID: other.DeviceID, AccountID: other.TenantID, Key: "identity-c"}}).Error)
	acceptReport(t, a, subject, "identity-a", report(), now)
	acceptReport(t, b, second, "identity-b", report(), now)
	var ids []string
	require.NoError(t, a.ProcessInvalidations(ctx, now, recorder(&ids)))
	require.ElementsMatch(t, []string{subject.DeviceID, second.DeviceID}, ids, "one fanout, only this tenant")
	changed := report()
	changed.ClientVersion.Version = "0.0.9"
	acceptReport(t, b, subject, "identity-a", changed, now.Add(time.Second))
	acceptReport(t, a, other, "identity-c", report(), now.Add(time.Second))
	failure := errors.New("publisher unavailable")
	err := b.ProcessInvalidations(ctx, now.Add(time.Second), func(_ context.Context, id string) error {
		if id == subject.DeviceID {
			return failure
		}
		return nil
	})
	require.ErrorIs(t, err, failure)
	require.EqualValues(t, 1, pending(t, db, subject.TenantID))
	require.Zero(t, pending(t, db, other.TenantID))
	// Independent store/connection models restart recovery, not a process-local
	// callback queue. Duplicate deliveries after partial failure are permitted.
	ids = nil
	require.NoError(t, a.ProcessInvalidations(ctx, now.Add(2*time.Second), recorder(&ids)))
	require.ElementsMatch(t, []string{subject.DeviceID, second.DeviceID}, ids)
	require.Zero(t, pending(t, db, subject.TenantID))
}

func TestNewerInvalidationSurvivesAnOlderAcknowledgment(t *testing.T) {
	db, a, b := ingestionDB(t)
	ctx := context.Background()
	acceptReport(t, a, subject, "identity-a", report(), now)
	changed := report()
	changed.ClientVersion.Version = "0.0.1"
	require.NoError(t, a.ProcessInvalidations(ctx, now, func(context.Context, string) error {
		acceptReport(t, b, subject, "identity-a", changed, now.Add(time.Second))
		return nil
	}))
	require.EqualValues(t, 1, pending(t, db, subject.TenantID), "acknowledging the selected revision must not clear a newer failure")
	var ids []string
	require.NoError(t, b.ProcessInvalidations(ctx, now.Add(time.Second), recorder(&ids)))
	require.Equal(t, []string{subject.DeviceID}, ids)
	require.Zero(t, pending(t, db, subject.TenantID))
}

func TestFreshnessBackfillAndMalformedLegacyEvidence(t *testing.T) {
	db, a, b := ingestionDB(t)
	ctx := context.Background()
	acceptReport(t, a, subject, "identity-a", report(), now)
	// Model a row persisted by the prior release before these scheduling fields
	// existed. Migration must derive the deadline from the old receipt, not boot.
	require.NoError(t, db.Table("karst_device_compliance").Where("device_id = ?", subject.DeviceID).Updates(map[string]any{"evidence_expires_at": nil, "evidence_fingerprint": "", "notification_pending": false, "notification_revision": 0, "notification_epoch": ""}).Error)
	var ids []string
	deadline := now.Add(compliance.EvidenceLifetime)
	require.NoError(t, b.ProcessInvalidations(ctx, deadline, recorder(&ids)))
	require.Equal(t, []string{subject.DeviceID}, ids)
	var row struct {
		EvidenceExpiresAt time.Time
		ExpiryNotified    bool
	}
	require.NoError(t, db.Table("karst_device_compliance").Take(&row).Error)
	require.Equal(t, deadline, row.EvidenceExpiresAt)
	require.True(t, row.ExpiryNotified)
	ids = nil
	require.NoError(t, a.ProcessInvalidations(ctx, deadline, recorder(&ids)))
	require.Empty(t, ids)
	require.NoError(t, db.Table("karst_device_compliance").Where("device_id = ?", subject.DeviceID).Updates(map[string]any{"evidence_json": "malformed", "evidence_expires_at": nil}).Error)
	require.NoError(t, b.ProcessInvalidations(ctx, deadline.Add(time.Second), recorder(&ids)))
	require.Equal(t, []string{subject.DeviceID}, ids)
	_, err := a.Latest(ctx, subject, "identity-a", deadline.Add(time.Second))
	require.Error(t, err)
}

func TestInvalidationBatchDoesNotStarveOtherTenants(t *testing.T) {
	db, a, _ := ingestionDB(t)
	ctx := context.Background()
	for i := 0; i < 100; i++ {
		s := compliance.Subject{TenantID: "tenant-a", DeviceID: fmt.Sprintf("queued-%03d", i)}
		handle := fmt.Sprintf("key-%03d", i)
		require.NoError(t, db.Create(&enrollment{ID: s.DeviceID, AccountID: s.TenantID, Key: handle}).Error)
		acceptReport(t, a, s, handle, report(), now)
	}
	other := compliance.Subject{TenantID: "tenant-b", DeviceID: "other-peer"}
	require.NoError(t, db.Create(&enrollment{ID: other.DeviceID, AccountID: other.TenantID, Key: "other-key"}).Error)
	acceptReport(t, a, other, "other-key", report(), now)
	notifiedOther := false
	var attempted []string
	callback := func(_ context.Context, id string) error {
		attempted = append(attempted, id)
		if id == other.DeviceID {
			notifiedOther = true
			return nil
		}
		return errors.New("tenant-a publisher failure")
	}
	require.Error(t, a.ProcessInvalidations(ctx, now, callback))
	require.False(t, notifiedOther)
	// A hot failing tenant must not jump ahead of unattempted tenants just
	// because its devices submit newer observations while retry is pending.
	changed := report()
	changed.ClientVersion.Version = "0.2.0"
	for i := 0; i < 100; i++ {
		device := compliance.Subject{TenantID: "tenant-a", DeviceID: fmt.Sprintf("queued-%03d", i)}
		acceptReport(t, a, device, fmt.Sprintf("key-%03d", i), changed, now.Add(time.Second))
	}
	attempted = nil
	require.Error(t, a.ProcessInvalidations(ctx, now.Add(time.Second), callback))
	require.NotEmpty(t, attempted)
	require.Equal(t, other.DeviceID, attempted[0], "the oldest unattempted tenant must dispatch first")
	require.True(t, notifiedOther, "unattempted tenants must sort before retries")
	require.Zero(t, pending(t, db, other.TenantID))
}

func TestInvalidationValidationAndUnconsumedChallenges(t *testing.T) {
	_, a, _ := ingestionDB(t)
	ctx := context.Background()
	notify := func(context.Context, string) error { return nil }
	require.Error(t, a.DispatchInvalidations(ctx, now, nil))
	require.ErrorIs(t, a.ProcessInvalidations(ctx, time.Time{}, notify), compliance.ErrInvalidSubject)
	_, err := a.Issue(ctx, subject, "identity-a", now)
	require.NoError(t, err)
	var ids []string
	require.NoError(t, a.ProcessInvalidations(ctx, now.Add(time.Hour), recorder(&ids)))
	require.Empty(t, ids, "an unused challenge is not evidence")
}

func TestRecreatedEvidenceRowCannotBeAcknowledgedByItsPredecessor(t *testing.T) {
	db, a, b := ingestionDB(t)
	ctx := context.Background()
	acceptReport(t, a, subject, "identity-a", report(), now)
	failed := report()
	failed.ClientVersion = compliance.Observation{Status: compliance.CollectionError}
	require.NoError(t, a.ProcessInvalidations(ctx, now, func(context.Context, string) error {
		// Model retention cleanup and immediate recreation while a publication is
		// in flight. The revision counter restarts, but the row incarnation must not.
		require.NoError(t, db.Exec("DELETE FROM karst_device_compliance WHERE device_id = ?", subject.DeviceID).Error)
		acceptReport(t, b, subject, "identity-a", failed, now.Add(time.Second))
		return nil
	}))
	require.EqualValues(t, 1, pending(t, db, subject.TenantID))
	var ids []string
	require.NoError(t, b.ProcessInvalidations(ctx, now.Add(time.Second), recorder(&ids)))
	require.Equal(t, []string{subject.DeviceID}, ids)
	require.Zero(t, pending(t, db, subject.TenantID))
}
