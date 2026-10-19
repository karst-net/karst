// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package compliance

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"
)

const InvalidationInterval = 5 * time.Second
const invalidationBatch = 100

// fingerprint deliberately excludes receipt time and the challenge. Identical
// refreshes extend evidence freshness but must not create an account-wide push
// every 30 seconds. All typed observations and collector version participate.
func fingerprint(report Report) string {
	data, _ := json.Marshal(report) // This struct contains only strings, no fallible encoders.
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// BackfillFreshness initializes up to 100 rows written before expiry scheduling was
// implemented. Conditional updates cannot overwrite a concurrent new report.
// Malformed legacy evidence is scheduled as expired; readers still fail closed
// on its decoding error. No raw observations are placed in notifications.
func (s *Store) BackfillFreshness(ctx context.Context, now time.Time) error {
	if now.IsZero() {
		return ErrInvalidSubject
	}
	var rows []evidenceRow
	if err := s.db.WithContext(ctx).Select("tenant_id", "device_id", "handle", "generation", "evidence_json", "collector_version").Where("evidence_expires_at IS NULL AND evidence_json <> ?", "").Limit(invalidationBatch).Find(&rows).Error; err != nil {
		return err
	}
	if len(rows) == 0 {
		return nil
	}
	for _, row := range rows {
		var e Evidence
		deadline := now.UTC()
		hash := ""
		if err := json.Unmarshal([]byte(row.EvidenceJSON), &e); err == nil && !e.ReceivedAt.IsZero() {
			deadline = e.ReceivedAt.Add(EvidenceLifetime)
			hash = fingerprint(Report{CollectorVersion: row.CollectorVersion, Platform: e.Platform, Distribution: e.Distribution, ClientVersion: e.ClientVersion, OSVersion: e.OSVersion})
		}
		update := s.db.WithContext(ctx).Model(&evidenceRow{}).Where(scope(Subject{TenantID: row.TenantID, DeviceID: row.DeviceID}, row.Handle)).Where("generation = ? AND evidence_expires_at IS NULL AND evidence_json <> ?", row.Generation, "").Updates(map[string]any{
			"evidence_expires_at": deadline, "evidence_fingerprint": hash, "expiry_notified": false,
			"notification_pending": true, "notification_revision": gorm.Expr("notification_revision + 1"), "notification_attempt": gorm.Expr("CASE WHEN notification_pending THEN notification_attempt ELSE 0 END"),
		})
		if update.Error != nil {
			return update.Error
		}
	}
	return nil
}

// Expire queues one invalidation when a stored generation reaches its freshness
// deadline. The conditional UPDATE is safe across replicas and cannot expire
// a concurrently refreshed generation. It does not delete retained evidence.
func (s *Store) Expire(ctx context.Context, now time.Time) error {
	if now.IsZero() {
		return ErrInvalidSubject
	}
	return s.db.WithContext(ctx).Model(&evidenceRow{}).Where("evidence_expires_at <= ? AND expiry_notified = ?", now.UTC(), false).Updates(map[string]any{
		"expiry_notified": true, "notification_pending": true,
		"notification_revision": gorm.Expr("notification_revision + 1"), "notification_attempt": gorm.Expr("CASE WHEN notification_pending THEN notification_attempt ELSE 0 END"),
	}).Error
}

// DispatchInvalidations sends lightweight re-fetch hints to every current peer
// in each affected tenant. All selected device changes in a tenant share one
// fanout. A callback error retains that tenant's pending changes for retry;
// successful revision-checked acknowledgments cannot erase a newer change.
// Concurrent dispatchers may deliver duplicates; recipients must re-read current
// state rather than interpret a hint as a verdict. last-attempt ordering keeps
// failing tenants from permanently occupying the first batch.
func (s *Store) DispatchInvalidations(ctx context.Context, now time.Time, notifyPeer func(context.Context, string) error) error {
	if now.IsZero() {
		return ErrInvalidSubject
	}
	if notifyPeer == nil {
		return errors.New("compliance: notification callback is required")
	}
	var rows []evidenceRow
	if err := s.db.WithContext(ctx).Select("tenant_id", "device_id", "handle", "notification_epoch", "notification_revision").Where("notification_pending = ?", true).Order("notification_attempt ASC").Order("tenant_id ASC").Order("device_id ASC").Order("handle ASC").Limit(invalidationBatch).Find(&rows).Error; err != nil {
		return err
	}
	byTenant := make(map[string][]evidenceRow)
	var tenants []string
	for _, row := range rows {
		if _, exists := byTenant[row.TenantID]; !exists {
			tenants = append(tenants, row.TenantID)
		}
		byTenant[row.TenantID] = append(byTenant[row.TenantID], row)
	}
	var failures []error
	for _, tenant := range tenants {
		// Preserve last-attempt ordering across tenants, and stamp only a
		// tenant we are actually about to dispatch. A slow/failing publisher
		// must not age unattempted tenants out of the next batch's priority.
		var selected []evidenceRow
		for _, row := range byTenant[tenant] {
			result := s.db.WithContext(ctx).Model(&evidenceRow{}).Where(scope(Subject{TenantID: row.TenantID, DeviceID: row.DeviceID}, row.Handle)).Where("notification_epoch = ? AND notification_revision = ? AND notification_pending = ?", row.NotificationEpoch, row.NotificationRevision, true).Update("notification_attempt", now.UTC().UnixNano())
			if result.Error != nil {
				return errors.Join(append(failures, result.Error)...)
			}
			if result.RowsAffected == 1 {
				selected = append(selected, row)
			}
		}
		if len(selected) == 0 {
			continue
		}
		var ids []string
		err := s.db.WithContext(ctx).Table("peers").Where("account_id = ?", tenant).Order("id ASC").Pluck("id", &ids).Error
		if err == nil {
			for _, id := range ids {
				if err = notifyPeer(ctx, id); err != nil {
					break
				}
			}
		}
		if err != nil {
			failures = append(failures, fmt.Errorf("compliance: notify tenant %s: %w", tenant, err))
			continue
		}
		for _, row := range selected {
			ack := s.db.WithContext(ctx).Model(&evidenceRow{}).Where(scope(Subject{TenantID: row.TenantID, DeviceID: row.DeviceID}, row.Handle)).Where("notification_epoch = ? AND notification_revision = ?", row.NotificationEpoch, row.NotificationRevision).Update("notification_pending", false)
			if ack.Error != nil {
				failures = append(failures, ack.Error)
			}
		}
	}
	return errors.Join(failures...)
}

// ProcessInvalidations runs one deterministic scheduler pass. Notification
// delivery is advisory: future permission issuance must evaluate authoritative
// evidence and enforce local expiry independently of this worker.
func (s *Store) ProcessInvalidations(ctx context.Context, now time.Time, notifyPeer func(context.Context, string) error) error {
	if err := s.BackfillFreshness(ctx, now); err != nil {
		return err
	}
	if err := s.Expire(ctx, now); err != nil {
		return err
	}
	return s.DispatchInvalidations(ctx, now, notifyPeer)
}

// StartInvalidationWorker performs startup recovery and checks every 5 seconds.
// The durable pending state survives restarts and publisher/SQL failures. Tick
// work is bounded by a context deadline; multiple replicas need no leader.
func (s *Store) StartInvalidationWorker(ctx context.Context, notifyPeer func(context.Context, string) error, onError func(error)) {
	go func() {
		tick := func() {
			tickCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
			defer cancel()
			if err := s.ProcessInvalidations(tickCtx, time.Now().UTC(), notifyPeer); err != nil && onError != nil {
				onError(err)
			}
		}
		tick()
		ticker := time.NewTicker(InvalidationInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				tick()
			}
		}
	}()
}
