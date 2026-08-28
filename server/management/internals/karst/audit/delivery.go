// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package audit

import (
	"context"
	"fmt"
	"time"
)

// SinkDeliverer sends one immutable audit entry to one sink. Keeping transport
// behind this narrow interface makes the outbox testable without a network and
// prevents delivery failures from acquiring write access to the audit chain.
type SinkDeliverer interface {
	Deliver(context.Context, Sink, Entry) error
}

// DeliverPending sends due outbox entries. A failed delivery remains queued
// with exponential backoff; a successfully delivered entry is never sent
// again. The return value is the number of successful deliveries.
func (l *Log) DeliverPending(ctx context.Context, deliverer SinkDeliverer, limit int) (int, error) {
	return l.DeliverPendingAt(ctx, deliverer, limit, time.Now().UTC())
}

// DeliverPendingAt is DeliverPending with an explicit clock. The delivery
// worker uses the current time; exposing the clock makes retry policy directly
// testable and avoids sleeping in correctness tests.
func (l *Log) DeliverPendingAt(ctx context.Context, deliverer SinkDeliverer, limit int, now time.Time) (int, error) {
	if deliverer == nil {
		return 0, fmt.Errorf("audit: nil sink deliverer")
	}
	if limit <= 0 {
		return 0, fmt.Errorf("audit: delivery limit must be positive")
	}
	now = now.UTC()
	var pending []Delivery
	if err := l.db.WithContext(ctx).Where("delivered_at IS NULL AND next_attempt <= ?", now).
		Order("next_attempt ASC").Limit(limit).Find(&pending).Error; err != nil {
		return 0, fmt.Errorf("audit: list pending deliveries: %w", err)
	}
	var delivered int
	for _, item := range pending {
		var sink Sink
		if err := l.db.WithContext(ctx).Where("account_id = ? AND id = ?", item.AccountID, item.SinkID).First(&sink).Error; err != nil {
			if err := l.failDelivery(ctx, item, fmt.Errorf("load sink: %w", err), now); err != nil {
				return delivered, err
			}
			continue
		}
		var entry Entry
		if err := l.db.WithContext(ctx).Where("seq = ?", item.Sequence).First(&entry).Error; err != nil {
			if err := l.failDelivery(ctx, item, fmt.Errorf("load entry: %w", err), now); err != nil {
				return delivered, err
			}
			continue
		}
		if err := deliverer.Deliver(ctx, sink, entry); err != nil {
			if err := l.failDelivery(ctx, item, err, now); err != nil {
				return delivered, err
			}
			continue
		}
		at := time.Now().UTC()
		if err := l.db.WithContext(ctx).Model(&Delivery{}).
			Where("account_id = ? AND sink_id = ? AND sequence = ? AND delivered_at IS NULL", item.AccountID, item.SinkID, item.Sequence).
			Updates(map[string]any{"delivered_at": at, "last_error": ""}).Error; err != nil {
			return delivered, fmt.Errorf("audit: mark delivery complete: %w", err)
		}
		delivered++
	}
	return delivered, nil
}

func (l *Log) failDelivery(ctx context.Context, item Delivery, cause error, now time.Time) error {
	attempts := item.Attempts + 1
	backoff := time.Second * time.Duration(1<<min(attempts-1, 10))
	if backoff > time.Hour {
		backoff = time.Hour
	}
	if err := l.db.WithContext(ctx).Model(&Delivery{}).
		Where("account_id = ? AND sink_id = ? AND sequence = ? AND delivered_at IS NULL", item.AccountID, item.SinkID, item.Sequence).
		Updates(map[string]any{"attempts": attempts, "next_attempt": now.Add(backoff), "last_error": cause.Error()}).Error; err != nil {
		return fmt.Errorf("audit: mark failed delivery: %w", err)
	}
	return nil
}

func min(left, right uint32) uint32 {
	if left < right {
		return left
	}
	return right
}
