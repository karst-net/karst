// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package audit

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"
)

// StartDeliveryWorker drains the durable outbox until ctx is cancelled. It
// makes one immediate pass at startup so a restart recovers queued events
// without waiting for the ticker.
func (l *Log) StartDeliveryWorker(ctx context.Context, deliverer SinkDeliverer, interval time.Duration, batch int) {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	if batch <= 0 {
		batch = 100
	}
	go func() {
		deliver := func() {
			if _, err := l.DeliverPending(ctx, deliverer, batch); err != nil && ctx.Err() == nil {
				log.WithContext(ctx).Errorf("deliver audit sinks: %v", err)
			}
		}
		deliver()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				deliver()
			}
		}
	}()
}
