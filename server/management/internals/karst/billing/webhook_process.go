// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package billing

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"
)

// ProcessWebhook applies one persisted normalized event once. Events that
// arrive out of order are marked handled but cannot roll the payment state
// back. Events not relevant to a transaction payment are safely ignored.
func (s *Store) ProcessWebhook(ctx context.Context, eventID string) (bool, error) {
	if eventID == "" {
		return false, errors.New("billing: missing webhook event ID")
	}
	processed := false
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var inbox webhookInboxRow
		if err := tx.First(&inbox, "event_id = ?", eventID).Error; err != nil {
			return err
		}
		if inbox.ProcessedAt != nil {
			return nil
		}
		var event NormalizedPaddleEvent
		if err := json.Unmarshal(inbox.Payload, &event); err != nil {
			return err
		}
		var target string
		switch event.EventType {
		case "transaction.completed", "transaction.paid":
			target = PaymentPaid
		case "transaction.past_due", "transaction.payment_failed":
			target = PaymentPastDue
		case "transaction.ready", "transaction.billed":
			target = PaymentCheckout
		case "transaction.canceled":
			target = PaymentOperatorHold
		default:
			return markWebhookProcessed(tx, &inbox, &processed)
		}
		if event.InvoiceRef == "" || !validPaddleID(event.TransactionID, "txn_") {
			return errors.New("billing: webhook lacks a valid Karst invoice or Paddle transaction reference")
		}
		var payment paymentOutboxRow
		if err := tx.First(&payment, "invoice_ref = ?", event.InvoiceRef).Error; err != nil {
			return ErrPaymentNotFound
		}
		if payment.ProviderCustomerID == "" || event.CustomerID != payment.ProviderCustomerID {
			return ErrWebhookConflict
		}
		if event.AttemptNumber < 0 || event.AttemptNumber > len(paymentRetryDays) {
			return ErrWebhookConflict
		}
		if err := ensureInitialPaymentAttempt(tx, payment); err != nil {
			return err
		}
		var attempt paymentAttemptRow
		if err := tx.First(&attempt, "invoice_ref = ? AND number = ?", event.InvoiceRef, event.AttemptNumber).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) && event.AttemptNumber > 0 {
				return ErrWebhookConflict
			}
			return err
		}
		if attempt.ProviderID != "" && attempt.ProviderID != event.TransactionID {
			return ErrWebhookConflict
		}
		if attempt.LastProviderEventUS > inbox.OccurredUS || (payment.State == PaymentPaid && target != PaymentPaid) {
			return markWebhookProcessed(tx, &inbox, &processed)
		}
		if payment.State != target && payment.LatestAttempt == event.AttemptNumber && !validPaymentTransition(payment.State, target) {
			return ErrInvalidPaymentState
		}
		now := time.Now().UTC()
		attemptUpdates := map[string]any{"provider_id": event.TransactionID, "last_provider_event_us": inbox.OccurredUS, "updated_at": now}
		if target == PaymentPastDue || target == PaymentPaid || target == PaymentCheckout || target == PaymentOperatorHold {
			attemptUpdates["state"] = target
		}
		if err := tx.Model(&paymentAttemptRow{}).Where("invoice_ref = ? AND number = ?", event.InvoiceRef, event.AttemptNumber).Updates(attemptUpdates).Error; err != nil {
			return err
		}
		// Any successful attempt pays the invoice. Other attempt events can be
		// audited without moving the customer-visible invoice backwards.
		updates := map[string]any{"updated_at": now}
		if inbox.OccurredUS > payment.LastProviderEventUS {
			updates["last_provider_event_us"] = inbox.OccurredUS
		}
		if target == PaymentPaid || payment.LatestAttempt == event.AttemptNumber {
			updates["state"], updates["provider_id"] = target, event.TransactionID
			if payment.State == PaymentPaid && target != PaymentPaid {
				delete(updates, "state")
				delete(updates, "provider_id")
			}
		}
		if err := tx.Model(&paymentOutboxRow{}).Where("invoice_ref = ?", event.InvoiceRef).Updates(updates).Error; err != nil {
			return err
		}
		fromState := attempt.State
		if payment.LatestAttempt == event.AttemptNumber {
			fromState = payment.State
		}
		if fromState != target {
			if err := tx.Create(&paymentHistoryRow{InvoiceRef: event.InvoiceRef, FromState: fromState, ToState: target, EventID: event.EventID, CreatedAt: now}).Error; err != nil {
				return err
			}
		} else if target == PaymentPastDue {
			// Each distinct provider failure event can represent a later failed
			// collection attempt. Preserve it as a payment-audit entry so the
			// in-app notice feed can show it; duplicate event delivery is already
			// stopped by ProcessedAt above.
			if err := tx.Create(&paymentHistoryRow{InvoiceRef: event.InvoiceRef, FromState: PaymentPastDue, ToState: PaymentPastDue, EventID: event.EventID, CreatedAt: now}).Error; err != nil {
				return err
			}
		}
		if target == PaymentPastDue && payment.FirstFailureAtUS == nil {
			if err := schedulePaymentRetriesTx(tx, &payment, time.UnixMicro(inbox.OccurredUS)); err != nil {
				return err
			}
		}
		if target == PaymentPaid || target == PaymentCheckout || target == PaymentOperatorHold {
			if err := tx.Model(&paymentAttemptRow{}).Where("invoice_ref = ? AND number > ? AND state = ?", event.InvoiceRef, event.AttemptNumber, paymentRetryQueued).
				Updates(map[string]any{"state": paymentRetrySkipped, "updated_at": now}).Error; err != nil {
				return err
			}
		}
		return markWebhookProcessed(tx, &inbox, &processed)
	})
	return processed, err
}

// ProcessPendingWebhooks applies oldest normalized events first. Events are
// still individually ordered by their provider occurrence time for each
// payment, so a late delivery cannot replace newer payment state.
func (s *Store) ProcessPendingWebhooks(ctx context.Context, limit int) error {
	if limit <= 0 || limit > 1000 {
		return errors.New("billing: invalid webhook batch limit")
	}
	var rows []webhookInboxRow
	if err := s.db.WithContext(ctx).Where("processed_at IS NULL").Order("occurred_us ASC, event_id ASC").Limit(limit).Find(&rows).Error; err != nil {
		return err
	}
	var joined error
	for _, row := range rows {
		if _, err := s.ProcessWebhook(ctx, row.EventID); err != nil {
			joined = errors.Join(joined, fmt.Errorf("event %s: %w", row.EventID, err))
		}
	}
	return joined
}

// StartWebhookWorker continuously applies the durable inbox. Provider API
// calls remain outside request handling; payment state changes cannot enter
// the relay forwarding path.
func (s *Store) StartWebhookWorker(ctx context.Context, interval time.Duration, onError func(error)) {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	process := func() {
		if err := s.ProcessPendingWebhooks(ctx, 100); err != nil && onError != nil {
			onError(err)
		}
	}
	process()
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				process()
			}
		}
	}()
}

func markWebhookProcessed(tx *gorm.DB, inbox *webhookInboxRow, processed *bool) error {
	now := time.Now().UTC()
	result := tx.Model(&webhookInboxRow{}).Where("event_id = ? AND processed_at IS NULL", inbox.EventID).Update("processed_at", now)
	if result.Error != nil {
		return result.Error
	}
	*processed = result.RowsAffected == 1
	return nil
}
