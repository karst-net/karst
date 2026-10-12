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
		if payment.ProviderID != "" && payment.ProviderID != event.TransactionID {
			return ErrWebhookConflict
		}
		if payment.LastProviderEventUS > inbox.OccurredUS || (payment.State == PaymentPaid && target != PaymentPaid) {
			return markWebhookProcessed(tx, &inbox, &processed)
		}
		if payment.State != target && !validPaymentTransition(payment.State, target) {
			return ErrInvalidPaymentState
		}
		updates := map[string]any{"provider_id": event.TransactionID, "last_provider_event_us": inbox.OccurredUS, "updated_at": time.Now().UTC()}
		if payment.State != target {
			updates["state"] = target
		}
		if err := tx.Model(&paymentOutboxRow{}).Where("invoice_ref = ?", event.InvoiceRef).Updates(updates).Error; err != nil {
			return err
		}
		if payment.State != target {
			if err := tx.Create(&paymentHistoryRow{InvoiceRef: event.InvoiceRef, FromState: payment.State, ToState: target, EventID: event.EventID, CreatedAt: time.Now().UTC()}).Error; err != nil {
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
