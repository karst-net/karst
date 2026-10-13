// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package billing

import (
	"context"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// schedulePaymentRetriesTx is called inside the first accepted past-due
// webhook transaction. Retries are anchored to provider occurrence time, not
// webhook receipt or worker time, and the composite key makes replay safe.
func schedulePaymentRetriesTx(tx *gorm.DB, payment *paymentOutboxRow, failedAt time.Time) error {
	if payment.FirstFailureAtUS != nil {
		return nil
	}
	failedAt = failedAt.UTC()
	failedAtUS := failedAt.UnixMicro()
	if err := tx.Model(&paymentOutboxRow{}).Where("invoice_ref = ? AND first_failure_at_us IS NULL", payment.InvoiceRef).
		Update("first_failure_at_us", failedAtUS).Error; err != nil {
		return err
	}
	payment.FirstFailureAtUS = &failedAtUS
	for index, days := range paymentRetryDays {
		attempt := paymentAttemptRow{
			InvoiceRef: payment.InvoiceRef, Number: index + 1, State: paymentRetryQueued,
			ScheduledAt: failedAt.AddDate(0, 0, days), UpdatedAt: failedAt,
		}
		if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&attempt).Error; err != nil {
			return err
		}
	}
	return nil
}

// ProcessScheduledPaymentRetries submits at most one retry per invoice in a
// pass. A retry is created only for a past-due invoice and only after Paddle's
// saved-payment-method list has confirmed the customer's Checkout opt-in or a
// fresh Checkout transaction can be returned. All API calls happen outside a
// SQL transaction.
func (s *Store) ProcessScheduledPaymentRetries(ctx context.Context, client *PaddleClient, now time.Time, limit int) error {
	if client == nil {
		return nil
	}
	if now.IsZero() || limit <= 0 || limit > 1000 {
		return errors.New("billing: invalid payment retry batch")
	}
	var rows []paymentAttemptRow
	err := s.db.WithContext(ctx).Table("karst_billing_payment_attempts AS r").
		Select("r.*").
		Joins("JOIN karst_billing_payment_outbox AS p ON p.invoice_ref = r.invoice_ref").
		Joins("JOIN karst_billing_paddle_accounts AS a ON a.account_id = p.account_id AND a.enabled = ?", true).
		Where("r.number > 0 AND r.state = ? AND r.scheduled_at <= ? AND p.state = ?", paymentRetryQueued, now.UTC(), PaymentPastDue).
		Order("r.scheduled_at ASC, r.invoice_ref ASC, r.number ASC").Limit(limit).Find(&rows).Error
	if err != nil {
		return err
	}
	var joined error
	seen := make(map[string]struct{}, len(rows))
	for _, candidate := range rows {
		if _, ok := seen[candidate.InvoiceRef]; ok {
			continue
		}
		seen[candidate.InvoiceRef] = struct{}{}
		if err := s.processPaymentRetry(ctx, client, candidate, now.UTC()); err != nil {
			joined = errors.Join(joined, fmt.Errorf("billing: process retry %s/%d: %w", candidate.InvoiceRef, candidate.Number, err))
		}
	}
	return joined
}

func (s *Store) processPaymentRetry(ctx context.Context, client *PaddleClient, candidate paymentAttemptRow, now time.Time) error {
	payment, attempt, claimed, err := s.claimPaymentRetry(ctx, candidate.InvoiceRef, candidate.Number, now)
	if err != nil || !claimed {
		return err
	}
	accountCtx := WithAccount(ctx, payment.AccountID)
	providerAccount, err := s.PaddleAccount(accountCtx)
	if err != nil {
		return s.releasePaymentRetry(ctx, payment.InvoiceRef, attempt.Number, err)
	}
	// The presence of a Paddle saved-method entity proves the customer opted
	// in through Checkout. If none exists, creating an automatic transaction
	// only yields Checkout; it must never capture a method from Karst storage.
	if _, err := client.HasSavedPaymentMethod(ctx, providerAccount.CustomerID); err != nil {
		return s.releasePaymentRetry(ctx, payment.InvoiceRef, attempt.Number, err)
	}
	start, end := time.UnixMicro(payment.PeriodStart).UTC(), time.UnixMicro(payment.PeriodEnd).UTC()
	invoice, err := s.Invoice(accountCtx, start, end)
	if err != nil {
		return s.finishPaymentRetry(ctx, payment.InvoiceRef, attempt.Number, PaymentSubmitting, PaymentOperatorHold, nil, 0)
	}
	request, err := BuildPaddleAttemptRequest(invoice, providerAccount.CustomerID, providerAccount.ProductID, attempt.Number)
	if err != nil {
		return s.finishPaymentRetry(ctx, payment.InvoiceRef, attempt.Number, PaymentSubmitting, PaymentOperatorHold, nil, 0)
	}
	transaction, createErr := client.CreateTransaction(ctx, request)
	if createErr != nil {
		finishErr := s.finishPaymentRetry(ctx, payment.InvoiceRef, attempt.Number, PaymentSubmitting, PaymentReconcile, nil, 0)
		return errors.Join(ErrPaymentRequiresReconciliation, createErr, finishErr)
	}
	return s.finishPaymentRetry(ctx, payment.InvoiceRef, attempt.Number, PaymentSubmitting, paddlePaymentState(transaction.Status), &transaction, 0)
}

func (s *Store) claimPaymentRetry(ctx context.Context, reference string, number int, now time.Time) (paymentOutboxRow, paymentAttemptRow, bool, error) {
	var payment paymentOutboxRow
	var attempt paymentAttemptRow
	claimed := false
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&payment, "invoice_ref = ?", reference).Error; err != nil {
			return err
		}
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&attempt, "invoice_ref = ? AND number = ?", reference, number).Error; err != nil {
			return err
		}
		if attempt.State != paymentRetryQueued || now.Before(attempt.ScheduledAt) {
			return nil
		}
		if payment.State != PaymentPastDue {
			attempt.State = paymentRetrySkipped
			attempt.UpdatedAt = now
			return tx.Model(&paymentAttemptRow{}).Where("invoice_ref = ? AND number = ? AND state = ?", reference, number, paymentRetryQueued).
				Updates(map[string]any{"state": paymentRetrySkipped, "updated_at": now}).Error
		}
		result := tx.Model(&paymentAttemptRow{}).Where("invoice_ref = ? AND number = ? AND state = ?", reference, number, paymentRetryQueued).
			Updates(map[string]any{"state": PaymentSubmitting, "attempt_started_at": now, "updated_at": now})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return nil
		}
		if err := tx.Model(&paymentOutboxRow{}).Where("invoice_ref = ? AND state = ?", reference, PaymentPastDue).
			Updates(map[string]any{"state": PaymentSubmitting, "latest_attempt": number, "attempt_started_at": now, "updated_at": now}).Error; err != nil {
			return err
		}
		if err := tx.Create(&paymentHistoryRow{InvoiceRef: reference, FromState: PaymentPastDue, ToState: PaymentSubmitting, CreatedAt: now}).Error; err != nil {
			return err
		}
		attempt.State, attempt.AttemptStartedAt, attempt.UpdatedAt = PaymentSubmitting, now, now
		payment.State, payment.LatestAttempt, payment.AttemptStartedAt, payment.UpdatedAt = PaymentSubmitting, number, now, now
		claimed = true
		return nil
	})
	return payment, attempt, claimed, err
}

func (s *Store) releasePaymentRetry(ctx context.Context, reference string, number int, cause error) error {
	now := time.Now().UTC()
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		result := tx.Model(&paymentAttemptRow{}).Where("invoice_ref = ? AND number = ? AND state = ? AND provider_id = ''", reference, number, PaymentSubmitting).
			Updates(map[string]any{"state": paymentRetryQueued, "attempt_started_at": time.Time{}, "updated_at": now})
		if result.Error != nil || result.RowsAffected == 0 {
			return result.Error
		}
		if err := tx.Model(&paymentOutboxRow{}).Where("invoice_ref = ? AND latest_attempt = ? AND state = ?", reference, number, PaymentSubmitting).
			Updates(map[string]any{"state": PaymentPastDue, "attempt_started_at": time.Time{}, "updated_at": now}).Error; err != nil {
			return err
		}
		return tx.Create(&paymentHistoryRow{InvoiceRef: reference, FromState: PaymentSubmitting, ToState: PaymentPastDue, CreatedAt: now}).Error
	})
	return errors.Join(cause, err)
}

func (s *Store) finishPaymentRetry(ctx context.Context, reference string, number int, expected, next string, transaction *PaddleTransaction, occurredUS int64) error {
	now := time.Now().UTC()
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var payment paymentOutboxRow
		var attempt paymentAttemptRow
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&payment, "invoice_ref = ?", reference).Error; err != nil {
			return err
		}
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&attempt, "invoice_ref = ? AND number = ?", reference, number).Error; err != nil {
			return err
		}
		if attempt.State == next && (transaction == nil || attempt.ProviderID == transaction.ID) {
			return nil
		}
		if attempt.State != expected {
			return ErrPaymentRetryConflict
		}
		attemptUpdates := map[string]any{"state": next, "updated_at": now}
		if transaction != nil {
			attemptUpdates["provider_id"] = transaction.ID
			attemptUpdates["checkout_url"] = transaction.Checkout.URL
		}
		if occurredUS != 0 {
			attemptUpdates["last_provider_event_us"] = occurredUS
		}
		if err := tx.Model(&paymentAttemptRow{}).Where("invoice_ref = ? AND number = ? AND state = ?", reference, number, expected).Updates(attemptUpdates).Error; err != nil {
			return err
		}
		invoiceUpdates := map[string]any{"updated_at": now}
		if next == PaymentPaid || payment.LatestAttempt == number {
			invoiceUpdates["state"] = next
			invoiceUpdates["provider_id"] = attempt.ProviderID
			invoiceUpdates["checkout_url"] = attempt.CheckoutURL
			if transaction != nil {
				invoiceUpdates["provider_id"] = transaction.ID
				invoiceUpdates["checkout_url"] = transaction.Checkout.URL
			}
		}
		if next == PaymentPaid {
			invoiceUpdates["state"] = PaymentPaid
		}
		if occurredUS != 0 && occurredUS > payment.LastProviderEventUS {
			invoiceUpdates["last_provider_event_us"] = occurredUS
		}
		if err := tx.Model(&paymentOutboxRow{}).Where("invoice_ref = ?", reference).Updates(invoiceUpdates).Error; err != nil {
			return err
		}
		from := expected
		if payment.LatestAttempt != number && next != PaymentPaid {
			from = payment.State
		}
		if from != next {
			if err := tx.Create(&paymentHistoryRow{InvoiceRef: reference, FromState: from, ToState: next, CreatedAt: now}).Error; err != nil {
				return err
			}
		}
		if next == PaymentCheckout || next == PaymentOperatorHold || next == PaymentPaid {
			if err := tx.Model(&paymentAttemptRow{}).Where("invoice_ref = ? AND number > ? AND state = ?", reference, number, paymentRetryQueued).
				Updates(map[string]any{"state": paymentRetrySkipped, "updated_at": now}).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

func paddlePaymentState(status string) string {
	switch status {
	case "completed", "paid":
		return PaymentPaid
	case "past_due":
		return PaymentPastDue
	case "draft", "ready", "billed":
		return PaymentCheckout
	default:
		return PaymentOperatorHold
	}
}

// ReconcilePendingPaymentAttempts finds a possibly-created transaction by its
// exact invoice/attempt custom data. A zero or multiple match never causes a
// second create. Expired or ambiguous lookups move to operator_hold.
func (s *Store) ReconcilePendingPaymentAttempts(ctx context.Context, client *PaddleClient, now time.Time, limit int) error {
	if client == nil {
		return nil
	}
	if now.IsZero() || limit <= 0 || limit > 1000 {
		return errors.New("billing: invalid payment reconciliation batch")
	}
	var rows []paymentAttemptRow
	if err := s.db.WithContext(ctx).Table("karst_billing_payment_attempts AS r").Select("r.*").
		Joins("JOIN karst_billing_payment_outbox AS p ON p.invoice_ref = r.invoice_ref").
		Joins("JOIN karst_billing_paddle_accounts AS a ON a.account_id = p.account_id AND a.enabled = ?", true).
		Where("r.state = ? AND p.state = ?", PaymentReconcile, PaymentReconcile).
		Order("r.updated_at ASC, r.invoice_ref ASC, r.number ASC").Limit(limit).Find(&rows).Error; err != nil {
		return err
	}
	var joined error
	for _, row := range rows {
		if err := s.reconcilePaymentAttempt(ctx, client, row, now.UTC()); err != nil {
			joined = errors.Join(joined, fmt.Errorf("billing: reconcile attempt %s/%d: %w", row.InvoiceRef, row.Number, err))
		}
	}
	return joined
}

func (s *Store) reconcilePaymentAttempt(ctx context.Context, client *PaddleClient, attempt paymentAttemptRow, now time.Time) error {
	var payment paymentOutboxRow
	if err := s.db.WithContext(ctx).First(&payment, "invoice_ref = ?", attempt.InvoiceRef).Error; err != nil {
		return err
	}
	if payment.ProviderCustomerID == "" || attempt.AttemptStartedAt.IsZero() || now.Before(attempt.AttemptStartedAt) {
		return s.finishPaymentRetry(ctx, attempt.InvoiceRef, attempt.Number, PaymentReconcile, PaymentOperatorHold, nil, 0)
	}
	if now.Sub(attempt.AttemptStartedAt) > paddleLookupWindow {
		return s.finishPaymentRetry(ctx, attempt.InvoiceRef, attempt.Number, PaymentReconcile, PaymentOperatorHold, nil, 0)
	}
	matches, err := client.FindTransactionsByAttempt(ctx, payment.ProviderCustomerID, attempt.InvoiceRef, attempt.Number, attempt.AttemptStartedAt, now)
	if err != nil {
		return err
	}
	if len(matches) == 0 {
		return ErrPaymentRequiresReconciliation
	}
	if len(matches) != 1 {
		return s.finishPaymentRetry(ctx, attempt.InvoiceRef, attempt.Number, PaymentReconcile, PaymentOperatorHold, nil, 0)
	}
	transaction := matches[0]
	return s.finishPaymentRetry(ctx, attempt.InvoiceRef, attempt.Number, PaymentReconcile, paddlePaymentState(transaction.Status), &transaction, 0)
}
