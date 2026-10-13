// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package billing

import (
	"context"
	"errors"
	"fmt"
	"time"
)

var ErrPaymentRequiresReconciliation = errors.New("billing: payment create outcome requires provider reconciliation")

// SubmitFinalizedInvoice queues and submits one finalized invoice. The
// submitting state is persisted before the one-shot provider request; any
// transport or response error moves the intent to reconcile and prevents a
// blind second create.
func (s *Store) SubmitFinalizedInvoice(ctx context.Context, client *PaddleClient, start, end time.Time, customerID, productID string) (PaymentIntent, error) {
	if client == nil {
		return PaymentIntent{}, ErrPaddleAPIUnavailable
	}
	invoice, err := s.Invoice(ctx, start, end)
	if err != nil {
		return PaymentIntent{}, err
	}
	request, err := BuildPaddleTransactionRequest(invoice, customerID, productID)
	if err != nil {
		return PaymentIntent{}, err
	}
	intent, err := s.QueuePayment(ctx, start, end)
	if err != nil {
		return PaymentIntent{}, err
	}
	if intent.State != PaymentReady {
		return intent, ErrPaymentRequiresReconciliation
	}
	intent, err = s.SetPaymentCustomer(ctx, intent.InvoiceReference, customerID)
	if err != nil {
		return PaymentIntent{}, err
	}
	intent, err = s.UpdatePaymentState(ctx, intent.InvoiceReference, PaymentReady, PaymentSubmitting, "", "")
	if err != nil {
		return PaymentIntent{}, err
	}
	transaction, requestErr := client.CreateTransaction(ctx, request)
	if requestErr != nil {
		intent, stateErr := s.UpdatePaymentState(ctx, intent.InvoiceReference, PaymentSubmitting, PaymentReconcile, "", "")
		if stateErr != nil {
			return PaymentIntent{}, errors.Join(requestErr, stateErr)
		}
		return intent, errors.Join(ErrPaymentRequiresReconciliation, requestErr)
	}
	var next string
	switch transaction.Status {
	case "completed", "paid":
		next = PaymentPaid
	case "past_due":
		next = PaymentPastDue
	case "draft", "ready", "billed":
		next = PaymentCheckout
	default:
		intent, stateErr := s.UpdatePaymentState(ctx, intent.InvoiceReference, PaymentSubmitting, PaymentOperatorHold, transaction.ID, transaction.Checkout.URL)
		if stateErr != nil {
			return PaymentIntent{}, stateErr
		}
		return intent, ErrPaymentRequiresReconciliation
	}
	return s.UpdatePaymentState(ctx, intent.InvoiceReference, PaymentSubmitting, next, transaction.ID, transaction.Checkout.URL)
}

// ReconcilePayment performs only a bounded lookup for an ambiguous create. A
// missing or multiple match never triggers another create; operations remain
// in reconcile or move to operator hold.
func (s *Store) ReconcilePayment(ctx context.Context, client *PaddleClient, start, end, now time.Time, customerID string) (PaymentIntent, error) {
	if client == nil {
		return PaymentIntent{}, ErrPaddleAPIUnavailable
	}
	intent, err := s.Payment(ctx, start, end)
	if err != nil {
		return PaymentIntent{}, err
	}
	if intent.State != PaymentReconcile {
		return intent, ErrInvalidPaymentState
	}
	if intent.ProviderCustomerID == "" || customerID != intent.ProviderCustomerID {
		return PaymentIntent{}, ErrPaymentConflict
	}
	if intent.AttemptStartedAt.IsZero() || now.IsZero() || now.Before(intent.AttemptStartedAt) || now.Sub(intent.AttemptStartedAt) > paddleLookupWindow {
		return s.UpdatePaymentState(ctx, intent.InvoiceReference, PaymentReconcile, PaymentOperatorHold, "", "")
	}
	matches, err := client.FindTransactionsByInvoice(ctx, customerID, intent.InvoiceReference, intent.AttemptStartedAt, now)
	if err != nil {
		return intent, err
	}
	if len(matches) == 0 {
		return intent, ErrPaymentRequiresReconciliation
	}
	if len(matches) != 1 {
		intent, updateErr := s.UpdatePaymentState(ctx, intent.InvoiceReference, PaymentReconcile, PaymentOperatorHold, "", "")
		if updateErr != nil {
			return PaymentIntent{}, updateErr
		}
		return intent, ErrPaymentRequiresReconciliation
	}
	transaction := matches[0]
	var next string
	switch transaction.Status {
	case "completed", "paid":
		next = PaymentPaid
	case "past_due":
		next = PaymentPastDue
	case "draft", "ready", "billed":
		next = PaymentCheckout
	default:
		next = PaymentOperatorHold
	}
	return s.UpdatePaymentState(ctx, intent.InvoiceReference, PaymentReconcile, next, transaction.ID, transaction.Checkout.URL)
}

// ProcessReadyPayments handles only explicitly opted-in accounts. It is safe
// to run on every management replica because the transition to submitting is
// compare-and-set and every create remains one-shot.
func (s *Store) ProcessReadyPayments(ctx context.Context, client *PaddleClient, limit int) error {
	if client == nil {
		return nil
	}
	if limit <= 0 || limit > 1000 {
		return errors.New("billing: invalid payment batch limit")
	}
	var rows []paymentOutboxRow
	err := s.db.WithContext(ctx).Table("karst_billing_payment_outbox AS p").
		Select("p.*").Joins("JOIN karst_billing_paddle_accounts AS a ON a.account_id = p.account_id AND a.enabled = ?", true).
		Where("p.state = ?", PaymentReady).Order("p.updated_at ASC, p.invoice_ref ASC").Limit(limit).Scan(&rows).Error
	if err != nil {
		return err
	}
	var failures error
	for _, row := range rows {
		accountCtx := WithAccount(ctx, row.AccountID)
		providerAccount, err := s.PaddleAccount(accountCtx)
		if err == nil {
			start, end := time.UnixMicro(row.PeriodStart).UTC(), time.UnixMicro(row.PeriodEnd).UTC()
			_, err = s.SubmitFinalizedInvoice(accountCtx, client, start, end, providerAccount.CustomerID, providerAccount.ProductID)
		}
		if err != nil {
			failures = errors.Join(failures, fmt.Errorf("billing: process payment %s: %w", row.InvoiceRef, err))
		}
	}
	return failures
}

// StartPaymentWorker submits queued invoices only when the caller supplied an
// enabled Paddle client. The database's per-account opt-in is checked for each
// item; absent or disabled configuration cannot create a provider request.
func (s *Store) StartPaymentWorker(ctx context.Context, client *PaddleClient, interval time.Duration, onError func(error)) {
	if client == nil {
		return
	}
	if interval <= 0 {
		interval = time.Minute
	}
	process := func() {
		now := time.Now().UTC()
		var runErr error
		for _, err := range []error{
			s.ProcessReadyPayments(ctx, client, 100),
			s.ReconcilePendingPaymentAttempts(ctx, client, now, 100),
			s.ProcessScheduledPaymentRetries(ctx, client, now, 100),
		} {
			runErr = errors.Join(runErr, err)
		}
		if runErr != nil && onError != nil {
			onError(runErr)
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
