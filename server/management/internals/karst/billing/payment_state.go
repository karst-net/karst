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
	"gorm.io/gorm/clause"
)

const (
	PaymentReady        = "ready"
	PaymentSubmitting   = "submitting"
	PaymentReconcile    = "reconcile"
	PaymentCheckout     = "checkout"
	PaymentPaid         = "paid"
	PaymentPastDue      = "past_due"
	PaymentOperatorHold = "operator_hold"
)

var (
	ErrPaymentNotFound     = errors.New("billing: payment outbox record not found")
	ErrPaymentConflict     = errors.New("billing: payment outbox record conflicts with finalized invoice")
	ErrWebhookConflict     = errors.New("billing: webhook event conflicts with previously received event")
	ErrInvalidPaymentState = errors.New("billing: invalid payment state transition")
)

// paymentOutboxRow is durable intent. A transition to submitting is written
// before making the provider request; after a crash or ambiguous response the
// record must be reconciled by invoice reference, never blindly resubmitted.
type paymentOutboxRow struct {
	InvoiceRef          string    `gorm:"primaryKey;size:67"`
	AccountID           string    `gorm:"size:128;not null;index:idx_billing_payment_retention"`
	PeriodStart         int64     `gorm:"not null"`
	PeriodEnd           int64     `gorm:"not null"`
	Currency            string    `gorm:"size:3;not null"`
	AmountMinor         int64     `gorm:"not null"`
	InvoiceHash         string    `gorm:"size:64;not null"`
	State               string    `gorm:"size:32;not null;index"`
	ProviderID          string    `gorm:"size:128"`
	ProviderCustomerID  string    `gorm:"size:128"`
	CheckoutURL         string    `gorm:"size:2048"`
	AttemptStartedAt    time.Time `gorm:"index"`
	LastProviderEventUS int64     `gorm:"not null;default:0"`
	UpdatedAt           time.Time `gorm:"not null;index:idx_billing_payment_retention"`
}

func (paymentOutboxRow) TableName() string { return "karst_billing_payment_outbox" }

// paymentHistoryRow preserves the durable, minimal state-transition audit for
// seven years independently of the shorter webhook delivery inbox retention.
type paymentHistoryRow struct {
	ID         uint      `gorm:"primaryKey"`
	InvoiceRef string    `gorm:"size:67;not null;index"`
	FromState  string    `gorm:"size:32;not null"`
	ToState    string    `gorm:"size:32;not null"`
	EventID    string    `gorm:"size:128"`
	CreatedAt  time.Time `gorm:"not null;index"`
}

func (paymentHistoryRow) TableName() string { return "karst_billing_payment_history" }

// PaymentIntent is a safe view of the durable charge intent. It contains no
// customer PII, card data, or webhook body.
type PaymentIntent struct {
	InvoiceReference   string    `json:"invoice_reference"`
	AccountID          string    `json:"account_id"`
	PeriodStart        time.Time `json:"period_start"`
	PeriodEnd          time.Time `json:"period_end"`
	Currency           string    `json:"currency"`
	AmountMinor        int64     `json:"amount_minor"`
	InvoiceSHA256      string    `json:"invoice_sha256"`
	State              string    `json:"state"`
	ProviderID         string    `json:"provider_id,omitempty"`
	ProviderCustomerID string    `json:"provider_customer_id,omitempty"`
	CheckoutURL        string    `json:"checkout_url,omitempty"`
	AttemptStartedAt   time.Time `json:"attempt_started_at,omitempty"`
	UpdatedAt          time.Time `json:"updated_at"`
}

// QueuePayment requires a persisted, finalized invoice and creates a stable,
// unique outbox entry. It performs no provider call.
func (s *Store) QueuePayment(ctx context.Context, start, end time.Time) (PaymentIntent, error) {
	invoice, err := s.Invoice(ctx, start, end)
	if err != nil {
		return PaymentIntent{}, err
	}
	if invoice.TotalMinor <= 0 || invoice.Currency != "USD" {
		return PaymentIntent{}, ErrInvalidPaddleInvoice
	}
	ref := paddleInvoiceReference(invoice)
	hash, err := digestJSON(invoice)
	if err != nil {
		return PaymentIntent{}, fmt.Errorf("billing: hash payment invoice: %w", err)
	}
	row := paymentOutboxRow{InvoiceRef: ref, AccountID: invoice.AccountID, PeriodStart: invoice.PeriodStart.UnixMicro(), PeriodEnd: invoice.PeriodEnd.UnixMicro(), Currency: invoice.Currency, AmountMinor: invoice.TotalMinor, InvoiceHash: hash, State: PaymentReady, UpdatedAt: time.Now().UTC()}
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		result := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&row)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 1 {
			return tx.Create(&paymentHistoryRow{InvoiceRef: ref, FromState: "", ToState: PaymentReady, CreatedAt: row.UpdatedAt}).Error
		}
		var existing paymentOutboxRow
		if err := tx.First(&existing, "invoice_ref = ?", ref).Error; err != nil {
			return err
		}
		if existing.AccountID != row.AccountID || existing.PeriodStart != row.PeriodStart || existing.PeriodEnd != row.PeriodEnd || existing.AmountMinor != row.AmountMinor || existing.Currency != row.Currency || existing.InvoiceHash != row.InvoiceHash {
			return ErrPaymentConflict
		}
		row = existing
		return nil
	})
	if err != nil {
		return PaymentIntent{}, fmt.Errorf("billing: queue payment: %w", err)
	}
	return paymentIntent(row), nil
}

func (s *Store) Payment(ctx context.Context, start, end time.Time) (PaymentIntent, error) {
	accountID, err := billingAccountFromContext(ctx)
	if err != nil {
		return PaymentIntent{}, err
	}
	startUS, endUS, err := billingPeriodMicros(start, end)
	if err != nil {
		return PaymentIntent{}, err
	}
	var row paymentOutboxRow
	err = s.db.WithContext(ctx).Where("account_id = ? AND period_start = ? AND period_end = ?", accountID, startUS, endUS).First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return PaymentIntent{}, ErrPaymentNotFound
	}
	if err != nil {
		return PaymentIntent{}, err
	}
	return paymentIntent(row), nil
}

// UpdatePaymentState uses a compare-and-set transition so concurrent workers
// cannot erase a webhook result or reuse an ambiguous create attempt.
func (s *Store) UpdatePaymentState(ctx context.Context, reference, expected, next, providerID, checkoutURL string) (PaymentIntent, error) {
	if !validPaymentTransition(expected, next) {
		return PaymentIntent{}, ErrInvalidPaymentState
	}
	now := time.Now().UTC()
	updates := map[string]any{"state": next, "updated_at": now}
	if next == PaymentSubmitting {
		updates["attempt_started_at"] = now
	}
	if providerID != "" {
		updates["provider_id"] = providerID
	}
	if checkoutURL != "" {
		updates["checkout_url"] = checkoutURL
	}
	var row paymentOutboxRow
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.First(&row, "invoice_ref = ?", reference).Error; err != nil {
			return ErrPaymentNotFound
		}
		if row.State == next {
			return nil
		}
		if row.State != expected {
			return ErrInvalidPaymentState
		}
		result := tx.Model(&paymentOutboxRow{}).Where("invoice_ref = ? AND state = ?", reference, expected).Updates(updates)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return ErrInvalidPaymentState
		}
		if err := tx.Create(&paymentHistoryRow{InvoiceRef: reference, FromState: expected, ToState: next, CreatedAt: now}).Error; err != nil {
			return err
		}
		row.State = next
		row.UpdatedAt = now
		if next == PaymentSubmitting {
			row.AttemptStartedAt = now
		}
		if providerID != "" {
			row.ProviderID = providerID
		}
		if checkoutURL != "" {
			row.CheckoutURL = checkoutURL
		}
		return nil
	})
	if err != nil {
		return PaymentIntent{}, err
	}
	return paymentIntent(row), nil
}

// SetPaymentCustomer associates the operator-provisioned Paddle customer with
// a not-yet-submitted invoice. A webhook must match this value before changing
// payment state.
func (s *Store) SetPaymentCustomer(ctx context.Context, reference, customerID string) (PaymentIntent, error) {
	if !validPaddleID(customerID, "ctm_") {
		return PaymentIntent{}, ErrInvalidPaddleInvoice
	}
	var row paymentOutboxRow
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.First(&row, "invoice_ref = ?", reference).Error; err != nil {
			return ErrPaymentNotFound
		}
		if row.ProviderCustomerID != "" && row.ProviderCustomerID != customerID {
			return ErrPaymentConflict
		}
		if row.State != PaymentReady {
			return ErrInvalidPaymentState
		}
		if row.ProviderCustomerID == "" {
			result := tx.Model(&paymentOutboxRow{}).Where("invoice_ref = ? AND state = ? AND provider_customer_id = ''", reference, PaymentReady).Updates(map[string]any{"provider_customer_id": customerID, "updated_at": time.Now().UTC()})
			if result.Error != nil {
				return result.Error
			}
			if result.RowsAffected != 1 {
				return ErrInvalidPaymentState
			}
			row.ProviderCustomerID = customerID
		}
		return nil
	})
	if err != nil {
		return PaymentIntent{}, err
	}
	return paymentIntent(row), nil
}

func validPaymentTransition(from, to string) bool {
	switch from {
	case PaymentReady:
		return to == PaymentSubmitting || to == PaymentOperatorHold
	case PaymentSubmitting:
		return to == PaymentReconcile || to == PaymentCheckout || to == PaymentPaid || to == PaymentPastDue || to == PaymentOperatorHold
	case PaymentReconcile:
		return to == PaymentCheckout || to == PaymentPaid || to == PaymentPastDue || to == PaymentOperatorHold
	case PaymentCheckout:
		return to == PaymentPaid || to == PaymentPastDue || to == PaymentOperatorHold
	case PaymentPastDue:
		return to == PaymentPaid || to == PaymentOperatorHold
	case PaymentOperatorHold:
		return to == PaymentReconcile || to == PaymentCheckout || to == PaymentPaid || to == PaymentPastDue
	default:
		return false
	}
}

func paymentIntent(row paymentOutboxRow) PaymentIntent {
	return PaymentIntent{InvoiceReference: row.InvoiceRef, AccountID: row.AccountID, PeriodStart: time.UnixMicro(row.PeriodStart).UTC(), PeriodEnd: time.UnixMicro(row.PeriodEnd).UTC(), Currency: row.Currency, AmountMinor: row.AmountMinor, InvoiceSHA256: row.InvoiceHash, State: row.State, ProviderID: row.ProviderID, ProviderCustomerID: row.ProviderCustomerID, CheckoutURL: row.CheckoutURL, AttemptStartedAt: row.AttemptStartedAt, UpdatedAt: row.UpdatedAt}
}

// NormalizedPaddleEvent is the only webhook representation persisted. Do not
// add raw request/body fields: Paddle signatures are verified before parsing.
type NormalizedPaddleEvent struct {
	EventID       string    `json:"event_id"`
	EventType     string    `json:"event_type"`
	OccurredAt    time.Time `json:"occurred_at"`
	TransactionID string    `json:"transaction_id,omitempty"`
	CustomerID    string    `json:"customer_id,omitempty"`
	InvoiceRef    string    `json:"invoice_reference,omitempty"`
	Status        string    `json:"status,omitempty"`
}

type webhookInboxRow struct {
	EventID     string     `gorm:"primaryKey;size:128"`
	EventType   string     `gorm:"size:128;not null"`
	OccurredUS  int64      `gorm:"not null;index"`
	ReceivedAt  time.Time  `gorm:"not null;index:idx_billing_webhook_retention"`
	ProcessedAt *time.Time `gorm:"index"`
	Payload     []byte     `gorm:"not null"`
}

func (webhookInboxRow) TableName() string { return "karst_billing_webhook_inbox" }

// RecordWebhook persists a normalized event idempotently before an HTTP
// handler acknowledges it. Raw webhook bytes and signature material are never
// stored. Exact duplicate delivery is successful; conflicting reuse is not.
func (s *Store) RecordWebhook(ctx context.Context, event NormalizedPaddleEvent) (bool, error) {
	if event.EventID == "" || len(event.EventID) > 128 || event.EventType == "" || len(event.EventType) > 128 || event.OccurredAt.IsZero() || event.OccurredAt.Location() == nil {
		return false, errors.New("billing: invalid normalized webhook event")
	}
	event.OccurredAt = event.OccurredAt.UTC()
	payload, err := json.Marshal(event)
	if err != nil {
		return false, err
	}
	row := webhookInboxRow{EventID: event.EventID, EventType: event.EventType, OccurredUS: event.OccurredAt.UnixMicro(), ReceivedAt: time.Now().UTC(), Payload: payload}
	result := s.db.WithContext(ctx).Clauses(clause.OnConflict{DoNothing: true}).Create(&row)
	if result.Error != nil {
		return false, result.Error
	}
	if result.RowsAffected != 0 {
		return true, nil
	}
	var old webhookInboxRow
	if err := s.db.WithContext(ctx).First(&old, "event_id = ?", event.EventID).Error; err != nil {
		return false, err
	}
	if old.EventType != row.EventType || old.OccurredUS != row.OccurredUS || string(old.Payload) != string(payload) {
		return false, ErrWebhookConflict
	}
	return false, nil
}

// PruneBillingHistory deletes records at or beyond their approved retention
// cutoffs. Invoices and payment audit/outbox state live seven years;
// normalized webhook events live thirteen months. No raw body is retained.
func (s *Store) PruneBillingHistory(ctx context.Context, now time.Time) error {
	if now.IsZero() {
		return errors.New("billing: pruning requires an explicit clock")
	}
	invoiceCutoff := now.UTC().AddDate(-7, 0, 0)
	eventCutoff := now.UTC().AddDate(0, -13, 0)
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("updated_at < ?", invoiceCutoff).Delete(&paymentOutboxRow{}).Error; err != nil {
			return err
		}
		if err := tx.Where("created_at < ?", invoiceCutoff).Delete(&paymentHistoryRow{}).Error; err != nil {
			return err
		}
		if err := tx.Where("received_at < ?", eventCutoff).Delete(&webhookInboxRow{}).Error; err != nil {
			return err
		}
		if err := tx.Where("finalized_at < ?", invoiceCutoff).Delete(&invoiceRow{}).Error; err != nil {
			return err
		}
		return nil
	})
}

// StartRetentionWorker prunes history at startup and on the requested cadence.
// Cancellation stops the worker; a nil error callback is allowed for callers
// that report database failures through their own health mechanism.
func (s *Store) StartRetentionWorker(ctx context.Context, interval time.Duration, onError func(error)) {
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	prune := func() {
		if err := s.PruneBillingHistory(ctx, time.Now().UTC()); err != nil && onError != nil {
			onError(err)
		}
	}
	prune()
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				prune()
			}
		}
	}()
}
