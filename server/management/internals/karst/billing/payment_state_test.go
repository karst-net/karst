// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package billing

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestPaymentOutboxRequiresFinalInvoiceAndIsIdempotent(t *testing.T) {
	store := testBillingStore(t)
	ctx := WithAccount(context.Background(), "payment-org")
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	end := start.AddDate(0, 1, 0)
	if _, err := store.QueuePayment(ctx, start, end); !errors.Is(err, ErrInvoiceNotFound) {
		t.Fatalf("queue without invoice = %v", err)
	}
	if err := store.PutSchedule(ctx, testSchedule()); err != nil {
		t.Fatal(err)
	}
	if err := store.AssignSchedule(ctx, start, end, testSchedule().Version); err != nil {
		t.Fatal(err)
	}
	devices := completeDeviceReport(start, end, deviceSegment(start, end, 2))
	if _, err := store.FinalizeInvoice(ctx, devices, completeRelayReport(start, end, "0")); err != nil {
		t.Fatal(err)
	}
	first, err := store.QueuePayment(ctx, start, end)
	if err != nil || first.State != PaymentReady || first.AmountMinor != 500 {
		t.Fatalf("queue payment = %+v, %v", first, err)
	}
	second, err := store.QueuePayment(ctx, start, end)
	if err != nil || second.InvoiceReference != first.InvoiceReference || second.State != first.State {
		t.Fatalf("idempotent queue = %+v, %v", second, err)
	}
	updated, err := store.UpdatePaymentState(ctx, first.InvoiceReference, PaymentReady, PaymentSubmitting, "", "")
	if err != nil || updated.State != PaymentSubmitting {
		t.Fatalf("begin submit = %+v, %v", updated, err)
	}
	if _, err := store.UpdatePaymentState(ctx, first.InvoiceReference, PaymentSubmitting, PaymentReady, "", ""); !errors.Is(err, ErrInvalidPaymentState) {
		t.Fatalf("unsafe retry transition = %v", err)
	}
	updated, err = store.UpdatePaymentState(ctx, first.InvoiceReference, PaymentSubmitting, PaymentReconcile, "", "")
	if err != nil || updated.State != PaymentReconcile {
		t.Fatalf("ambiguous result transition = %+v, %v", updated, err)
	}
	var history int64
	if err := store.db.Model(&paymentHistoryRow{}).Where("invoice_ref = ?", first.InvoiceReference).Count(&history).Error; err != nil || history != 3 {
		t.Fatalf("payment transition history count=%d err=%v; want queued, submitting, reconcile", history, err)
	}
}

func TestWebhookInboxDeduplicatesNormalizedEvents(t *testing.T) {
	store := testBillingStore(t)
	event := NormalizedPaddleEvent{EventID: "evt_123", EventType: "transaction.completed", OccurredAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), TransactionID: "txn_123", InvoiceRef: "ki_example", Status: "completed"}
	inserted, err := store.RecordWebhook(context.Background(), event)
	if err != nil || !inserted {
		t.Fatalf("first event = %v, %v", inserted, err)
	}
	inserted, err = store.RecordWebhook(context.Background(), event)
	if err != nil || inserted {
		t.Fatalf("duplicate event = %v, %v", inserted, err)
	}
	conflict := event
	conflict.Status = "past_due"
	if _, err := store.RecordWebhook(context.Background(), conflict); !errors.Is(err, ErrWebhookConflict) {
		t.Fatalf("conflicting duplicate = %v", err)
	}
}

func TestWebhookWorkerAppliesEventsIdempotentlyAndIgnoresOutOfOrderState(t *testing.T) {
	store, ctx, start, end := finalizedTestInvoice(t)
	intent, err := store.QueuePayment(ctx, start, end)
	if err != nil {
		t.Fatal(err)
	}
	intent, err = store.SetPaymentCustomer(ctx, intent.InvoiceReference, testPaddleCustomer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpdatePaymentState(ctx, intent.InvoiceReference, PaymentReady, PaymentSubmitting, "", ""); err != nil {
		t.Fatal(err)
	}
	eventAt := time.Date(2026, 2, 1, 1, 0, 0, 0, time.UTC)
	event := NormalizedPaddleEvent{EventID: "evt_completed", EventType: "transaction.completed", OccurredAt: eventAt, TransactionID: "txn_01grnn4zta5a1mf02jjze7y2ys", CustomerID: testPaddleCustomer, InvoiceRef: intent.InvoiceReference, Status: "completed"}
	if _, err := store.RecordWebhook(ctx, event); err != nil {
		t.Fatal(err)
	}
	if err := store.ProcessPendingWebhooks(ctx, 100); err != nil {
		t.Fatal(err)
	}
	got, err := store.Payment(ctx, start, end)
	if err != nil || got.State != PaymentPaid || got.ProviderID != event.TransactionID {
		t.Fatalf("applied webhook payment = %+v, %v", got, err)
	}
	processed, err := store.ProcessWebhook(ctx, event.EventID)
	if err != nil || processed {
		t.Fatalf("duplicate process = %v, %v", processed, err)
	}
	older := NormalizedPaddleEvent{EventID: "evt_past_due", EventType: "transaction.past_due", OccurredAt: eventAt.Add(-time.Minute), TransactionID: event.TransactionID, CustomerID: testPaddleCustomer, InvoiceRef: intent.InvoiceReference, Status: "past_due"}
	if _, err := store.RecordWebhook(ctx, older); err != nil {
		t.Fatal(err)
	}
	if err := store.ProcessPendingWebhooks(ctx, 100); err != nil {
		t.Fatal(err)
	}
	got, err = store.Payment(ctx, start, end)
	if err != nil || got.State != PaymentPaid {
		t.Fatalf("out-of-order event rolled back payment: %+v, %v", got, err)
	}
}

func TestPruneBillingHistoryUsesApprovedCalendarCutoffs(t *testing.T) {
	store := testBillingStore(t)
	now := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	oldPayment := paymentOutboxRow{InvoiceRef: "old", AccountID: "org", PeriodStart: 1, PeriodEnd: 2, Currency: "USD", AmountMinor: 10, InvoiceHash: "hash", State: PaymentPaid, UpdatedAt: now.AddDate(-7, 0, 0).Add(-time.Second)}
	newPayment := oldPayment
	newPayment.InvoiceRef = "new"
	newPayment.UpdatedAt = now.AddDate(-7, 0, 0)
	oldEvent := webhookInboxRow{EventID: "old", EventType: "test", OccurredUS: 1, ReceivedAt: now.AddDate(0, -13, 0).Add(-time.Second), Payload: []byte(`{"event_id":"old"}`)}
	newEvent := oldEvent
	newEvent.EventID = "new"
	newEvent.ReceivedAt = now.AddDate(0, -13, 0)
	if err := store.db.Create(&[]paymentOutboxRow{oldPayment, newPayment}).Error; err != nil {
		t.Fatal(err)
	}
	if err := store.db.Create(&[]webhookInboxRow{oldEvent, newEvent}).Error; err != nil {
		t.Fatal(err)
	}
	oldHistory := paymentHistoryRow{InvoiceRef: "old", FromState: PaymentReady, ToState: PaymentPaid, CreatedAt: now.AddDate(-7, 0, 0).Add(-time.Second)}
	newHistory := oldHistory
	newHistory.InvoiceRef = "new"
	newHistory.CreatedAt = now.AddDate(-7, 0, 0)
	if err := store.db.Create(&[]paymentHistoryRow{oldHistory, newHistory}).Error; err != nil {
		t.Fatal(err)
	}
	if err := store.PruneBillingHistory(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	var payments, events, history int64
	store.db.Model(&paymentOutboxRow{}).Count(&payments)
	store.db.Model(&webhookInboxRow{}).Count(&events)
	store.db.Model(&paymentHistoryRow{}).Count(&history)
	if payments != 1 || events != 1 || history != 1 {
		t.Fatalf("records at retention boundary: payments=%d events=%d history=%d, want 1 each", payments, events, history)
	}
}
