// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package billing

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/netbirdio/netbird/management/internals/karst/usage"
	"gorm.io/gorm"
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

func TestPaymentFailureNoticesPersistAndStayAccountScoped(t *testing.T) {
	store, ctx, start, end := finalizedTestInvoice(t)
	intent, err := store.QueuePayment(ctx, start, end)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetPaymentCustomer(ctx, intent.InvoiceReference, testPaddleCustomer); err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpdatePaymentState(ctx, intent.InvoiceReference, PaymentReady, PaymentSubmitting, "", ""); err != nil {
		t.Fatal(err)
	}
	eventAt := start.Add(2 * time.Hour)
	event := NormalizedPaddleEvent{EventID: "evt_payment_failed", EventType: "transaction.payment_failed", OccurredAt: eventAt, TransactionID: "txn_01grnn4zta5a1mf02jjze7y2ys", CustomerID: testPaddleCustomer, InvoiceRef: intent.InvoiceReference, Status: "past_due"}
	if _, err := store.RecordWebhook(ctx, event); err != nil {
		t.Fatal(err)
	}
	if err := store.ProcessPendingWebhooks(ctx, 100); err != nil {
		t.Fatal(err)
	}
	var retries []paymentAttemptRow
	if err := store.db.Where("invoice_ref = ? AND number > 0", intent.InvoiceReference).Order("number ASC").Find(&retries).Error; err != nil {
		t.Fatal(err)
	}
	if len(retries) != len(paymentRetryDays) {
		t.Fatalf("scheduled retry count=%d; want %d", len(retries), len(paymentRetryDays))
	}
	for index, days := range paymentRetryDays {
		want := eventAt.AddDate(0, 0, days)
		if retries[index].Number != index+1 || retries[index].State != paymentRetryQueued || !retries[index].ScheduledAt.Equal(want) {
			t.Fatalf("retry %d = %+v; want queued at %s", index+1, retries[index], want)
		}
	}
	notices, err := store.PaymentFailureNotices(ctx, start, end)
	if err != nil || len(notices) != 1 {
		t.Fatalf("payment notices=%+v err=%v; want one notice", notices, err)
	}
	if !notices[0].PeriodStart.Equal(start) || !notices[0].PeriodEnd.Equal(end) || notices[0].CreatedAt.IsZero() {
		t.Fatalf("unexpected failure notice: %+v", notices[0])
	}
	if _, err := store.ProcessWebhook(ctx, event.EventID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RecordWebhook(ctx, NormalizedPaddleEvent{EventID: "evt_payment_failed_again", EventType: "transaction.past_due", OccurredAt: eventAt.Add(time.Hour), TransactionID: event.TransactionID, CustomerID: event.CustomerID, InvoiceRef: event.InvoiceRef, Status: "past_due"}); err != nil {
		t.Fatal(err)
	}
	if err := store.ProcessPendingWebhooks(ctx, 100); err != nil {
		t.Fatal(err)
	}
	notices, err = store.PaymentFailureNotices(ctx, start, end)
	if err != nil || len(notices) != 2 {
		t.Fatalf("distinct past-due events notices=%+v err=%v; want one notice per failed payment event", notices, err)
	}
	if _, err := store.ProcessWebhook(ctx, "evt_payment_failed_again"); err != nil {
		t.Fatal(err)
	}
	notices, err = store.PaymentFailureNotices(ctx, start, end)
	if err != nil || len(notices) != 2 {
		t.Fatalf("duplicate event delivery notices=%+v err=%v; want no duplicate notice", notices, err)
	}
	otherAccount := WithAccount(context.Background(), "other-account")
	notices, err = store.PaymentFailureNotices(otherAccount, start, end)
	if err != nil || len(notices) != 0 {
		t.Fatalf("cross-account notices=%+v err=%v; want empty feed", notices, err)
	}
}

func TestScheduledPaymentRetryWithoutSavedMethodReturnsCheckoutAndStops(t *testing.T) {
	store, ctx, start, end := finalizedTestInvoice(t)
	intent, err := store.QueuePayment(ctx, start, end)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetPaymentCustomer(ctx, intent.InvoiceReference, testPaddleCustomer); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConfigurePaddleAccount(ctx, true, testPaddleCustomer, "pro_01gsz4t5hdjse848p5f9t9hf5h"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpdatePaymentState(ctx, intent.InvoiceReference, PaymentReady, PaymentSubmitting, "", ""); err != nil {
		t.Fatal(err)
	}
	eventAt := start.Add(2 * time.Hour)
	event := NormalizedPaddleEvent{EventID: "evt_retry_schedule", EventType: "transaction.past_due", OccurredAt: eventAt,
		TransactionID: "txn_01grnn4zta5a1mf02jjze7y2ys", CustomerID: testPaddleCustomer, InvoiceRef: intent.InvoiceReference, Status: "past_due"}
	if _, err := store.RecordWebhook(ctx, event); err != nil {
		t.Fatal(err)
	}
	if err := store.ProcessPendingWebhooks(ctx, 100); err != nil {
		t.Fatal(err)
	}
	var creates, methodLookups int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/customers/"+testPaddleCustomer+"/payment-methods":
			methodLookups++
			_, _ = w.Write([]byte(`{"data":[],"meta":{"pagination":{"has_more":false}}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/transactions":
			creates++
			var request PaddleTransactionRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Errorf("decode retry create: %v", err)
			}
			if request.CustomData.KarstInvoiceID != intent.InvoiceReference || request.CustomData.KarstAttemptNumber != 1 {
				t.Errorf("retry metadata = %+v", request.CustomData)
			}
			response, _ := json.Marshal(map[string]any{"data": map[string]any{
				"id": "txn_01grnn4zta5a1mf02jjze7y2yz", "status": "ready", "customer_id": testPaddleCustomer,
				"currency_code": "USD", "created_at": eventAt.AddDate(0, 0, 1).Format(time.RFC3339),
				"custom_data": request.CustomData, "checkout": map[string]string{"url": "https://pay.paddle.com/checkout/retry"},
			}})
			_, _ = w.Write(response)
		default:
			t.Errorf("unexpected Paddle retry request %s %s", r.Method, r.URL)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client, err := newPaddleClient("token", server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	due := eventAt.AddDate(0, 0, paymentRetryDays[0])
	if err := store.ProcessScheduledPaymentRetries(ctx, client, due.Add(-time.Microsecond), 10); err != nil {
		t.Fatal(err)
	}
	if creates != 0 || methodLookups != 0 {
		t.Fatalf("early retry made API calls: creates=%d method lookups=%d", creates, methodLookups)
	}
	if err := store.ProcessScheduledPaymentRetries(ctx, client, due, 10); err != nil {
		t.Fatal(err)
	}
	got, err := store.Payment(ctx, start, end)
	if err != nil || got.State != PaymentCheckout || got.CheckoutURL != "https://pay.paddle.com/checkout/retry" {
		t.Fatalf("retry result = %+v, %v", got, err)
	}
	if creates != 1 || methodLookups != 1 {
		t.Fatalf("retry API counts: creates=%d method lookups=%d; want 1 each", creates, methodLookups)
	}
	var attempts []paymentAttemptRow
	if err := store.db.Where("invoice_ref = ? AND number > 0", intent.InvoiceReference).Order("number ASC").Find(&attempts).Error; err != nil {
		t.Fatal(err)
	}
	if len(attempts) != len(paymentRetryDays) || attempts[0].State != PaymentCheckout {
		t.Fatalf("attempt states = %+v", attempts)
	}
	for _, attempt := range attempts[1:] {
		if attempt.State != paymentRetrySkipped {
			t.Fatalf("later attempt %d state=%s, want skipped", attempt.Number, attempt.State)
		}
	}
}

func TestPaddleAccountRequiresPerAccountOptInAndPreservesMappingOnDisable(t *testing.T) {
	store := testBillingStore(t)
	ctx := WithAccount(context.Background(), "paddle-config-org")
	if _, err := store.PaddleAccount(ctx); !errors.Is(err, ErrPaddleAccountNotConfigured) {
		t.Fatalf("missing config = %v", err)
	}
	disabled, err := store.ConfigurePaddleAccount(ctx, false, "", "")
	if err != nil || disabled.Enabled {
		t.Fatalf("default disabled config=%+v err=%v", disabled, err)
	}
	configured, err := store.ConfigurePaddleAccount(ctx, true, testPaddleCustomer, testPaddleProduct)
	if err != nil || !configured.Enabled {
		t.Fatalf("enable config=%+v err=%v", configured, err)
	}
	loaded, err := store.PaddleAccount(ctx)
	if err != nil || loaded.CustomerID != testPaddleCustomer || loaded.ProductID != testPaddleProduct {
		t.Fatalf("load config=%+v err=%v", loaded, err)
	}
	disabled, err = store.ConfigurePaddleAccount(ctx, false, "", "")
	if err != nil || disabled.Enabled || disabled.CustomerID != testPaddleCustomer {
		t.Fatalf("disable config=%+v err=%v", disabled, err)
	}
	if _, err := store.PaddleAccount(ctx); !errors.Is(err, ErrPaddleAccountNotConfigured) {
		t.Fatalf("disabled config lookup=%v", err)
	}
	if _, err := store.PaddleAccount(WithAccount(context.Background(), "another-org")); !errors.Is(err, ErrPaddleAccountNotConfigured) {
		t.Fatalf("cross-account config lookup=%v", err)
	}
}

func TestPaymentWorkerOnlySubmitsExplicitlyConfiguredAccount(t *testing.T) {
	store, ctx, start, end := finalizedTestInvoice(t)
	if _, err := store.QueuePayment(ctx, start, end); err != nil {
		t.Fatal(err)
	}
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		var body struct {
			CustomData PaddleTransactionCustomData `json:"custom_data"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"id":"txn_01grnn4zta5a1mf02jjze7y2ys","status":"ready","customer_id":"` + testPaddleCustomer + `","currency_code":"USD","created_at":"2026-09-01T03:00:00Z","custom_data":{"karst_invoice_id":"` + body.CustomData.KarstInvoiceID + `"},"checkout":{"url":"https://pay.paddle.com/checkout/abc"}}}`))
	}))
	defer server.Close()
	client, err := newPaddleClient("paddle-secret", server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ProcessReadyPayments(ctx, client, 10); err != nil {
		t.Fatal(err)
	}
	if requests != 0 {
		t.Fatalf("unconfigured account made %d provider requests", requests)
	}
	if _, err := store.ConfigurePaddleAccount(ctx, true, testPaddleCustomer, testPaddleProduct); err != nil {
		t.Fatal(err)
	}
	if err := store.ProcessReadyPayments(ctx, client, 10); err != nil {
		t.Fatal(err)
	}
	intent, err := store.Payment(ctx, start, end)
	if err != nil || requests != 1 || intent.State != PaymentCheckout {
		t.Fatalf("configured account: intent=%+v requests=%d err=%v", intent, requests, err)
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

func TestPruneBillingHistoryRequiresVerifiedExpiredInvoiceForDeviceEvents(t *testing.T) {
	store := testBillingStore(t)
	if err := usage.Migrate(store.db); err != nil {
		t.Fatal(err)
	}
	baseNow := time.Now().UTC()
	monthStart := func(monthsAgo int) time.Time {
		month := time.Date(baseNow.Year(), baseNow.Month(), 1, 0, 0, 0, 0, time.UTC)
		return month.AddDate(0, -monthsAgo, 0)
	}
	appendPair := func(account string, start time.Time) {
		t.Helper()
		for _, change := range []usage.Change{
			{ID: account + "-enroll", AccountID: account, GenerationID: account + "-generation", Kind: usage.Enrolled, At: start.Add(time.Hour)},
			{ID: account + "-revoke", AccountID: account, GenerationID: account + "-generation", Kind: usage.Revoked, At: start.Add(2 * time.Hour)},
		} {
			if err := store.db.Transaction(func(tx *gorm.DB) error { return usage.Append(tx, change) }); err != nil {
				t.Fatal(err)
			}
		}
	}
	finalize := func(account string, start time.Time) {
		t.Helper()
		end := start.AddDate(0, 1, 0)
		ctx := WithAccount(context.Background(), account)
		if err := store.PutSchedule(ctx, testSchedule()); err != nil {
			t.Fatal(err)
		}
		if err := store.AssignSchedule(ctx, start, end, testSchedule().Version); err != nil {
			t.Fatal(err)
		}
		if _, err := store.FinalizeInvoice(ctx,
			completeDeviceReport(start, end, deviceSegment(start, end, 1)),
			completeRelayReport(start, end, "0")); err != nil {
			t.Fatal(err)
		}
	}

	expiredStart := monthStart(15)
	appendPair("expired", expiredStart)
	finalize("expired", expiredStart)

	recentStart := monthStart(10)
	appendPair("recent", recentStart)
	finalize("recent", recentStart)

	unfinalizedStart := monthStart(15)
	appendPair("unfinalized", unfinalizedStart)

	if err := store.PruneBillingHistory(context.Background(), time.Now().UTC().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	for account, want := range map[string]int64{"expired": 0, "recent": 2, "unfinalized": 2} {
		var got int64
		if err := store.db.Table("karst_usage_device_events").Where("account_id = ?", account).Count(&got).Error; err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("%s raw event count=%d; want %d", account, got, want)
		}
	}
	var checkpoints int64
	if err := store.db.Table("karst_usage_device_checkpoints").Where("account_id = ?", "expired").Count(&checkpoints).Error; err != nil {
		t.Fatal(err)
	}
	if checkpoints != 1 {
		t.Fatalf("expired account checkpoints=%d; want 1", checkpoints)
	}
	start, end := expiredStart, expiredStart.AddDate(0, 1, 0)
	if _, err := store.Invoice(WithAccount(context.Background(), "expired"), start, end); err != nil {
		t.Fatalf("invoice evidence should remain readable for seven years: %v", err)
	}
}

func TestPruneBillingHistoryKeepsEventsWhenInvoiceEvidenceIsInvalid(t *testing.T) {
	store := testBillingStore(t)
	if err := usage.Migrate(store.db); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	month := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, -15, 0)
	end := month.AddDate(0, 1, 0)
	ctx := WithAccount(context.Background(), "tampered")
	if err := store.PutSchedule(ctx, testSchedule()); err != nil {
		t.Fatal(err)
	}
	if err := store.AssignSchedule(ctx, month, end, testSchedule().Version); err != nil {
		t.Fatal(err)
	}
	if _, err := store.FinalizeInvoice(ctx, completeDeviceReport(month, end, deviceSegment(month, end, 1)), completeRelayReport(month, end, "0")); err != nil {
		t.Fatal(err)
	}
	for _, change := range []usage.Change{
		{ID: "tampered-enroll", AccountID: "tampered", GenerationID: "generation", Kind: usage.Enrolled, At: month.Add(time.Hour)},
		{ID: "tampered-revoke", AccountID: "tampered", GenerationID: "generation", Kind: usage.Revoked, At: month.Add(2 * time.Hour)},
	} {
		if err := store.db.Transaction(func(tx *gorm.DB) error { return usage.Append(tx, change) }); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.db.Model(&invoiceRow{}).Where("account_id = ? AND period_start_us = ?", "tampered", month.UnixMicro()).Update("snapshot", []byte("corrupt")).Error; err != nil {
		t.Fatal(err)
	}
	if err := store.PruneBillingHistory(context.Background(), time.Now().UTC().Add(time.Second)); err == nil {
		t.Fatal("retention accepted an invalid finalized invoice")
	}
	var count int64
	if err := store.db.Table("karst_usage_device_events").Where("account_id = ?", "tampered").Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("invalid invoice allowed pruning: retained events=%d; want 2", count)
	}
}
