// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package billing

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

const (
	testPaddleCustomer = "ctm_01grnn4zta5a1mf02jjze7y2ys"
	testPaddleProduct  = "pro_01grnn4zta5a1mf02jjze7y2ys"
)

func finalizedTestInvoice(t *testing.T) (*Store, context.Context, time.Time, time.Time) {
	t.Helper()
	store := testBillingStore(t)
	ctx := WithAccount(context.Background(), "paddle-submit-org")
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	end := start.AddDate(0, 1, 0)
	if err := store.PutSchedule(ctx, testSchedule()); err != nil {
		t.Fatal(err)
	}
	if err := store.AssignSchedule(ctx, start, end, testSchedule().Version); err != nil {
		t.Fatal(err)
	}
	if _, err := store.FinalizeInvoice(ctx, completeDeviceReport(start, end, deviceSegment(start, end, 2)), completeRelayReport(start, end, "0")); err != nil {
		t.Fatal(err)
	}
	return store, ctx, start, end
}

func TestSubmitFinalizedInvoicePersistsBeforeSingleProviderCreate(t *testing.T) {
	store, ctx, start, end := finalizedTestInvoice(t)
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"id":"txn_01grnn4zta5a1mf02jjze7y2ys","status":"ready","customer_id":"ctm_01grnn4zta5a1mf02jjze7y2ys","currency_code":"USD","created_at":"2026-09-01T03:00:00Z","custom_data":{"karst_invoice_id":"` + paddleInvoiceReference(mustInvoice(t, store, ctx, start, end)) + `"},"checkout":{"url":"https://pay.paddle.com/checkout/abc"}}}`))
	}))
	defer server.Close()
	client, err := newPaddleClient("paddle-secret", server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	intent, err := store.SubmitFinalizedInvoice(ctx, client, start, end, testPaddleCustomer, testPaddleProduct)
	if err != nil || intent.State != PaymentCheckout || intent.CheckoutURL != "https://pay.paddle.com/checkout/abc" || requests != 1 {
		t.Fatalf("submit = %+v err=%v requests=%d", intent, err, requests)
	}
	if intent.AttemptStartedAt.IsZero() {
		t.Fatal("attempt timestamp was not persisted")
	}
	if _, err := store.SubmitFinalizedInvoice(ctx, client, start, end, testPaddleCustomer, testPaddleProduct); !errors.Is(err, ErrPaymentRequiresReconciliation) || requests != 1 {
		t.Fatalf("second submit err=%v requests=%d; must not create again", err, requests)
	}
}

func TestSubmitAmbiguousProviderFailureMovesToReconciliation(t *testing.T) {
	store, ctx, start, end := finalizedTestInvoice(t)
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		http.Error(w, "gateway timeout", http.StatusBadGateway)
	}))
	defer server.Close()
	client, err := newPaddleClient("paddle-secret", server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	intent, err := store.SubmitFinalizedInvoice(ctx, client, start, end, testPaddleCustomer, testPaddleProduct)
	if !errors.Is(err, ErrPaymentRequiresReconciliation) || intent.State != PaymentReconcile || requests != 1 || intent.AttemptStartedAt.IsZero() {
		t.Fatalf("ambiguous submit = %+v err=%v requests=%d", intent, err, requests)
	}
	if _, err := store.SubmitFinalizedInvoice(ctx, client, start, end, testPaddleCustomer, testPaddleProduct); !errors.Is(err, ErrPaymentRequiresReconciliation) || requests != 1 {
		t.Fatalf("blind retry err=%v requests=%d", err, requests)
	}
}

func mustInvoice(t *testing.T, store *Store, ctx context.Context, start, end time.Time) FinalInvoice {
	t.Helper()
	invoice, err := store.Invoice(ctx, start, end)
	if err != nil {
		t.Fatal(err)
	}
	return invoice
}
