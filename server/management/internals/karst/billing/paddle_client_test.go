// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package billing

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestNewPaddleClientIsOptIn(t *testing.T) {
	client, err := NewPaddleClient(false, false, "", nil)
	if err != nil || client != nil {
		t.Fatalf("disabled client = %v, %v; want nil, nil", client, err)
	}
	if _, err := NewPaddleClient(true, false, "", nil); !errors.Is(err, ErrPaddleAPIUnavailable) {
		t.Fatalf("enabled client without token error = %v", err)
	}
	client, err = NewPaddleClient(true, true, "sandbox-token", nil)
	if err != nil || client.baseURL != paddleSandboxAPI {
		t.Fatalf("sandbox client = %v, %v", client, err)
	}
}

func TestPaddleCreateTransactionMakesOneRequestAndValidatesResponse(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != http.MethodPost || r.URL.Path != "/transactions" {
			t.Errorf("request = %s %s", r.Method, r.URL)
		}
		if r.Header.Get("Authorization") != "Bearer paddle-secret" || !strings.HasPrefix(r.Header.Get("User-Agent"), "PaddleSDK/go ") {
			t.Errorf("request headers missing required credentials/version: %v", r.Header)
		}
		var request PaddleTransactionRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode create request: %v", err)
		}
		if request.CustomData.KarstInvoiceID != "ki_stable" {
			t.Errorf("custom_data = %+v", request.CustomData)
		}
		if len(request.Items) != 1 || request.Items[0].Price.UnitPrice.Amount != "1234" || request.Items[0].Price.BillingCycle != nil {
			t.Errorf("transaction items = %+v", request.Items)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"id":"txn_01grnn4zta5a1mf02jjze7y2ys","status":"ready","customer_id":"ctm_01grnn4zta5a1mf02jjze7y2ys","currency_code":"USD","created_at":"2026-09-01T03:00:00Z","custom_data":{"karst_invoice_id":"ki_stable"},"checkout":{"url":"https://pay.paddle.com/checkout/abc"}}}`))
	}))
	defer server.Close()
	client, err := newPaddleClient("paddle-secret", server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	request := PaddleTransactionRequest{
		CustomerID: "ctm_01grnn4zta5a1mf02jjze7y2ys", CollectionMode: "automatic", CurrencyCode: "USD",
		Items: []PaddleTransactionItem{{Quantity: 1, Price: PaddlePrice{
			ProductID: "pro_01gsz4t5hdjse848p5f9t9hf5h", Description: "test item", Name: "Managed usage",
			UnitPrice: PaddleUnitPrice{Amount: "1234", CurrencyCode: "USD"},
		}}},
		CustomData: PaddleTransactionCustomData{KarstInvoiceID: "ki_stable"},
	}
	transaction, err := client.CreateTransaction(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if requests != 1 || transaction.ID != "txn_01grnn4zta5a1mf02jjze7y2ys" || transaction.Checkout.URL != "https://pay.paddle.com/checkout/abc" {
		t.Fatalf("requests=%d transaction=%+v", requests, transaction)
	}
}

func TestPaddleCreateTransactionRejectsMismatchedProviderResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"id":"txn_01grnn4zta5a1mf02jjze7y2ys","status":"ready","customer_id":"ctm_01grnn4zta5a1mf02jjze7y2ys","currency_code":"USD","created_at":"2026-09-01T03:00:00Z","custom_data":{"karst_invoice_id":"another-invoice"},"checkout":{"url":"https://pay.paddle.com/checkout/abc"}}}`))
	}))
	defer server.Close()
	client, err := newPaddleClient("token", server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.CreateTransaction(context.Background(), PaddleTransactionRequest{
		CustomerID: "ctm_01grnn4zta5a1mf02jjze7y2ys", CollectionMode: "automatic", CurrencyCode: "USD",
		Items: []PaddleTransactionItem{{Quantity: 1, Price: PaddlePrice{
			ProductID: "pro_01gsz4t5hdjse848p5f9t9hf5h", Description: "test item", Name: "Managed usage",
			UnitPrice: PaddleUnitPrice{Amount: "1234", CurrencyCode: "USD"},
		}}},
		CustomData: PaddleTransactionCustomData{KarstInvoiceID: "ki_stable"},
	})
	if !errors.Is(err, ErrPaddleResponseInvalid) {
		t.Fatalf("mismatched response error = %v", err)
	}
}

func TestPaddleCreateTransactionDoesNotRetryAmbiguousServerFailure(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		http.Error(w, `{"error":{"code":"temporary_error"}}`, http.StatusBadGateway)
	}))
	defer server.Close()
	client, err := newPaddleClient("token", server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	request := PaddleTransactionRequest{
		CustomerID: "ctm_01grnn4zta5a1mf02jjze7y2ys", CollectionMode: "automatic", CurrencyCode: "USD",
		Items: []PaddleTransactionItem{{Quantity: 1, Price: PaddlePrice{
			ProductID: "pro_01gsz4t5hdjse848p5f9t9hf5h", Description: "test item", Name: "Managed usage",
			UnitPrice: PaddleUnitPrice{Amount: "1234", CurrencyCode: "USD"},
		}}},
		CustomData: PaddleTransactionCustomData{KarstInvoiceID: "ki_stable"},
	}
	if _, err := client.CreateTransaction(context.Background(), request); err == nil {
		t.Fatal("server failure unexpectedly succeeded")
	}
	if requests != 1 {
		t.Fatalf("ambiguous create sent %d requests, want exactly one", requests)
	}
}

func TestPaddleFindTransactionsBoundsAndMatchesLocally(t *testing.T) {
	start := time.Date(2026, time.September, 1, 0, 0, 0, 0, time.UTC)
	var query url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query = r.URL.Query()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"id":"txn_01grnn4zta5a1mf02jjze7y2ys","status":"ready","customer_id":"ctm_01grnn4zta5a1mf02jjze7y2ys","created_at":"2026-09-01T03:00:00Z","custom_data":{"karst_invoice_id":"ki_stable"}},{"id":"txn_01grnn4zta5a1mf02jjze7y2ys","status":"ready","customer_id":"ctm_01grnn4zta5a1mf02jjze7y2ys","custom_data":{"karst_invoice_id":"ki_other"}}],"meta":{"pagination":{"has_more":false}}}`))
	}))
	defer server.Close()
	client := &PaddleClient{baseURL: server.URL, apiKey: "token", httpClient: server.Client()}
	matches, err := client.FindTransactionsByInvoice(context.Background(), "ctm_01grnn4zta5a1mf02jjze7y2ys", "ki_stable", start, start.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 || matches[0].CustomData.KarstInvoiceID != "ki_stable" {
		t.Fatalf("matches = %+v", matches)
	}
	if query.Get("customer_id") != "ctm_01grnn4zta5a1mf02jjze7y2ys" || query.Get("per_page") != "30" ||
		!strings.Contains(query.Get("created_at[GTE]"), "2026-09-01") || query.Get("created_at[LTE]") == "" {
		t.Fatalf("lookup query = %v", query)
	}
}

func TestPaddleFindTransactionsFailsClosedWhenResultsAreTruncated(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":[],"meta":{"pagination":{"has_more":true}}}`))
	}))
	defer server.Close()
	client := &PaddleClient{baseURL: server.URL, apiKey: "token", httpClient: server.Client()}
	start := time.Date(2026, time.September, 1, 0, 0, 0, 0, time.UTC)
	_, err := client.FindTransactionsByInvoice(context.Background(), "ctm_01grnn4zta5a1mf02jjze7y2ys", "ki_stable", start, start.Add(time.Hour))
	if !errors.Is(err, ErrPaddleLookupIncomplete) {
		t.Fatalf("truncated lookup error = %v", err)
	}
}

func TestPaddleSavedPaymentMethodLookupIsBoundedAndConsentAware(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != http.MethodGet || r.URL.Path != "/customers/ctm_01grnn4zta5a1mf02jjze7y2yz/payment-methods" || r.URL.Query().Get("per_page") != "30" {
			t.Errorf("saved-method request = %s %s", r.Method, r.URL)
		}
		_, _ = w.Write([]byte(`{"data":[{"id":"paymtd_01grnn4zta5a1mf02jjze7y2yz"}],"meta":{"pagination":{"has_more":false}}}`))
	}))
	defer server.Close()
	client := &PaddleClient{baseURL: server.URL, apiKey: "token", httpClient: server.Client()}
	hasMethod, err := client.HasSavedPaymentMethod(context.Background(), "ctm_01grnn4zta5a1mf02jjze7y2yz")
	if err != nil || !hasMethod || requests != 1 {
		t.Fatalf("saved-method lookup = %v, %v, requests=%d", hasMethod, err, requests)
	}
}
