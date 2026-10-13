// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package billing

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestBuildPaddleTransactionRequestUsesTruncatedInvoiceLines(t *testing.T) {
	invoice := paddleTestInvoice()
	request, err := BuildPaddleTransactionRequest(invoice, "ctm_01grnn4zta5a1mf02jjze7y2ys", "pro_01gsz4t5hdjse848p5f9t9hf5h")
	if err != nil {
		t.Fatal(err)
	}
	if request.CollectionMode != "automatic" || request.CurrencyCode != "USD" {
		t.Fatalf("request collection settings = %+v", request)
	}
	if len(request.Items) != 2 || request.Items[0].Quantity != 1 || request.Items[0].Price.UnitPrice.Amount != "1234" || request.Items[1].Price.UnitPrice.Amount != "56" {
		t.Fatalf("transaction items = %+v", request.Items)
	}
	if request.Items[0].Price.BillingCycle != nil || request.Items[1].Price.BillingCycle != nil {
		t.Fatal("monthly usage items must be one-time prices")
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), invoice.AccountID) || request.CustomData.KarstInvoiceID == invoice.AccountID {
		t.Fatal("Paddle metadata must not expose the Karst account ID")
	}
	if !strings.HasPrefix(request.CustomData.KarstInvoiceID, "ki_") {
		t.Fatalf("invoice reference = %q", request.CustomData.KarstInvoiceID)
	}
	if got := paddleInvoiceReference(invoice); got != request.CustomData.KarstInvoiceID {
		t.Fatalf("invoice reference is not stable: %q != %q", got, request.CustomData.KarstInvoiceID)
	}
}

func TestBuildPaddleTransactionRequestOmitsZeroLines(t *testing.T) {
	invoice := paddleTestInvoice()
	invoice.DeviceMinor = 0
	invoice.RelayMinor = 56
	invoice.TotalMinor = 56
	request, err := BuildPaddleTransactionRequest(invoice, "ctm_01grnn4zta5a1mf02jjze7y2ys", "pro_01gsz4t5hdjse848p5f9t9hf5h")
	if err != nil {
		t.Fatal(err)
	}
	if len(request.Items) != 1 || request.Items[0].Price.Name != "Managed relay usage 2026-09" || request.Items[0].Price.UnitPrice.Amount != "56" {
		t.Fatalf("transaction items = %+v", request.Items)
	}
}

func TestBuildPaddleTransactionRequestRejectsInvalidInvoices(t *testing.T) {
	base := paddleTestInvoice()
	cases := []struct {
		name       string
		invoice    FinalInvoice
		customerID string
		productID  string
		want       error
	}{
		{name: "non USD", invoice: func() FinalInvoice { i := base; i.Currency = "EUR"; return i }(), customerID: "ctm_01grnn4zta5a1mf02jjze7y2ys", productID: "pro_01gsz4t5hdjse848p5f9t9hf5h", want: ErrInvalidPaddleInvoice},
		{name: "amount mismatch", invoice: func() FinalInvoice { i := base; i.TotalMinor++; return i }(), customerID: "ctm_01grnn4zta5a1mf02jjze7y2ys", productID: "pro_01gsz4t5hdjse848p5f9t9hf5h", want: ErrInvalidPaddleInvoice},
		{name: "zero total", invoice: func() FinalInvoice { i := base; i.DeviceMinor = 0; i.RelayMinor = 0; i.TotalMinor = 0; return i }(), customerID: "ctm_01grnn4zta5a1mf02jjze7y2ys", productID: "pro_01gsz4t5hdjse848p5f9t9hf5h", want: ErrNoPaddleCharge},
		{name: "invalid customer id", invoice: base, customerID: "ctm_invalid", productID: "pro_01gsz4t5hdjse848p5f9t9hf5h", want: ErrInvalidPaddleInvoice},
		{name: "invalid product id", invoice: base, customerID: "ctm_01grnn4zta5a1mf02jjze7y2ys", productID: "pro_invalid", want: ErrInvalidPaddleInvoice},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := BuildPaddleTransactionRequest(tc.invoice, tc.customerID, tc.productID)
			if !errors.Is(err, tc.want) {
				t.Fatalf("BuildPaddleTransactionRequest() error = %v, want %v", err, tc.want)
			}
		})
	}
}

func paddleTestInvoice() FinalInvoice {
	start := time.Date(2026, time.September, 1, 0, 0, 0, 0, time.UTC)
	return FinalInvoice{
		SchemaVersion: "invoice-inputs-v1", AccountID: "private-account-name",
		PeriodStart: start, PeriodEnd: start.AddDate(0, 1, 0), Currency: "USD",
		DeviceMinor: 1234, RelayMinor: 56, TotalMinor: 1290,
		FinalizedAt: time.Date(2026, time.October, 1, 0, 0, 0, 0, time.UTC),
	}
}
