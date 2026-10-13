// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package billing

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
)

var (
	ErrInvalidPaddleInvoice = errors.New("billing: finalized invoice cannot be represented as a Paddle transaction")
	ErrNoPaddleCharge       = errors.New("billing: finalized invoice has no chargeable amount")
)

// PaddleTransactionRequest is the automatic-collection request for one
// finalized Karst invoice. It contains no customer-identifying data beyond the
// Paddle customer ID and uses one-time, non-catalog prices attached to the
// approved Paddle product.
type PaddleTransactionRequest struct {
	CustomerID     string                      `json:"customer_id"`
	CollectionMode string                      `json:"collection_mode"`
	CurrencyCode   string                      `json:"currency_code"`
	Items          []PaddleTransactionItem     `json:"items"`
	CustomData     PaddleTransactionCustomData `json:"custom_data"`
}

type PaddleTransactionItem struct {
	Quantity int         `json:"quantity"`
	Price    PaddlePrice `json:"price"`
}

type PaddlePrice struct {
	ProductID    string              `json:"product_id"`
	Description  string              `json:"description"`
	Name         string              `json:"name"`
	UnitPrice    PaddleUnitPrice     `json:"unit_price"`
	BillingCycle *PaddleBillingCycle `json:"billing_cycle"`
}

type PaddleUnitPrice struct {
	Amount       string `json:"amount"`
	CurrencyCode string `json:"currency_code"`
}

// A nil billing cycle explicitly represents a one-time price.
type PaddleBillingCycle struct {
	Interval  string `json:"interval"`
	Frequency int    `json:"frequency"`
}

type PaddleTransactionCustomData struct {
	KarstInvoiceID     string `json:"karst_invoice_id"`
	KarstAttemptNumber int    `json:"karst_attempt_number,omitempty"`
}

// BuildPaddleTransactionRequest maps a verified finalized invoice to one
// Paddle transaction with independently truncated device and relay lines.
// Tax is left to Paddle's approved catalog product and account configuration.
// The function has no side effects; callers must persist an outbox record
// before sending this request and reconcile ambiguous creates by KarstInvoiceID.
func BuildPaddleTransactionRequest(invoice FinalInvoice, customerID, productID string) (PaddleTransactionRequest, error) {
	return BuildPaddleAttemptRequest(invoice, customerID, productID, 0)
}

// BuildPaddleAttemptRequest maps a finalized invoice and one durable attempt
// number to a one-time Paddle transaction. Attempt zero is the customer-
// initiated initial collection; retries use numbers 1 through 4. The stable
// invoice reference is preserved separately so webhook reconciliation can
// identify both the invoice and exact attempt.
func BuildPaddleAttemptRequest(invoice FinalInvoice, customerID, productID string, attemptNumber int) (PaddleTransactionRequest, error) {
	if !validPaddleID(customerID, "ctm_") || !validPaddleID(productID, "pro_") ||
		attemptNumber < 0 || attemptNumber > len(paymentRetryDays) ||
		invoice.AccountID == "" || invoice.SchemaVersion != "invoice-inputs-v1" ||
		invoice.Currency != "USD" || invoice.FinalizedAt.IsZero() ||
		!isUTCCalendarMonth(invoice.PeriodStart.UnixMicro(), invoice.PeriodEnd.UnixMicro()) ||
		invoice.PeriodStart.Nanosecond()%1000 != 0 || invoice.PeriodEnd.Nanosecond()%1000 != 0 ||
		invoice.DeviceMinor < 0 || invoice.RelayMinor < 0 || invoice.TotalMinor < 0 ||
		invoice.DeviceMinor > int64(^uint64(0)>>1)-invoice.RelayMinor ||
		invoice.DeviceMinor+invoice.RelayMinor != invoice.TotalMinor {
		return PaddleTransactionRequest{}, ErrInvalidPaddleInvoice
	}
	if invoice.TotalMinor == 0 {
		return PaddleTransactionRequest{}, ErrNoPaddleCharge
	}
	period := invoice.PeriodStart.UTC().Format("2006-01")
	items := make([]PaddleTransactionItem, 0, 2)
	if invoice.DeviceMinor > 0 {
		items = append(items, paddleItem(productID, "Managed device usage "+period, "Karst managed device usage for "+period, invoice.DeviceMinor))
	}
	if invoice.RelayMinor > 0 {
		items = append(items, paddleItem(productID, "Managed relay usage "+period, "Karst managed relay usage for "+period, invoice.RelayMinor))
	}
	return PaddleTransactionRequest{
		CustomerID: customerID, CollectionMode: "automatic", CurrencyCode: "USD",
		Items:      items,
		CustomData: PaddleTransactionCustomData{KarstInvoiceID: paddleInvoiceReference(invoice), KarstAttemptNumber: attemptNumber},
	}, nil
}

func paddleItem(productID, name, description string, amount int64) PaddleTransactionItem {
	return PaddleTransactionItem{Quantity: 1, Price: PaddlePrice{
		ProductID: productID, Description: description, Name: name,
		UnitPrice:    PaddleUnitPrice{Amount: strconv.FormatInt(amount, 10), CurrencyCode: "USD"},
		BillingCycle: nil,
	}}
}

func validPaddleID(value, prefix string) bool {
	if len(value) != len(prefix)+26 || value[:len(prefix)] != prefix {
		return false
	}
	for _, char := range value[len(prefix):] {
		if !(char >= 'a' && char <= 'z') && !(char >= '0' && char <= '9') {
			return false
		}
	}
	return true
}

func paddleInvoiceReference(invoice FinalInvoice) string {
	input := fmt.Sprintf("karst-invoice-v1\x00%s\x00%d\x00%d", invoice.AccountID, invoice.PeriodStart.UnixMicro(), invoice.PeriodEnd.UnixMicro())
	digest := sha256.Sum256([]byte(input))
	return "ki_" + hex.EncodeToString(digest[:])
}
