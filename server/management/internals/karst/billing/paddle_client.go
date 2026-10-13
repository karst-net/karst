// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package billing

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	paddle "github.com/PaddleHQ/paddle-go-sdk/v5"
)

var (
	ErrPaddleAPIUnavailable   = errors.New("billing: Paddle API is not configured")
	ErrPaddleResponseInvalid  = errors.New("billing: Paddle returned an invalid response")
	ErrPaddleLookupIncomplete = errors.New("billing: Paddle transaction lookup was incomplete")
)

const (
	paddleProductionAPI = "https://api.paddle.com"
	paddleSandboxAPI    = "https://sandbox-api.paddle.com"
	paddleResponseLimit = 1 << 20
	paddleLookupWindow  = 7 * 24 * time.Hour
	paddlePageLimit     = 10
)

// PaddleClient makes single-attempt calls to Paddle Billing. It intentionally
// does not retry transaction creates: callers must persist their outbox first
// and reconcile any ambiguous result by the stable Karst invoice reference.
type PaddleClient struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
	sdk        *paddle.SDK
}

// NewPaddleClient returns nil when collection is not enabled. This lets the
// default-off deployment path avoid constructing a provider client or making
// external requests. An enabled client requires a server-side API key.
func NewPaddleClient(enabled, sandbox bool, apiKey string, httpClient *http.Client) (*PaddleClient, error) {
	if !enabled {
		return nil, nil
	}
	if strings.TrimSpace(apiKey) == "" {
		return nil, ErrPaddleAPIUnavailable
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	baseURL := paddleProductionAPI
	if sandbox {
		baseURL = paddleSandboxAPI
	}
	return newPaddleClient(apiKey, baseURL, httpClient)
}

func newPaddleClient(apiKey, baseURL string, httpClient *http.Client) (*PaddleClient, error) {
	if strings.TrimSpace(apiKey) == "" || httpClient == nil {
		return nil, ErrPaddleAPIUnavailable
	}
	options := []paddle.Option{paddle.WithBaseURL(baseURL), paddle.WithClient(httpClient)}
	sdk, err := paddle.New(apiKey, options...)
	if err != nil {
		return nil, fmt.Errorf("billing: configure Paddle SDK: %w", err)
	}
	return &PaddleClient{baseURL: baseURL, apiKey: apiKey, httpClient: httpClient, sdk: sdk}, nil
}

// CreateTransaction makes exactly one transaction-create request.
func (c *PaddleClient) CreateTransaction(ctx context.Context, request PaddleTransactionRequest) (PaddleTransaction, error) {
	if c == nil || c.httpClient == nil || c.apiKey == "" || c.sdk == nil {
		return PaddleTransaction{}, ErrPaddleAPIUnavailable
	}
	if err := validatePaddleTransactionRequest(request); err != nil {
		return PaddleTransaction{}, err
	}
	items := make([]paddle.CreateTransactionItems, 0, len(request.Items))
	for _, item := range request.Items {
		name := item.Price.Name
		price := paddle.TransactionPriceCreateWithProductID{
			ProductID: item.Price.ProductID, Description: item.Price.Description, Name: &name,
			UnitPrice: paddle.Money{Amount: item.Price.UnitPrice.Amount, CurrencyCode: paddle.CurrencyCodeUSD},
			// Each invoice line is one whole, non-recurring charge.
			Quantity: paddle.PriceQuantity{Minimum: 1, Maximum: 1},
		}
		items = append(items, *paddle.NewCreateTransactionItemsTransactionItemCreateWithPrice(
			&paddle.TransactionItemCreateWithPrice{Quantity: item.Quantity, Price: price}))
	}
	customerID := request.CustomerID
	currencyCode := paddle.CurrencyCodeUSD
	collectionMode := paddle.CollectionModeAutomatic
	transaction, err := c.sdk.CreateTransaction(ctx, &paddle.CreateTransactionRequest{
		CustomerID: &customerID, CurrencyCode: &currencyCode, CollectionMode: &collectionMode,
		Items: items, CustomData: paddle.CustomData{
			"karst_invoice_id":     request.CustomData.KarstInvoiceID,
			"karst_attempt_number": request.CustomData.KarstAttemptNumber,
		},
	})
	if err != nil {
		return PaddleTransaction{}, fmt.Errorf("billing: create Paddle transaction: %w", err)
	}
	invoiceRef, _ := transaction.CustomData["karst_invoice_id"].(string)
	if !validPaddleID(transaction.ID, "txn_") || transaction.CustomerID == nil || *transaction.CustomerID != request.CustomerID ||
		invoiceRef != request.CustomData.KarstInvoiceID || transaction.CurrencyCode != paddle.CurrencyCodeUSD || transaction.Status == "" {
		return PaddleTransaction{}, ErrPaddleResponseInvalid
	}
	if transaction.Checkout == nil || transaction.Checkout.URL == nil {
		return PaddleTransaction{}, ErrPaddleResponseInvalid
	}
	checkoutURL, err := url.Parse(*transaction.Checkout.URL)
	if err != nil || checkoutURL.Scheme != "https" || checkoutURL.Host == "" || checkoutURL.User != nil {
		return PaddleTransaction{}, ErrPaddleResponseInvalid
	}
	createdAt, err := time.Parse(time.RFC3339Nano, transaction.CreatedAt)
	if err != nil {
		return PaddleTransaction{}, ErrPaddleResponseInvalid
	}
	return PaddleTransaction{
		ID: transaction.ID, Status: string(transaction.Status), CustomerID: *transaction.CustomerID,
		CurrencyCode: string(transaction.CurrencyCode), CustomData: request.CustomData,
		Checkout: struct {
			URL string `json:"url"`
		}{URL: *transaction.Checkout.URL}, CreatedAt: createdAt,
	}, nil
}

func validatePaddleTransactionRequest(request PaddleTransactionRequest) error {
	if !validPaddleID(request.CustomerID, "ctm_") || request.CollectionMode != "automatic" ||
		request.CurrencyCode != "USD" || len(request.Items) == 0 || len(request.Items) > 100 ||
		!strings.HasPrefix(request.CustomData.KarstInvoiceID, "ki_") ||
		request.CustomData.KarstAttemptNumber < 0 || request.CustomData.KarstAttemptNumber > len(paymentRetryDays) {
		return ErrInvalidPaddleInvoice
	}
	for _, item := range request.Items {
		amount, err := strconv.ParseInt(item.Price.UnitPrice.Amount, 10, 64)
		if item.Quantity != 1 || amount <= 0 || err != nil || !validPaddleID(item.Price.ProductID, "pro_") ||
			item.Price.UnitPrice.CurrencyCode != "USD" || item.Price.Name == "" || item.Price.Description == "" {
			return ErrInvalidPaddleInvoice
		}
	}
	return nil
}

// FindTransactionsByInvoice lists a bounded creation window for a Paddle
// customer, then compares custom_data locally. It never filters on untrusted
// Karst metadata at the provider and fails closed if Paddle reports more rows
// than were returned.
func (c *PaddleClient) FindTransactionsByInvoice(ctx context.Context, customerID, invoiceReference string, createdAfter, createdBefore time.Time) ([]PaddleTransaction, error) {
	return c.FindTransactionsByAttempt(ctx, customerID, invoiceReference, 0, createdAfter, createdBefore)
}

// FindTransactionsByAttempt reconciles one possibly ambiguous create. Karst
// metadata is compared locally after listing a bounded set for the provider
// customer; no new transaction is created by this lookup.
func (c *PaddleClient) FindTransactionsByAttempt(ctx context.Context, customerID, invoiceReference string, attemptNumber int, createdAfter, createdBefore time.Time) ([]PaddleTransaction, error) {
	if c == nil || c.httpClient == nil || c.apiKey == "" {
		return nil, ErrPaddleAPIUnavailable
	}
	if !validPaddleID(customerID, "ctm_") || !strings.HasPrefix(invoiceReference, "ki_") ||
		attemptNumber < 0 || attemptNumber > len(paymentRetryDays) ||
		!createdAfter.Before(createdBefore) || createdAfter.IsZero() || createdBefore.IsZero() ||
		createdBefore.Sub(createdAfter) > paddleLookupWindow {
		return nil, ErrInvalidPaddleInvoice
	}
	query := url.Values{}
	query.Set("customer_id", customerID)
	query.Set("created_at[GTE]", createdAfter.UTC().Format(time.RFC3339Nano))
	query.Set("created_at[LTE]", createdBefore.UTC().Format(time.RFC3339Nano))
	query.Set("per_page", "30")
	path := "/transactions?" + query.Encode()
	var envelope paddleTransactionListEnvelope
	if err := c.doJSON(ctx, http.MethodGet, path, nil, &envelope); err != nil {
		return nil, err
	}
	if envelope.Meta.Pagination.HasMore {
		return nil, ErrPaddleLookupIncomplete
	}
	matches := make([]PaddleTransaction, 0, 1)
	for _, transaction := range envelope.Data {
		if transaction.CustomerID == customerID && transaction.CustomData.KarstInvoiceID == invoiceReference && transaction.CustomData.KarstAttemptNumber == attemptNumber {
			if !validPaddleID(transaction.ID, "txn_") {
				return nil, ErrPaddleResponseInvalid
			}
			if transaction.CreatedAt.IsZero() || transaction.CreatedAt.Before(createdAfter) || transaction.CreatedAt.After(createdBefore) {
				return nil, ErrPaddleResponseInvalid
			}
			matches = append(matches, transaction)
		}
	}
	return matches, nil
}

// HasSavedPaymentMethod checks Paddle's authoritative saved-payment-method
// list. Paddle only creates these records after the customer has explicitly
// opted in through Checkout, so Karst never stores card data or an independent
// consent flag. A transient/incomplete lookup fails closed and does not create
// an automatic-collection transaction.
func (c *PaddleClient) HasSavedPaymentMethod(ctx context.Context, customerID string) (bool, error) {
	if c == nil || c.httpClient == nil || c.apiKey == "" {
		return false, ErrPaddleAPIUnavailable
	}
	if !validPaddleID(customerID, "ctm_") {
		return false, ErrInvalidPaddleInvoice
	}
	var after string
	for page := 0; page < paddlePageLimit; page++ {
		query := url.Values{}
		query.Set("per_page", "30")
		if after != "" {
			query.Set("after", after)
		}
		path := "/customers/" + url.PathEscape(customerID) + "/payment-methods?" + query.Encode()
		var envelope paddlePaymentMethodListEnvelope
		if err := c.doJSON(ctx, http.MethodGet, path, nil, &envelope); err != nil {
			return false, err
		}
		for _, method := range envelope.Data {
			if !validPaddleID(method.ID, "paymtd_") {
				return false, ErrPaddleResponseInvalid
			}
			return true, nil
		}
		if !envelope.Meta.Pagination.HasMore {
			return false, nil
		}
		if len(envelope.Data) == 0 || envelope.Data[len(envelope.Data)-1].ID == "" {
			return false, ErrPaddleLookupIncomplete
		}
		after = envelope.Data[len(envelope.Data)-1].ID
	}
	return false, ErrPaddleLookupIncomplete
}

// PaddleTransaction is the minimal provider state Karst needs to reconcile
// an invoice and present checkout. Keep raw provider payloads out of storage.
type PaddleTransaction struct {
	ID           string                      `json:"id"`
	Status       string                      `json:"status"`
	CustomerID   string                      `json:"customer_id"`
	CurrencyCode string                      `json:"currency_code"`
	CustomData   PaddleTransactionCustomData `json:"custom_data"`
	Checkout     struct {
		URL string `json:"url"`
	} `json:"checkout"`
	CreatedAt time.Time `json:"created_at"`
}

type paddleTransactionListEnvelope struct {
	Data []PaddleTransaction `json:"data"`
	Meta struct {
		Pagination struct {
			HasMore bool `json:"has_more"`
		} `json:"pagination"`
	} `json:"meta"`
}

type paddlePaymentMethodListEnvelope struct {
	Data []struct {
		ID string `json:"id"`
	} `json:"data"`
	Meta struct {
		Pagination struct {
			HasMore bool `json:"has_more"`
		} `json:"pagination"`
	} `json:"meta"`
}

func (c *PaddleClient) doJSON(ctx context.Context, method, path string, body any, result any) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("billing: encode Paddle request: %w", err)
		}
		reader = strings.NewReader(string(encoded))
	}
	request, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return fmt.Errorf("billing: create Paddle request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+c.apiKey)
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := c.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("billing: Paddle request failed: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("billing: Paddle returned HTTP %s", strconv.Itoa(response.StatusCode))
	}
	encoded, err := io.ReadAll(io.LimitReader(response.Body, paddleResponseLimit+1))
	if err != nil {
		return fmt.Errorf("billing: read Paddle response: %w", err)
	}
	if len(encoded) > paddleResponseLimit {
		return ErrPaddleResponseInvalid
	}
	if err := json.Unmarshal(encoded, result); err != nil {
		return fmt.Errorf("billing: decode Paddle response: %w", err)
	}
	return nil
}
