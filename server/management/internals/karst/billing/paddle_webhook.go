// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package billing

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"strings"
	"time"

	paddle "github.com/PaddleHQ/paddle-go-sdk/v5"
)

var (
	ErrPaddleWebhookNotConfigured = errors.New("billing: Paddle webhook verification is not configured")
	ErrPaddleWebhookInvalid       = errors.New("billing: Paddle webhook signature is invalid or stale")
)

const paddleWebhookTimestampTolerance = 5 * time.Minute
const paddleWebhookBodyLimit = 1 << 20

// PaddleWebhookVerifier delegates raw-body signature and timestamp validation
// to Paddle's official SDK. A webhook handler must call Verify before reading
// or decoding the request body, then persist an idempotent inbox row before
// acknowledging the event.
type PaddleWebhookVerifier struct {
	verifier *paddle.WebhookVerifier
}

func NewPaddleWebhookVerifier(secret string) (*PaddleWebhookVerifier, error) {
	if strings.TrimSpace(secret) == "" {
		return nil, ErrPaddleWebhookNotConfigured
	}
	return &PaddleWebhookVerifier{verifier: paddle.NewWebhookVerifier(secret,
		paddle.VerifierWithTimestampTolerance(paddleWebhookTimestampTolerance))}, nil
}

func (v *PaddleWebhookVerifier) Verify(request *http.Request) error {
	if v == nil || v.verifier == nil || request == nil {
		return ErrPaddleWebhookNotConfigured
	}
	valid, err := v.verifier.Verify(request)
	if err != nil || !valid {
		return ErrPaddleWebhookInvalid
	}
	return nil
}

type webhookInbox interface {
	RecordWebhook(context.Context, NormalizedPaddleEvent) (bool, error)
}

type paddleWebhookEnvelope struct {
	EventID    string    `json:"event_id"`
	EventType  string    `json:"event_type"`
	OccurredAt time.Time `json:"occurred_at"`
	Data       struct {
		ID         string         `json:"id"`
		Status     string         `json:"status"`
		CustomerID string         `json:"customer_id"`
		CustomData map[string]any `json:"custom_data"`
	} `json:"data"`
}

// NewPaddleWebhookHandler exposes a signature-verified, size-bounded endpoint
// that stores only normalized event fields. An identical redelivery receives
// success; events are applied asynchronously by the payment processor.
func NewPaddleWebhookHandler(verifier *PaddleWebhookVerifier, inbox webhookInbox) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if verifier == nil || inbox == nil {
			http.Error(w, "webhook receiver is not configured", http.StatusServiceUnavailable)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, paddleWebhookBodyLimit)
		if err := verifier.Verify(r); err != nil {
			http.Error(w, "invalid webhook signature", http.StatusBadRequest)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, paddleWebhookBodyLimit+1))
		if err != nil || len(body) > paddleWebhookBodyLimit {
			http.Error(w, "invalid webhook body", http.StatusRequestEntityTooLarge)
			return
		}
		var envelope paddleWebhookEnvelope
		decoder := json.NewDecoder(strings.NewReader(string(body)))
		if err := decoder.Decode(&envelope); err != nil {
			http.Error(w, "invalid webhook event", http.StatusBadRequest)
			return
		}
		if err := decoder.Decode(new(any)); err != io.EOF {
			http.Error(w, "invalid webhook event", http.StatusBadRequest)
			return
		}
		invoiceRef, _ := envelope.Data.CustomData["karst_invoice_id"].(string)
		attemptNumber := 0
		if value, ok := envelope.Data.CustomData["karst_attempt_number"]; ok {
			n, valid := value.(float64)
			if !valid || n < 0 || n > float64(len(paymentRetryDays)) || math.Trunc(n) != n {
				http.Error(w, "invalid webhook event", http.StatusBadRequest)
				return
			}
			attemptNumber = int(n)
		}
		event := NormalizedPaddleEvent{EventID: envelope.EventID, EventType: envelope.EventType,
			OccurredAt: envelope.OccurredAt, TransactionID: envelope.Data.ID,
			CustomerID: envelope.Data.CustomerID, InvoiceRef: invoiceRef, AttemptNumber: attemptNumber, Status: envelope.Data.Status}
		if _, err := inbox.RecordWebhook(r.Context(), event); err != nil {
			http.Error(w, "could not persist webhook event", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	})
}
