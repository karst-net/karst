// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package billing

import (
	"errors"
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
