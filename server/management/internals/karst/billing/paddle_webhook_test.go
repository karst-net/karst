// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package billing

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func TestPaddleWebhookVerifierChecksFreshSignatureOverRawBody(t *testing.T) {
	const secret = "pdl_ntfset_test_secret"
	body := []byte("{\"event_id\":\"evt_01grnn4zta5a1mf02jjze7y2ys\"}\n")
	request := paddleSignedRequest(t, secret, time.Now(), body)
	verifier, err := NewPaddleWebhookVerifier(secret)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.Verify(request); err != nil {
		t.Fatal(err)
	}
	restored, err := io.ReadAll(request.Body)
	if err != nil || !bytes.Equal(restored, body) {
		t.Fatalf("verified request body was not restored: %q, %v", restored, err)
	}
}

func TestPaddleWebhookVerifierRejectsWrongBodyAndStaleTimestamp(t *testing.T) {
	const secret = "pdl_ntfset_test_secret"
	verifier, err := NewPaddleWebhookVerifier(secret)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("changed raw body", func(t *testing.T) {
		request := paddleSignedRequest(t, secret, time.Now(), []byte("{}"))
		request.Body = io.NopCloser(bytes.NewBufferString("{ }"))
		if err := verifier.Verify(request); !errors.Is(err, ErrPaddleWebhookInvalid) {
			t.Fatalf("changed body error = %v", err)
		}
	})
	t.Run("stale timestamp", func(t *testing.T) {
		request := paddleSignedRequest(t, secret, time.Now().Add(-10*time.Minute), []byte("{}"))
		if err := verifier.Verify(request); !errors.Is(err, ErrPaddleWebhookInvalid) {
			t.Fatalf("stale signature error = %v", err)
		}
	})
}

func TestPaddleWebhookVerifierRequiresSecret(t *testing.T) {
	if _, err := NewPaddleWebhookVerifier(" \t"); !errors.Is(err, ErrPaddleWebhookNotConfigured) {
		t.Fatalf("empty secret error = %v", err)
	}
	var verifier *PaddleWebhookVerifier
	if err := verifier.Verify(httptest.NewRequest("POST", "/", nil)); !errors.Is(err, ErrPaddleWebhookNotConfigured) {
		t.Fatalf("nil verifier error = %v", err)
	}
}

func paddleSignedRequest(t *testing.T, secret string, timestamp time.Time, body []byte) *http.Request {
	t.Helper()
	timestampText := strconv.FormatInt(timestamp.Unix(), 10)
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(timestampText + ":"))
	_, _ = mac.Write(body)
	request := httptest.NewRequest("POST", "/webhooks/paddle", bytes.NewReader(body))
	request.Header.Set("Paddle-Signature", "ts="+timestampText+";h1="+hex.EncodeToString(mac.Sum(nil)))
	return request
}
