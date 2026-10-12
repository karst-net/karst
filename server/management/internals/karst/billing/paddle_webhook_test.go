// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package billing

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func TestPaddleWebhookHandlerPersistsOnlyVerifiedNormalizedEvent(t *testing.T) {
	const secret = "pdl_ntfset_test_secret"
	store := testBillingStore(t)
	verifier, err := NewPaddleWebhookVerifier(secret)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewPaddleWebhookHandler(verifier, store)
	body := []byte(`{"event_id":"evt_01grnn4zta5a1mf02jjze7y2ys","event_type":"transaction.completed","occurred_at":"2026-01-02T03:04:05Z","data":{"id":"txn_01grnn4zta5a1mf02jjze7y2ys","status":"completed","customer_id":"ctm_01grnn4zta5a1mf02jjze7y2ys","custom_data":{"karst_invoice_id":"ki_safe"},"private_note":"must not persist"}}`)
	request := paddleSignedRequest(t, secret, time.Now(), body)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("webhook response = %d %s", response.Code, response.Body.String())
	}
	var rows []webhookInboxRow
	if err := store.db.Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("stored rows = %d", len(rows))
	}
	var event NormalizedPaddleEvent
	if err := json.Unmarshal(rows[0].Payload, &event); err != nil {
		t.Fatal(err)
	}
	if event.EventID != "evt_01grnn4zta5a1mf02jjze7y2ys" || event.InvoiceRef != "ki_safe" || event.Status != "completed" {
		t.Fatalf("normalized event = %+v", event)
	}
	if bytes.Contains(rows[0].Payload, []byte("private_note")) || bytes.Contains(rows[0].Payload, []byte("private")) {
		t.Fatalf("raw provider fields were persisted: %s", rows[0].Payload)
	}
	duplicate := paddleSignedRequest(t, secret, time.Now(), body)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, duplicate)
	if response.Code != http.StatusAccepted {
		t.Fatalf("duplicate response = %d", response.Code)
	}
	if err := store.db.WithContext(context.Background()).Find(&rows).Error; err != nil || len(rows) != 1 {
		t.Fatalf("duplicate created rows=%d err=%v", len(rows), err)
	}
}

func TestPaddleWebhookHandlerRejectsUnverifiedAndUnconfiguredRequests(t *testing.T) {
	store := testBillingStore(t)
	verifier, err := NewPaddleWebhookVerifier("pdl_ntfset_test_secret")
	if err != nil {
		t.Fatal(err)
	}
	handler := NewPaddleWebhookHandler(verifier, store)
	request := httptest.NewRequest(http.MethodPost, "/webhooks/paddle", bytes.NewReader([]byte(`{}`)))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("unsigned response = %d", response.Code)
	}
	response = httptest.NewRecorder()
	NewPaddleWebhookHandler(nil, store).ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("disabled response = %d", response.Code)
	}
}

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
