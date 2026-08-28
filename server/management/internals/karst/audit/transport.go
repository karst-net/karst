// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package audit

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Transport delivers the credential-free sink types accepted by AddSink.
// Authentication material stays in a deployment's outbound proxy or secret
// store; it is never accepted by, stored in, or returned from this package.
type Transport struct {
	HTTPClient *http.Client
	TLSConfig  *tls.Config
	DialTLS    func(context.Context, string, string, *tls.Config) (net.Conn, error)
}

func NewTransport() *Transport {
	return &Transport{HTTPClient: &http.Client{Timeout: 10 * time.Second}}
}

type deliveryPayload struct {
	Sequence     uint64    `json:"sequence"`
	CreatedAt    time.Time `json:"created_at"`
	Actor        string    `json:"actor"`
	Action       string    `json:"action"`
	Target       string    `json:"target"`
	Detail       string    `json:"detail,omitempty"`
	PreviousHash string    `json:"previous_hash"`
	Hash         string    `json:"hash"`
}

func payloadFor(entry Entry) deliveryPayload {
	return deliveryPayload{entry.Seq, entry.CreatedAt.UTC(), entry.Actor, entry.Action, entry.Target, entry.Detail, entry.PrevHash, entry.Hash}
}

func (t *Transport) Deliver(ctx context.Context, sink Sink, entry Entry) error {
	switch sink.Kind {
	case "webhook":
		return t.webhook(ctx, sink, entry)
	case "syslog":
		return t.syslog(ctx, sink, entry)
	default:
		return fmt.Errorf("audit: unsupported sink kind %q", sink.Kind)
	}
}

func (t *Transport) webhook(ctx context.Context, sink Sink, entry Entry) error {
	body, err := json.Marshal(payloadFor(entry))
	if err != nil {
		return fmt.Errorf("audit: encode webhook payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, sink.Endpoint, strings.NewReader(string(body)))
	if err != nil {
		return fmt.Errorf("audit: create webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Karst-Audit-Sequence", fmt.Sprint(entry.Seq))
	req.Header.Set("X-Karst-Audit-Hash", entry.Hash)
	client := t.HTTPClient
	if client == nil {
		client = NewTransport().HTTPClient
	}
	response, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("audit: webhook: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return fmt.Errorf("audit: webhook returned %s: %s", response.Status, strings.TrimSpace(string(body)))
	}
	return nil
}

func (t *Transport) syslog(ctx context.Context, sink Sink, entry Entry) error {
	u, err := url.Parse(sink.Endpoint)
	if err != nil || u.Scheme != "tls" || u.Hostname() == "" {
		return fmt.Errorf("audit: invalid syslog endpoint")
	}
	address := u.Host
	if _, _, err := net.SplitHostPort(address); err != nil {
		address = net.JoinHostPort(u.Hostname(), "6514")
	}
	config := t.TLSConfig
	if config == nil {
		config = &tls.Config{MinVersion: tls.VersionTLS13}
	} else {
		config = config.Clone()
	}
	if config.ServerName == "" {
		config.ServerName = u.Hostname()
	}
	dial := t.DialTLS
	if dial == nil {
		dialer := &tls.Dialer{Config: config}
		dial = func(ctx context.Context, network, address string, _ *tls.Config) (net.Conn, error) {
			return dialer.DialContext(ctx, network, address)
		}
	}
	connection, err := dial(ctx, "tcp", address, config)
	if err != nil {
		return fmt.Errorf("audit: syslog dial: %w", err)
	}
	defer connection.Close()
	payload, err := json.Marshal(payloadFor(entry))
	if err != nil {
		return fmt.Errorf("audit: encode syslog payload: %w", err)
	}
	message := fmt.Sprintf("<134>1 %s - karst-audit - AUDIT - [karst@32473 sequence=\"%d\" hash=\"%s\"] %s\n", entry.CreatedAt.UTC().Format(time.RFC3339Nano), entry.Seq, entry.Hash, payload)
	if _, err := io.WriteString(connection, message); err != nil {
		return fmt.Errorf("audit: syslog write: %w", err)
	}
	return nil
}
