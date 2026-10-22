// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// Package turnhealth checks TURN admission using short-lived credentials.
// Allocation readiness is evidence from the control host's network vantage,
// not proof of end-to-end overlay delivery or every client's reachability.
package turnhealth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/netbirdio/netbird/management/internals/karst/turncred"
	"github.com/pion/logging"
	"github.com/pion/stun/v4"
	"github.com/pion/turn/v5"
)

type Result struct {
	State      string    `json:"state"`
	ObservedAt time.Time `json:"observed_at"`
	DurationMS int64     `json:"duration_ms"`
}

type endpoint struct {
	host, port, transport string
	tls                   bool
}

func parseURI(raw string) (endpoint, error) {
	scheme, rest, ok := strings.Cut(raw, ":")
	if !ok || (scheme != "turn" && scheme != "turns") {
		return endpoint{}, errors.New("unsupported scheme")
	}
	authority, query, _ := strings.Cut(strings.TrimPrefix(rest, "//"), "?")
	u, err := url.Parse("//" + authority)
	if err != nil || u.Hostname() == "" || u.User != nil || u.Path != "" || u.Fragment != "" {
		return endpoint{}, errors.New("invalid endpoint")
	}
	values, err := url.ParseQuery(query)
	if err != nil {
		return endpoint{}, err
	}
	transport := "udp"
	if scheme == "turns" {
		transport = "tcp"
	}
	if len(values) > 0 {
		if len(values) != 1 || len(values["transport"]) != 1 {
			return endpoint{}, errors.New("unsupported URI query")
		}
		transport = values.Get("transport")
	}
	if (transport != "udp" && transport != "tcp") || (scheme == "turns" && transport != "tcp") {
		return endpoint{}, errors.New("unsupported transport")
	}
	port := u.Port()
	if port == "" {
		port = "3478"
		if scheme == "turns" {
			port = "5349"
		}
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return endpoint{}, errors.New("invalid port")
	}
	return endpoint{host: u.Hostname(), port: port, transport: transport, tls: scheme == "turns"}, nil
}

// Probe performs one authenticated allocation and immediately releases it.
// It never returns raw protocol errors, credentials, or assigned relay addresses.
// A fixed upper bound applies even when the caller supplies no deadline.
func Probe(ctx context.Context, uri string, credential turncred.Credential) Result {
	return (ProbeConfig{}).Check(ctx, uri, credential)
}

// ProbeConfig permits private trust roots for deployments using an internal
// CA. Nil RootCAs uses the host's system roots; verification stays mandatory.
type ProbeConfig struct{ RootCAs *x509.CertPool }

func (config ProbeConfig) Check(ctx context.Context, uri string, credential turncred.Credential) (result Result) {
	started := time.Now()
	result.State = "unreachable"
	defer func() { result.ObservedAt = time.Now().UTC(); result.DurationMS = time.Since(started).Milliseconds() }()
	target, err := parseURI(uri)
	if err != nil {
		result.State = "unsupported"
		return
	}
	if credential.Username == "" || credential.Password == "" {
		result.State = "credentials_unavailable"
		return
	}
	if !credential.ExpiresAt.After(started) {
		result.State = "credentials_expired"
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	classify := func(err error) string {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return "timeout"
		}
		if errors.Is(ctx.Err(), context.Canceled) {
			return "canceled"
		}
		var verification *tls.CertificateVerificationError
		if errors.As(err, &verification) {
			return "tls_failed"
		}
		var networkError net.Error
		if errors.As(err, &networkError) && networkError.Timeout() {
			return "timeout"
		}
		var response *stun.TurnError
		if errors.As(err, &response) {
			switch int(response.ErrorCodeAttr.Code) {
			case 400, 401, 403, 441, 486:
				return "denied"
			}
		}
		return "unreachable"
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", target.host)
	if err != nil || len(ips) == 0 {
		result.State = classify(err)
		return
	}
	ip := ips[0].Unmap()
	address := net.JoinHostPort(ip.String(), target.port)
	var packet net.PacketConn
	if target.transport == "udp" {
		network, local := "udp4", "0.0.0.0:0"
		if ip.Is6() {
			network, local = "udp6", "[::]:0"
		}
		var listener net.ListenConfig
		packet, err = listener.ListenPacket(ctx, network, local)
	} else {
		var conn net.Conn
		if target.tls {
			dialer := tls.Dialer{Config: &tls.Config{ServerName: target.host, RootCAs: config.RootCAs, MinVersion: tls.VersionTLS12}}
			conn, err = dialer.DialContext(ctx, "tcp", address)
		} else {
			conn, err = (&net.Dialer{}).DialContext(ctx, "tcp", address)
		}
		if err == nil {
			packet = turn.NewSTUNConn(conn)
		}
	}
	if err != nil {
		result.State = classify(err)
		return
	}
	defer packet.Close()
	// Bound both allocation traffic and the best-effort release write.
	if deadline, ok := ctx.Deadline(); ok {
		if err := packet.SetDeadline(deadline); err != nil {
			result.State = classify(err)
			return
		}
	}
	// Suppress library logging at construction, independent of environment
	// overrides, so neither wire errors nor credentials reach application logs.
	client, err := turn.NewClient(&turn.ClientConfig{TURNServerAddr: address, Conn: packet, Username: credential.Username, Password: credential.Password, LoggerFactory: &logging.DefaultLoggerFactory{Writer: io.Discard, DefaultLogLevel: logging.LogLevelDisabled}})
	if err != nil {
		result.State = classify(err)
		return
	}
	defer client.Close()
	if err := client.Listen(); err != nil {
		result.State = classify(err)
		return
	}
	allocation, err := client.AllocateWithContext(ctx)
	if err != nil {
		result.State = classify(err)
		return
	}
	defer allocation.Close()
	result.State = "ready"
	return
}
