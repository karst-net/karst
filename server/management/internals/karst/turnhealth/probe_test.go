// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package turnhealth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/netbirdio/netbird/management/internals/karst/turncred"
	"github.com/pion/logging"
	"github.com/pion/turn/v5"
	"github.com/stretchr/testify/require"
)

func TestTLSAllocationRequiresTrustedServerIdentity(t *testing.T) {
	certificate := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	keypair := certificate.TLS.Certificates[0]
	roots := x509.NewCertPool()
	roots.AddCert(certificate.Certificate())
	certificate.Close()
	listener, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{keypair}, MinVersion: tls.VersionTLS12})
	require.NoError(t, err)
	s, err := turn.NewServer(turn.ServerConfig{Realm: "test", AuthHandler: func(request *turn.RequestAttributes) (string, []byte, bool) {
		return request.Username, turn.GenerateAuthKey(request.Username, "test", "private"), true
	}, ListenerConfigs: []turn.ListenerConfig{{Listener: listener, RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{RelayAddress: net.ParseIP("127.0.0.1"), Address: "127.0.0.1"}}}, LoggerFactory: &logging.DefaultLoggerFactory{Writer: io.Discard, DefaultLogLevel: logging.LogLevelDisabled}})
	require.NoError(t, err)
	defer s.Close()
	uri := "turns:" + listener.Addr().String()
	credential := turncred.Credential{Username: "allowed", Password: "private", ExpiresAt: time.Now().Add(time.Minute)}
	require.Equal(t, "tls_failed", Probe(context.Background(), uri, credential).State)
	require.Equal(t, "ready", (ProbeConfig{RootCAs: roots}).Check(context.Background(), uri, credential).State)
	require.Eventually(t, func() bool { return s.AllocationCount() == 0 }, time.Second, 10*time.Millisecond)
}

func server(t *testing.T, tcp bool) (string, *turn.Server) {
	t.Helper()
	config := turn.ServerConfig{Realm: "test", AuthHandler: func(request *turn.RequestAttributes) (string, []byte, bool) {
		if request.Username != "allowed" {
			return "", nil, false
		}
		return request.Username, turn.GenerateAuthKey(request.Username, "test", "test-password"), true
	}, LoggerFactory: &logging.DefaultLoggerFactory{Writer: io.Discard, DefaultLogLevel: logging.LogLevelDisabled}}
	allocator := &turn.RelayAddressGeneratorStatic{RelayAddress: net.ParseIP("127.0.0.1"), Address: "127.0.0.1"}
	var address string
	if tcp {
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		require.NoError(t, err)
		config.ListenerConfigs = []turn.ListenerConfig{{Listener: listener, RelayAddressGenerator: allocator}}
		address = "turn:" + listener.Addr().String() + "?transport=tcp"
	} else {
		conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
		require.NoError(t, err)
		config.PacketConnConfigs = []turn.PacketConnConfig{{PacketConn: conn, RelayAddressGenerator: allocator}}
		address = "turn:" + conn.LocalAddr().String()
	}
	s, err := turn.NewServer(config)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.Close()) })
	return address, s
}

func TestAuthenticatedAllocationIsReleasedAndDoesNotDiscloseCredentials(t *testing.T) {
	for _, tcp := range []bool{false, true} {
		t.Run(map[bool]string{false: "udp", true: "tcp"}[tcp], func(t *testing.T) {
			uri, s := server(t, tcp)
			credential := turncred.Credential{Username: "allowed", Password: "test-password", ExpiresAt: time.Now().Add(time.Minute)}
			result := Probe(context.Background(), uri, credential)
			require.Equal(t, "ready", result.State)
			require.False(t, result.ObservedAt.IsZero())
			require.Eventually(t, func() bool { return s.AllocationCount() == 0 }, time.Second, 10*time.Millisecond)
			raw, err := json.Marshal(result)
			require.NoError(t, err)
			require.NotContains(t, string(raw), credential.Password)
			require.NotContains(t, string(raw), credential.Username)
		})
	}
}

func TestAdmissionDenialExpiryUnsupportedURIAndCancellation(t *testing.T) {
	uri, s := server(t, false)
	credential := turncred.Credential{Username: "rejected", Password: "not-accepted", ExpiresAt: time.Now().Add(time.Minute)}
	result := Probe(context.Background(), uri, credential)
	require.Equal(t, "denied", result.State)
	require.Zero(t, s.AllocationCount())
	credential.ExpiresAt = time.Now().Add(-time.Second)
	require.Equal(t, "credentials_expired", Probe(context.Background(), uri, credential).State)
	require.Equal(t, "unsupported", Probe(context.Background(), "turns:example.com?transport=udp", credential).State)
	credential.ExpiresAt = time.Now().Add(time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	started := time.Now()
	require.Equal(t, "canceled", Probe(ctx, uri, credential).State)
	require.Less(t, time.Since(started), time.Second)
}

func TestSilentBackendIsBoundedByCallerDeadline(t *testing.T) {
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	result := Probe(ctx, "turn:"+conn.LocalAddr().String(), turncred.Credential{Username: "user", Password: "private", ExpiresAt: time.Now().Add(time.Minute)})
	require.Equal(t, "timeout", result.State)
	require.Less(t, result.DurationMS, int64(1000))
}

func TestIPv6AllocationProbe(t *testing.T) {
	conn, err := net.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	s, err := turn.NewServer(turn.ServerConfig{Realm: "test", AuthHandler: func(request *turn.RequestAttributes) (string, []byte, bool) {
		return request.Username, turn.GenerateAuthKey(request.Username, "test", "private"), true
	}, PacketConnConfigs: []turn.PacketConnConfig{{PacketConn: conn, RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{RelayAddress: net.ParseIP("::1"), Address: "::1"}}}, LoggerFactory: &logging.DefaultLoggerFactory{Writer: io.Discard, DefaultLogLevel: logging.LogLevelDisabled}})
	require.NoError(t, err)
	defer s.Close()
	result := Probe(context.Background(), "turn:"+conn.LocalAddr().String(), turncred.Credential{Username: "allowed", Password: "private", ExpiresAt: time.Now().Add(time.Minute)})
	require.Equal(t, "ready", result.State)
	require.Eventually(t, func() bool { return s.AllocationCount() == 0 }, time.Second, 10*time.Millisecond)
}
