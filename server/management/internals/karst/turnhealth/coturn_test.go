// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package turnhealth

import (
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/netbirdio/netbird/management/internals/karst/turncred"
	"github.com/stretchr/testify/require"
)

// A real coturn process, isolated from installed configuration and services.
// Environments without the binary skip explicitly; no provider is contacted.
func TestCoturnRESTCredentialCompatibility(t *testing.T) {
	binary, err := exec.LookPath("turnserver")
	if err != nil {
		t.Skip("coturn binary unavailable")
	}
	port := 0
	for range 10 {
		udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
		require.NoError(t, err)
		candidate := udp.LocalAddr().(*net.UDPAddr).Port
		tcp, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(candidate)))
		_ = udp.Close()
		if err != nil {
			continue
		}
		_ = tcp.Close()
		port = candidate
		break
	}
	require.NotZero(t, port, "reserve an isolated UDP/TCP listener port")
	dir := t.TempDir()
	command := exec.Command(binary, "-n", "--listening-ip=127.0.0.1", "--relay-ip=127.0.0.1", "--listening-port="+strconv.Itoa(port), "--no-tls", "--no-dtls", "--no-cli", "--no-tcp-relay", "--realm=karst-probe-test", "--use-auth-secret", "--static-auth-secret=probe-test-secret", "--relay-threads=1", "--log-file=stdout", "--pidfile="+filepath.Join(dir, "coturn.pid"))
	command.Dir = dir
	command.Stdout, command.Stderr = io.Discard, io.Discard
	require.NoError(t, command.Start())
	t.Cleanup(func() { _ = command.Process.Signal(os.Interrupt); _ = command.Process.Kill(); _ = command.Wait() })
	uri := "turn:" + net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	minter, err := turncred.NewMinter("probe-test-secret", time.Minute)
	require.NoError(t, err)
	ready := false
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		credential, err := minter.Mint()
		require.NoError(t, err)
		ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
		result := Probe(ctx, uri, credential)
		cancel()
		if result.State == "ready" {
			ready = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	require.True(t, ready, "coturn must accept credentials minted by control")
	credential, err := minter.Mint()
	require.NoError(t, err)
	require.Equal(t, "ready", Probe(context.Background(), uri+"?transport=tcp", credential).State)
	credential.Password = "invalid"
	require.Equal(t, "denied", Probe(context.Background(), uri, credential).State)
}
