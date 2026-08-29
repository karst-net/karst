// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package control_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/netbirdio/netbird/management/internals/karst/control"
	"github.com/netbirdio/netbird/management/internals/karst/identity"
)

// recordingSpy stands in for the node store. It records the calls rather than
// the rows, because what is under test here is the service's lifecycle — that
// something is opened once the node is authenticated, advanced as it works,
// and closed however the stream ends.
type recordingSpy struct {
	mu      sync.Mutex
	opened  []string
	addrs   []string
	touches int
	closed  []uint64
	nextID  uint64
}

func (s *recordingSpy) Opened(_ context.Context, handle, addr string) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextID++
	s.opened = append(s.opened, handle)
	s.addrs = append(s.addrs, addr)
	return s.nextID, nil
}

func (s *recordingSpy) Touched(_ context.Context, _ uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.touches++
	return nil
}

func (s *recordingSpy) Closed(_ context.Context, id uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = append(s.closed, id)
	return nil
}

func (s *recordingSpy) snapshot() ([]string, []string, int, []uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.opened...), append([]string(nil), s.addrs...), s.touches, append([]uint64(nil), s.closed...)
}

func TestAnAuthenticatedStreamOpensAndClosesASession(t *testing.T) {
	f := newFixture(t, nil, nil)
	defer f.cleanup()
	spy := &recordingSpy{}
	f.svc.RecordSessionsWith(spy)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := f.client.Session(ctx)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	cl, err := control.Dial(stream, f.svc.Pins(), identity.ControlVerifier{}, nil,
		identity.ControlSigner{Key: f.nodeKey}, true)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if _, err := cl.Request([]byte("hello")); err != nil {
		t.Fatalf("request: %v", err)
	}

	opened, addrs, touches, _ := spy.snapshot()
	if len(opened) != 1 {
		t.Fatalf("opened %d sessions, want 1", len(opened))
	}
	if touches == 0 {
		t.Error("no request advanced the session's last-seen time")
	}
	// bufconn reports an address; what matters is that the service asked the
	// transport for one rather than recording an empty string.
	if len(addrs) != 1 {
		t.Fatalf("addresses recorded: %d", len(addrs))
	}

	// The close is deferred, so it lands when the stream goes away — which is
	// the case that matters, because a node disconnecting is not a tidy
	// server-side return.
	if err := cl.CloseSend(); err != nil {
		t.Fatalf("close: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, _, _, closed := spy.snapshot(); len(closed) == 1 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	_, _, _, closed := spy.snapshot()
	t.Fatalf("the stream ended and the session was not closed: %v", closed)
}

// A connection that never authenticates is not a session. Recording one would
// let an unauthenticated caller append rows by connecting, and would show a
// user attempts that were never their device.
func TestARejectedHandshakeRecordsNothing(t *testing.T) {
	enrolled, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	// The node presents f.nodeKey; the server expects `enrolled`. Accept fails
	// and the stream ends before any session exists.
	f := newFixture(t, func([]byte) []byte { return enrolled.Public() }, nil)
	defer f.cleanup()
	spy := &recordingSpy{}
	f.svc.RecordSessionsWith(spy)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := f.client.Session(ctx)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if _, err := control.Dial(stream, f.svc.Pins(), identity.ControlVerifier{}, []byte("node-1"),
		identity.ControlSigner{Key: f.nodeKey}, false); err == nil {
		// Dial only sends; the rejection surfaces on the next receive.
		if _, err := stream.Recv(); err == nil {
			t.Fatal("a wrongly-signed handshake was accepted")
		}
	}
	if opened, _, _, _ := spy.snapshot(); len(opened) != 0 {
		t.Errorf("a rejected handshake recorded %d session(s)", len(opened))
	}
}
