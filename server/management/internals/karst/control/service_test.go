// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package control_test

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/netbirdio/netbird/management/internals/controllers/network_map/update_channel"
	"github.com/netbirdio/netbird/management/internals/karst/channel"
	"github.com/netbirdio/netbird/management/internals/karst/control"
	"github.com/netbirdio/netbird/management/internals/karst/identity"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/telemetry"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// These run over a real gRPC server on a real (in-memory) socket, with real
// ML-KEM-768 and ML-DSA-65 — not in-process calls. The point is to catch the
// things that only appear once messages are marshalled and streamed: the
// server having to speak first, oneof handling, and stream lifecycle.

type fixture struct {
	svc      *control.Service
	client   proto.KarstControlServiceClient
	nodeKey  *identity.Key
	cleanup  func()
	handlerC chan []byte
}

func newFixture(t *testing.T, lookup channel.IdentityLookup, handler control.Handler) *fixture {
	t.Helper()

	static, err := channel.GenerateStatic()
	if err != nil {
		t.Fatalf("static key: %v", err)
	}
	nodeKey, err := identity.Generate()
	if err != nil {
		t.Fatalf("node identity: %v", err)
	}
	srvKey, err := identity.Generate()
	if err != nil {
		t.Fatalf("server identity: %v", err)
	}
	if lookup == nil {
		lookup = func([]byte) []byte { return nil }
	}
	seen := make(chan []byte, 8)
	if handler == nil {
		handler = control.HandlerFunc(func(_ context.Context, _, _, payload []byte) ([]byte, error) {
			// Non-blocking: this channel exists only so a test can assert the
			// handler did *not* run. A blocking send wedges the handler once
			// the buffer fills, which looks exactly like a protocol deadlock.
			select {
			case seen <- bytes.Clone(payload):
			default:
			}
			return append([]byte("echo:"), payload...), nil
		})
	}
	svc := control.New(static, identity.ControlSigner{Key: srvKey}, lookup, identity.ControlVerifier{}, handler)

	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	proto.RegisterKarstControlServiceServer(srv, svc)
	go func() { _ = srv.Serve(lis) }()

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	return &fixture{
		svc:      svc,
		client:   proto.NewKarstControlServiceClient(conn),
		nodeKey:  nodeKey,
		handlerC: seen,
		cleanup: func() {
			_ = conn.Close()
			srv.Stop()
			_ = lis.Close()
		},
	}
}

func TestRegisterAndRequestOverGRPC(t *testing.T) {
	f := newFixture(t, nil, nil)
	defer f.cleanup()

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

	resp, err := cl.Request([]byte("hello"))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if want := "echo:hello"; string(resp) != want {
		t.Fatalf("got %q want %q", resp, want)
	}
}

// The channel must survive many requests: the sequence counters advance on
// both sides and a mistake there shows up on the second message, not the first.
func TestManyRequestsOnOneChannel(t *testing.T) {
	f := newFixture(t, nil, nil)
	defer f.cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
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

	for i := 0; i < 50; i++ {
		payload := []byte{byte(i)}
		resp, err := cl.Request(payload)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		if !bytes.Equal(resp, append([]byte("echo:"), payload...)) {
			t.Fatalf("request %d: got %q", i, resp)
		}
	}
}

// The authenticated identity reaches the handler, and it is the key the node
// actually proved possession of.
func TestHandlerReceivesAuthenticatedIdentity(t *testing.T) {
	got := make(chan []byte, 1)
	handler := control.HandlerFunc(func(_ context.Context, _, id, _ []byte) ([]byte, error) {
		got <- bytes.Clone(id)
		return []byte("ok"), nil
	})
	f := newFixture(t, nil, handler)
	defer f.cleanup()

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
	if _, err := cl.Request([]byte("x")); err != nil {
		t.Fatalf("request: %v", err)
	}

	select {
	case id := <-got:
		if !bytes.Equal(id, f.nodeKey.Public()) {
			t.Fatal("handler got an identity other than the node's")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handler was never called")
	}
}

// Skipping the handshake must not reach the handler.
func TestEnvelopeBeforeHandshakeRejected(t *testing.T) {
	f := newFixture(t, nil, nil)
	defer f.cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := f.client.Session(ctx)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if _, err := stream.Recv(); err != nil { // the hello
		t.Fatalf("recv hello: %v", err)
	}
	if err := stream.Send(&proto.KarstClientMessage{
		Msg: &proto.KarstClientMessage_Envelope{Envelope: &proto.KarstEnvelope{
			NodeId: []byte("node-1"), Body: []byte("unauthenticated"), Seq: 1, Version: 1,
		}},
	}); err != nil {
		t.Fatalf("send: %v", err)
	}
	if _, err := stream.Recv(); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("got %v want InvalidArgument", err)
	}
	select {
	case p := <-f.handlerC:
		t.Fatalf("handler ran on unauthenticated payload %q", p)
	default:
	}
}

// A node signing with the wrong key must be rejected uniformly, and the error
// must not distinguish "unknown node" from "bad signature" — that difference
// is a node-ID oracle for an unauthenticated caller.
func TestWrongIdentitirejected(t *testing.T) {
	enrolled, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	f := newFixture(t, func([]byte) []byte { return enrolled.Public() }, nil)
	defer f.cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := f.client.Session(ctx)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	// f.nodeKey is not the enrolled key.
	_, err = control.Dial(stream, f.svc.Pins(), identity.ControlVerifier{}, []byte("node-1"),
		identity.ControlSigner{Key: f.nodeKey}, false)
	if err == nil {
		// Dial only sends; the rejection surfaces on the next receive.
		if _, err = stream.Recv(); err == nil {
			t.Fatal("a wrongly-signed handshake was accepted")
		}
	}
	if code := status.Code(err); code != codes.Unauthenticated && !errors.Is(err, control.ErrHandshake) {
		t.Fatalf("got code %v (%v), want Unauthenticated", code, err)
	}
}

// Pinning the wrong server key means the node cannot derive the channel key.
// It fails closed at the first envelope rather than at the handshake, because
// ML-KEM decapsulation of a foreign ciphertext yields an implicit-rejection
// secret instead of an error — that is by design in FIPS 203.
func TestWrongPinnedServerKeyFailsClosed(t *testing.T) {
	f := newFixture(t, nil, nil)
	defer f.cleanup()

	impostor, err := channel.GenerateStatic()
	if err != nil {
		t.Fatalf("static: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := f.client.Session(ctx)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	cl, err := control.Dial(stream, channel.ServerPins{StaticKEM: impostor.PublicKey(), VerifyKey: f.svc.Pins().VerifyKey}, identity.ControlVerifier{}, nil,
		identity.ControlSigner{Key: f.nodeKey}, true)
	if err != nil {
		return // acceptable: rejected at the handshake
	}
	if _, err := cl.Request([]byte("secret")); err == nil {
		t.Fatal("a channel built on the wrong pinned key carried a request")
	}
	select {
	case p := <-f.handlerC:
		t.Fatalf("handler ran with a mismatched channel key, payload %q", p)
	default:
	}
}

// Re-handshaking mid-stream would reset sequence counters under a key already
// in use.
func TestSecondHandshakeRejected(t *testing.T) {
	f := newFixture(t, nil, nil)
	defer f.cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := f.client.Session(ctx)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if _, err := control.Dial(stream, f.svc.Pins(), identity.ControlVerifier{}, nil,
		identity.ControlSigner{Key: f.nodeKey}, true); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if err := stream.Send(&proto.KarstClientMessage{
		Msg: &proto.KarstClientMessage_Init{Init: &proto.ChannelInit{Version: 1}},
	}); err != nil {
		t.Fatalf("send: %v", err)
	}
	if _, err := stream.Recv(); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("got %v want InvalidArgument", err)
	}
}

// A second session for the same node identity must evict the first, not run
// alongside it — GitHub issue #87: an attacker who cloned a node's identity
// key used to get a fully functional, silently-accepted second session while
// the real device's own connection carried on undisturbed. Newest wins now,
// and the older connection is torn down rather than left running.
func TestSecondSessionForSameIdentityEvictsFirst(t *testing.T) {
	// §6 of the observability plan: karst.control.session_handshake must
	// fire for both the normal connection and the duplicate-identity
	// eviction path, not only the happy path — a real gap §9 of
	// 04-pentest.md found for logging (a successful duplicate registration
	// produced no log line at all), which a span-presence check here
	// guards against regressing for tracing too. An in-memory exporter
	// swapped in for this test's global TracerProvider, restored after,
	// is enough — no collector needed to see whether spans were created.
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	defer otel.SetTracerProvider(prev)

	f := newFixture(t, nil, nil)
	defer f.cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	dial := func() (*control.Client, proto.KarstControlService_SessionClient) {
		t.Helper()
		stream, err := f.client.Session(ctx)
		if err != nil {
			t.Fatalf("connect: %v", err)
		}
		cl, err := control.Dial(stream, f.svc.Pins(), identity.ControlVerifier{}, nil,
			identity.ControlSigner{Key: f.nodeKey}, true)
		if err != nil {
			t.Fatalf("handshake: %v", err)
		}
		return cl, stream
	}

	firstClient, firstStream := dial()
	if _, err := firstClient.Request([]byte("still alive")); err != nil {
		t.Fatalf("first session's initial request: %v", err)
	}

	// Same identity (f.nodeKey) again — the clone.
	secondClient, _ := dial()
	if _, err := secondClient.Request([]byte("the clone")); err != nil {
		t.Fatalf("second session's request: %v", err)
	}

	// The first session's stream must now be torn down, not merely quiet:
	// its next Recv should fail rather than hang or keep serving.
	if _, err := firstStream.Recv(); err == nil {
		t.Fatal("evicted session's stream is still open")
	}
	if _, err := firstClient.Request([]byte("should not land")); err == nil {
		t.Fatal("evicted session accepted a request after being superseded")
	}

	// The second session is unaffected by the first's teardown.
	if _, err := secondClient.Request([]byte("still the live one")); err != nil {
		t.Fatalf("second session after eviction: %v", err)
	}

	var handshakeSpans int
	for _, span := range exporter.GetSpans() {
		if span.Name == "karst.control.session_handshake" {
			handshakeSpans++
		}
	}
	if handshakeSpans != 2 {
		t.Fatalf("got %d karst.control.session_handshake spans, want 2 (one per session, including the evicted one)", handshakeSpans)
	}
}

// Two nodes on the same server must get independent channels.
func TestConcurrentNodesGetIndependentChannels(t *testing.T) {
	f := newFixture(t, nil, nil)
	defer f.cleanup()

	other, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	dial := func(k *identity.Key) *control.Client {
		t.Helper()
		stream, err := f.client.Session(ctx)
		if err != nil {
			t.Fatalf("connect: %v", err)
		}
		cl, err := control.Dial(stream, f.svc.Pins(), identity.ControlVerifier{}, nil,
			identity.ControlSigner{Key: k}, true)
		if err != nil {
			t.Fatalf("handshake: %v", err)
		}
		return cl
	}

	a, b := dial(f.nodeKey), dial(other)
	for i := 0; i < 5; i++ {
		if _, err := a.Request([]byte("a")); err != nil {
			t.Fatalf("a request %d: %v", i, err)
		}
		if _, err := b.Request([]byte("b")); err != nil {
			t.Fatalf("b request %d: %v", i, err)
		}
	}
}

// fakePeerLister resolves every peer key to one fixed peer.ID — all
// subscribeOnce needs from PeerLister to register a session for updates.
// The rest of the interface (routing, prefixes) belongs to tests that
// actually exercise a netmap, not this one.
type fakePeerLister struct{ peerID string }

func (fakePeerLister) GetPeersFromAccount(context.Context, string, string, string) ([]*nbpeer.Peer, error) {
	return nil, nil
}

func (fakePeerLister) GetAccountIDForPeerKey(context.Context, string) (string, error) { return "", nil }

func (f fakePeerLister) GetPeerByPeerPubKey(context.Context, string) (*nbpeer.Peer, error) {
	return &nbpeer.Peer{ID: f.peerID}, nil
}

func (fakePeerLister) AccountPrefixes(context.Context, string) (uint8, uint8, error) {
	return 16, 64, nil
}

// TestNetmapPushDurationRecordedExactlyOncePerPush is §6 of the observability
// plan: management.karst.netmap.push.duration.ms must record exactly one
// sample per real push, and the notification channel simply closing (the
// same "superseded" signal a duplicate-identity eviction produces via
// CreateNotificationChannel, service.go's own comment) must not itself be
// counted as one.
func TestNetmapPushDurationRecordedExactlyOncePerPush(t *testing.T) {
	f := newFixture(t, nil, nil)
	defer f.cleanup()

	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	defer func() {
		_ = provider.Shutdown(context.Background())
	}()
	metrics, err := telemetry.NewKarstMetrics(context.Background(), provider.Meter("test"))
	if err != nil {
		t.Fatalf("karst metrics: %v", err)
	}
	f.svc.RecordMetricsWith(metrics)

	const peerID = "peer-under-test"
	updates := update_channel.NewPeersUpdateManager(nil)
	f.svc.SubscribeToUpdatesWith(fakePeerLister{peerID: peerID}, updates)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	stream, err := f.client.Session(ctx)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if _, err := control.Dial(stream, f.svc.Pins(), identity.ControlVerifier{}, []byte("node-under-test"),
		identity.ControlSigner{Key: f.nodeKey}, true); err != nil {
		t.Fatalf("handshake: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for !updates.HasNotificationChannel(peerID) {
		if time.Now().After(deadline) {
			t.Fatalf("peer %s was never subscribed to updates", peerID)
		}
		time.Sleep(10 * time.Millisecond)
	}

	pushSamples := func() int64 {
		var rm metricdata.ResourceMetrics
		if err := reader.Collect(context.Background(), &rm); err != nil {
			t.Fatalf("collect: %v", err)
		}
		for _, sm := range rm.ScopeMetrics {
			for _, m := range sm.Metrics {
				if m.Name != "management.karst.netmap.push.duration.ms" {
					continue
				}
				hist, ok := m.Data.(metricdata.Histogram[int64])
				if !ok {
					t.Fatalf("expected Histogram[int64], got %T", m.Data)
				}
				var total uint64
				for _, dp := range hist.DataPoints {
					total += dp.Count
				}
				return int64(total)
			}
		}
		return 0
	}

	if got := pushSamples(); got != 0 {
		t.Fatalf("push duration recorded %d samples before any push", got)
	}

	// One SendNotification at a time, waiting for each to land before the
	// next: SendNotification deliberately coalesces (its own doc comment),
	// so firing several back to back would legitimately collapse into fewer
	// than N real pushes and prove nothing about double-recording.
	const pushes = 3
	for i := 1; i <= pushes; i++ {
		updates.SendNotification(ctx, peerID)
		waitUntil := time.Now().Add(2 * time.Second)
		for pushSamples() < int64(i) {
			if time.Now().After(waitUntil) {
				t.Fatalf("push %d: only %d samples recorded after 2s", i, pushSamples())
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	if got := pushSamples(); got != pushes {
		t.Fatalf("push duration recorded %d samples, want exactly %d (one per SendNotification)", got, pushes)
	}

	// Replacing the notification channel closes the old one out from under
	// this session, the same signal an evicting session's supersession
	// produces. That close reaches the session's select loop as `!ok`, not
	// as a value — confirm it is not recorded as a push.
	updates.CreateNotificationChannel(ctx, peerID)
	time.Sleep(200 * time.Millisecond)
	if got := pushSamples(); got != pushes {
		t.Fatalf("closing the notification channel changed the sample count to %d, want unchanged %d — a closed channel is not a push", got, pushes)
	}
}
