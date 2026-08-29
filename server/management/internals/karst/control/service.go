// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// Package control serves KarstControlService: the post-quantum node<->server
// stream described in ADR-0011.
//
// It is deliberately a *parallel* service rather than a rewrite of the forked
// ManagementService handlers. Spike 0001 §5.2a found that NetBird's identity
// fusion is confined to the gRPC layer — below it, LoginPeer and friends take
// the peer handle as a plain string and never do a key operation on it. So the
// business layer is reusable as-is, and the forked handlers stay untouched,
// which is what keeps upstream security cherry-picks applying cleanly.
package control

import (
	"context"
	"errors"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/management/internals/karst/channel"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// Handler processes one decrypted request and returns the decrypted response.
//
// It receives the *authenticated* node identity, not a claim: by the time this
// is called the ML-DSA signature over the handshake transcript has verified,
// so identity is the key the node proved possession of.
type Handler interface {
	Handle(ctx context.Context, nodeID, identity, payload []byte) ([]byte, error)
}

// HandlerFunc adapts a function to Handler.
type HandlerFunc func(ctx context.Context, nodeID, identity, payload []byte) ([]byte, error)

func (f HandlerFunc) Handle(ctx context.Context, nodeID, identity, payload []byte) ([]byte, error) {
	return f(ctx, nodeID, identity, payload)
}

// SessionRecorder is told when an authenticated node's stream opens, makes
// progress, and closes. It is what gives the portal a session history with a
// real end time and a real address instead of audit rows with neither
// (plans/phase-5/05-user-portal.md §1).
//
// Recording starts *after* the handshake, deliberately. A connection that
// fails to authenticate is not a session; writing a row for one would let an
// unauthenticated caller append to a table by connecting, and would show a
// user attempts that were never their device.
type SessionRecorder interface {
	// Opened returns an id that Touched and Closed refer to. An id of zero
	// means "not recording", and the other two methods ignore it.
	Opened(ctx context.Context, handle, clientAddr string) (uint64, error)
	Touched(ctx context.Context, id uint64) error
	Closed(ctx context.Context, id uint64) error
}

// Service implements proto.KarstControlServiceServer.
type Service struct {
	proto.UnimplementedKarstControlServiceServer

	static   *channel.StaticKey
	identity channel.Signer
	lookup   channel.IdentityLookup
	verifier channel.Verifier
	handler  Handler
	// sessions is optional. Nil means the deployment keeps no session history,
	// which is how the test server and every existing caller of New behave.
	sessions SessionRecorder
}

// RecordSessionsWith attaches a session recorder. Separate from New so that
// callers that do not keep session history — the test server, and anything
// constructing a service for one exchange — are unchanged by its existence.
func (s *Service) RecordSessionsWith(recorder SessionRecorder) { s.sessions = recorder }

// New builds the service.
//
// static is the server's long-lived ML-KEM-768 key and identity is its
// ML-DSA-65 signing key. Nodes pin *both* public halves at enrollment: the KEM
// key authenticates the server implicitly, and the verification key is what
// makes the per-connection ephemeral trustworthy, and so what makes forward
// secrecy real (ADR-0011, spec/models/karst-control.pv).
func New(static *channel.StaticKey, identity channel.Signer, lookup channel.IdentityLookup, verifier channel.Verifier, handler Handler) *Service {
	return &Service{static: static, identity: identity, lookup: lookup, verifier: verifier, handler: handler}
}

// Pins are what a node must be given out of band at enrollment. Handing out
// only the KEM half silently downgrades forward secrecy.
func (s *Service) Pins() channel.ServerPins {
	return channel.ServerPins{StaticKEM: s.static.PublicKey(), VerifyKey: s.identity.PublicKey()}
}

// StaticPublicKey is the KEM half alone.
func (s *Service) StaticPublicKey() []byte { return s.static.PublicKey() }

// Connect runs one node's stream: handshake, then request/response until the
// peer goes away.
func (s *Service) Session(stream proto.KarstControlService_SessionServer) error {
	ctx := stream.Context()

	// The server speaks first. This is what makes a captured ChannelInit
	// useless on a new connection: the node signs over server_random, which
	// it has not seen yet.
	hello, pending, err := s.static.Hello(s.identity)
	if err != nil {
		log.WithContext(ctx).Errorf("karst: generating hello: %v", err)
		return status.Error(codes.Internal, "handshake setup failed")
	}
	if err := stream.Send(&proto.KarstServerMessage{
		Msg: &proto.KarstServerMessage_Hello{Hello: hello},
	}); err != nil {
		return err
	}

	first, err := stream.Recv()
	if err != nil {
		return err
	}
	init := first.GetInit()
	if init == nil {
		// An envelope before the handshake means either a confused client or
		// someone probing for a path that skips authentication.
		return status.Error(codes.InvalidArgument, "first message must be ChannelInit")
	}

	ch, identity, err := s.static.Accept(pending, init, s.lookup, s.verifier)
	if err != nil {
		// Deliberately uniform: distinguishing "no such node" from "bad
		// signature" would let an unauthenticated caller enumerate node IDs.
		log.WithContext(ctx).Debugf("karst: handshake rejected: %v", err)
		return status.Error(codes.Unauthenticated, "handshake failed")
	}
	nodeID := init.GetNodeId()

	// From here the node is authenticated, so the connection is a session.
	//
	// The close is deferred rather than written at each return: this loop
	// leaves by seven different paths, one of them the ordinary io.EOF of a
	// node shutting down, and a session history that is correct only for the
	// tidy exits would be wrong exactly when someone is looking at it.
	//
	// A recording failure is logged and not returned. A device that cannot
	// connect because the server could not write a history row would be a
	// worse outcome than a missing row.
	var sessionID uint64
	if s.sessions != nil {
		var err error
		if sessionID, err = s.sessions.Opened(ctx, string(nodeID), clientAddr(ctx)); err != nil {
			log.WithContext(ctx).Warnf("karst: recording session start for %x: %v", nodeID, err)
		}
		defer func() {
			// ctx is canceled by the time this runs on a client hangup, and a
			// canceled context is one no write will be accepted on — so the
			// close gets its own.
			closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), sessionCloseTimeout)
			defer cancel()
			if err := s.sessions.Closed(closeCtx, sessionID); err != nil {
				log.WithContext(closeCtx).Warnf("karst: recording session end for %x: %v", nodeID, err)
			}
		}()
	}

	for {
		msg, err := stream.Recv()
		if err != nil {
			return err // includes io.EOF for a clean client hangup
		}
		if s.sessions != nil {
			if err := s.sessions.Touched(ctx, sessionID); err != nil {
				log.WithContext(ctx).Debugf("karst: advancing session for %x: %v", nodeID, err)
			}
		}
		if msg.GetInit() != nil {
			// Re-handshaking mid-stream would reset the sequence counters
			// under a key the peer has already used.
			return status.Error(codes.InvalidArgument, "channel already established")
		}
		env := msg.GetEnvelope()
		if env == nil {
			return status.Error(codes.InvalidArgument, "empty message")
		}

		payload, err := ch.Open(env)
		if err != nil {
			// A failure here is not a lost packet — the stream is ordered and
			// authenticated, so this means tampering or a bug. Ending the
			// stream is the correct response; there is no recovery that does
			// not weaken the channel.
			log.WithContext(ctx).Warnf("karst: envelope from %x rejected: %v", nodeID, err)
			return status.Error(codes.Unauthenticated, "envelope rejected")
		}

		resp, err := s.handler.Handle(ctx, nodeID, identity, payload)
		if err != nil {
			if s, ok := status.FromError(err); ok {
				return s.Err()
			}
			log.WithContext(ctx).Errorf("karst: handler: %v", err)
			return status.Error(codes.Internal, "request failed")
		}
		if resp == nil {
			continue // one-way message; nothing to send back
		}

		out, err := ch.Seal(nodeID, resp)
		if err != nil {
			return status.Error(codes.Internal, "response sealing failed")
		}
		if err := stream.Send(&proto.KarstServerMessage{
			Msg: &proto.KarstServerMessage_Envelope{Envelope: out},
		}); err != nil {
			return err
		}
	}
}

// sessionCloseTimeout bounds the write that records a disconnect. It runs on a
// context detached from the dead stream's, so without a deadline a stalled
// database would hold the goroutine for that connection open indefinitely.
const sessionCloseTimeout = 5 * time.Second

// clientAddr reports the address gRPC says the stream came from, or "" when
// the transport does not supply one — an in-process pipe in a test, for
// instance. See node.DeviceSession for what this address does and does not
// mean behind a proxy.
func clientAddr(ctx context.Context) string {
	if p, ok := peer.FromContext(ctx); ok && p.Addr != nil {
		return p.Addr.String()
	}
	return ""
}

// Client is the node side of the stream. It lives here rather than in the Rust
// node because the Go side needs it for tests, and having one reference
// implementation of the sequencing keeps the two from drifting.
type Client struct {
	stream proto.KarstControlService_SessionClient
	ch     *channel.Channel
	nodeID []byte
}

var ErrHandshake = errors.New("control: handshake failed")

// Dial completes the handshake on an already-open stream.
func Dial(stream proto.KarstControlService_SessionClient, pins channel.ServerPins, verifier channel.Verifier, nodeID []byte, signer channel.Signer, presentIdentity bool) (*Client, error) {
	msg, err := stream.Recv()
	if err != nil {
		return nil, fmt.Errorf("%w: receiving hello: %w", ErrHandshake, err)
	}
	hello := msg.GetHello()
	if hello == nil {
		return nil, fmt.Errorf("%w: first server message was not ChannelHello", ErrHandshake)
	}

	init, ch, err := channel.Initiate(hello, pins, verifier, nodeID, signer, presentIdentity)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrHandshake, err)
	}
	if err := stream.Send(&proto.KarstClientMessage{
		Msg: &proto.KarstClientMessage_Init{Init: init},
	}); err != nil {
		return nil, fmt.Errorf("%w: sending init: %w", ErrHandshake, err)
	}
	return &Client{stream: stream, ch: ch, nodeID: nodeID}, nil
}

// Request sends one payload and waits for its response.
func (c *Client) Request(payload []byte) ([]byte, error) {
	env, err := c.ch.Seal(c.nodeID, payload)
	if err != nil {
		return nil, err
	}
	if err := c.stream.Send(&proto.KarstClientMessage{
		Msg: &proto.KarstClientMessage_Envelope{Envelope: env},
	}); err != nil {
		return nil, err
	}
	msg, err := c.stream.Recv()
	if err != nil {
		return nil, err
	}
	in := msg.GetEnvelope()
	if in == nil {
		return nil, errors.New("control: expected an envelope")
	}
	return c.ch.Open(in)
}

// CloseSend signals no more requests.
func (c *Client) CloseSend() error { return c.stream.CloseSend() }
