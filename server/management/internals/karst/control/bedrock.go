// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package control

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	pb "google.golang.org/protobuf/proto"

	"github.com/netbirdio/netbird/management/internals/karst/bedrock"
	"github.com/netbirdio/netbird/management/internals/karst/node"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// BedrockLog is the narrow slice of bedrock.Log this handler needs.
//
// An interface rather than the concrete type so the control package does not
// acquire ownership of Bedrock storage, matching how NetmapHandler takes its
// DNS and relay dependencies.
type BedrockLog interface {
	Entries(ctx context.Context, accountID string, sinceSeq uint64, limit int) ([]bedrock.Entry, error)
	Head(ctx context.Context, accountID string) ([]byte, uint64, error)
}

// BedrockHandler answers KarstBedrockRequest — bedrock-v1.md §5, layer 2.
//
// # This handler is not a trust boundary and does not pretend to be one
//
// It reads entries and returns them. It does not sign, cannot sign, and holds
// no key that could. Everything it serves is verified by the node from genesis
// forward, so a compromised server that tampers here produces a node that
// refuses the log — not one that accepts a lie.
//
// What it *can* do is withhold. A server that serves a truncated log, or none,
// leaves a node enforcing on what it last verified (§4), which is the correct
// failure: denial is visible as a network that stops admitting new nodes, while
// the alternative — failing open — is invisible.
type BedrockHandler struct {
	Log   BedrockLog
	Peers PeerLister
}

// Handle implements Handler.
func (h *BedrockHandler) Handle(ctx context.Context, _, identity, payload []byte) ([]byte, error) {
	req := &proto.KarstBedrockRequest{}
	if err := pb.Unmarshal(payload, req); err != nil {
		return nil, status.Error(codes.InvalidArgument, "malformed bedrock request")
	}

	// Derived from the authenticated identity, never from the request — the
	// same rule as the netmap handler. A node asks about its own account's log
	// and has no way to name another.
	self := node.Handle(identity)
	accountID, err := h.Peers.GetAccountIDForPeerKey(ctx, self)
	if err != nil {
		return nil, fmt.Errorf("account for %s: %w", self, err)
	}

	resp := &proto.KarstBedrockResponse{}

	hash, seq, err := h.Log.Head(ctx, accountID)
	switch {
	case err == nil:
		resp.Head = &proto.KarstBedrockHead{Hash: hash, Seq: seq}
	case errors.Is(err, bedrock.ErrNoLog):
		// No log is a normal state: most accounts never turn Bedrock on. The
		// reply carries no head, which a node reads as "nothing to enforce"
		// rather than as a failure.
		return pb.Marshal(resp)
	default:
		return nil, fmt.Errorf("bedrock head: %w", err)
	}

	entries, err := h.Log.Entries(ctx, accountID, req.GetSinceSeq(), bedrock.MaxEntriesPerResponse)
	if err != nil {
		return nil, fmt.Errorf("bedrock entries: %w", err)
	}
	resp.Entries = make([][]byte, 0, len(entries))
	for i := range entries {
		resp.Entries = append(resp.Entries, entries[i].Encode())
	}

	return pb.Marshal(resp)
}
