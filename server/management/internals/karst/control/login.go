// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package control

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/realip"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	pb "google.golang.org/protobuf/proto"

	"github.com/netbirdio/netbird/management/internals/karst/node"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// PeerLoginer is the slice of the forked account manager that Karst needs.
//
// Deliberately narrow. account.Manager has over a hundred methods; depending
// on all of them to call one would make this package impossible to test
// without standing up the whole server, and would couple Karst to upstream
// churn across a surface it does not use.
type PeerLoginer interface {
	LoginPeer(ctx context.Context, login types.PeerLogin) (*nbpeer.Peer, *types.Network, []*posture.Checks, bool, error)
}

// LoginHandler turns an authenticated Karst request into a peer record in the
// forked server's database.
//
// The bridge between the two identity models is one line: the peer handle
// passed to LoginPeer is a hash of the node's ML-DSA-65 key, base64-encoded to
// the same 44 characters a WireGuard key occupies (see package node). The
// business layer never inspects it, so it does not care what produced it.
type LoginHandler struct {
	Nodes    *node.Store
	Accounts PeerLoginer
	// OIDC enables interactive registration. Nil means the server accepts
	// setup keys only, and a node presenting a token is refused rather than
	// quietly falling back to one.
	OIDC *OIDC
}

// Handle implements Handler.
//
// identity is the ML-DSA-65 public key the node proved possession of during
// the handshake — not a claim from the request body. Everything below derives
// the peer handle from that key rather than from anything the request says,
// so a request cannot ask to be someone else.
func (h *LoginHandler) Handle(ctx context.Context, _, identity, payload []byte) ([]byte, error) {
	req := &proto.KarstLoginRequest{}
	if err := pb.Unmarshal(payload, req); err != nil {
		return nil, status.Error(codes.InvalidArgument, "malformed login request")
	}
	if req.GetMeta() == nil {
		// The business layer derives the peer name and DNS label from the
		// hostname and fails without it; catching it here gives a better error
		// than a nil dereference three layers down.
		return nil, status.Error(codes.FailedPrecondition, "peer system meta is required")
	}

	// Validate before authorization, but do not persist yet. Invalid keys must
	// not create a business-layer peer record; conversely, an authorization
	// failure must not leave an orphan identity or rotate an existing node's
	// data-plane keys (FINDINGS.md #2).
	//
	// The node's PHREATIC keys are recorded only after enrolment because peers
	// cannot handshake without them, and the netmap is how they are distributed
	// (phreatic-v1.md §4).
	keys := node.DataPlaneKeys{
		KemPublicKey: req.GetKemPublicKey(),
		DhPublicKey:  req.GetDhPublicKey(),
	}
	handle, err := node.ValidateRegistration(identity, keys)
	if err != nil {
		if errors.Is(err, node.ErrBadPublicKey) {
			return nil, status.Errorf(codes.InvalidArgument, "data-plane keys: %v", err)
		}
		return nil, fmt.Errorf("validate identity: %w", err)
	}

	// An ID token, when present, decides the user. It is checked *before*
	// LoginPeer and a failure is fatal: falling through to the setup-key path
	// would register the node under no user at all while the operator believes
	// they authenticated as themselves.
	var userID string
	if tok := req.GetJwtToken(); tok != "" {
		userID, err = h.OIDC.authenticate(ctx, handle, tok)
		if err != nil {
			return nil, err
		}
	}

	peer, _, _, _, err := h.Accounts.LoginPeer(ctx, types.PeerLogin{
		// Named for WireGuard by the fork; carries a Karst node handle here.
		// Renaming the field is a forked-code change and therefore a
		// cherry-pick cost, so it is deferred deliberately.
		WireGuardPubKey: handle,
		Meta:            extractMeta(req.GetMeta()),
		SetupKey:        req.GetSetupKey(),
		UserID:          userID,
		ConnectionIP:    connectionIP(ctx),
		ExtraDNSLabels:  req.GetDnsLabels(),
	})
	if err != nil {
		return nil, err
	}

	// Authorization succeeded. It is now safe to create the Karst-owned
	// identity record or rotate its data-plane keys.
	if _, err := h.Nodes.Register(identity, keys); err != nil {
		if errors.Is(err, node.ErrKeyMismatch) {
			return nil, status.Error(codes.PermissionDenied, "identity does not match this handle")
		}
		return nil, fmt.Errorf("register identity: %w", err)
	}

	resp := &proto.KarstLoginResponse{
		NodeId:  []byte(handle),
		PeerIp:  peer.IP.String(),
		DnsName: peer.DNSLabel,
	}
	out, err := pb.Marshal(resp)
	if err != nil {
		return nil, fmt.Errorf("marshal login response: %w", err)
	}
	return out, nil
}

// extractMeta converts the wire message into the business layer's struct.
//
// Only the fields the server actually uses are carried. The rest of
// PeerSystemMeta is telemetry that the fork populates from its own client and
// that a Karst node has no equivalent for yet.
func extractMeta(m *proto.PeerSystemMeta) nbpeer.PeerSystemMeta {
	return nbpeer.PeerSystemMeta{
		Hostname:      m.GetHostname(),
		GoOS:          m.GetGoOS(),
		Kernel:        m.GetKernel(),
		Core:          m.GetCore(),
		Platform:      m.GetPlatform(),
		OS:            m.GetOS(),
		OSVersion:     m.GetOSVersion(),
		KernelVersion: m.GetKernelVersion(),
		WtVersion:     m.GetNetbirdVersion(),
		UIVersion:     m.GetUiVersion(),
	}
}

// connectionIP returns the peer's address, or nil when it cannot be
// determined. The business layer treats nil as "unknown", which is the honest
// answer rather than a fabricated one.
//
// This mirrors the fork's own getRealIP: the address comes from the realip
// interceptor, which is what makes it trustworthy behind a proxy.
func connectionIP(ctx context.Context) net.IP {
	if addr, ok := realip.FromContext(ctx); ok {
		return net.IP(addr.AsSlice())
	}
	return nil
}
