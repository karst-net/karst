// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package control

import (
	"context"
	"errors"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	pb "google.golang.org/protobuf/proto"

	"github.com/netbirdio/netbird/management/internals/karst/compliance"
	"github.com/netbirdio/netbird/management/internals/karst/node"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// KindCompliance is ingestion only; it conveys no enforcement capability.
const KindCompliance byte = 5
const maxComplianceRequest = 4096

// ComplianceHandler receives the identity authenticated by Service's handshake.
// Wire reports cannot select tenant/device, provenance or server receipt time.
type ComplianceHandler struct {
	Store *compliance.Store
	Peers interface {
		GetPeerByPeerPubKey(context.Context, string) (*nbpeer.Peer, error)
	}
	Now func() time.Time // nil uses the server clock
}

func (h *ComplianceHandler) Handle(ctx context.Context, _, identity, payload []byte) ([]byte, error) {
	if len(payload) > maxComplianceRequest {
		return nil, status.Error(codes.InvalidArgument, "compliance request too large")
	}
	req := &proto.KarstComplianceRequest{}
	if err := pb.Unmarshal(payload, req); err != nil {
		return nil, status.Error(codes.InvalidArgument, "malformed compliance request")
	}
	if req.SchemaVersion != 1 {
		return nil, status.Error(codes.InvalidArgument, "unsupported compliance schema")
	}
	if h.Store == nil || h.Peers == nil {
		return nil, status.Error(codes.Unimplemented, "compliance ingestion is unavailable")
	}
	handle := node.Handle(identity)
	peer, err := h.Peers.GetPeerByPeerPubKey(ctx, handle)
	if err != nil || peer == nil || peer.Key != handle || peer.AccountID == "" || peer.ID == "" {
		return nil, status.Error(codes.NotFound, "node is not registered")
	}
	subject := compliance.Subject{TenantID: peer.AccountID, DeviceID: peer.ID}
	now := time.Now().UTC()
	if h.Now != nil {
		now = h.Now().UTC()
	}
	resp := &proto.KarstComplianceResponse{SchemaVersion: 1}
	switch op := req.Operation.(type) {
	case *proto.KarstComplianceRequest_Challenge:
		if !op.Challenge {
			return nil, status.Error(codes.InvalidArgument, "challenge must be requested")
		}
		challenge, err := h.Store.Issue(ctx, subject, handle, now)
		if err != nil {
			return nil, complianceStatus(err)
		}
		resp.Challenge = challenge.Token
		resp.ValidForSeconds = uint32(compliance.ChallengeLifetime / time.Second)
	case *proto.KarstComplianceRequest_Report:
		if op.Report == nil {
			return nil, status.Error(codes.InvalidArgument, "missing compliance report")
		}
		r := op.Report
		report := compliance.Report{CollectorVersion: r.CollectorVersion, Platform: compliance.Platform(r.Platform), Distribution: r.Distribution, ClientVersion: complianceObservation(r.ClientVersion), OSVersion: complianceObservation(r.OsVersion)}
		if err := h.Store.Submit(ctx, subject, handle, r.Challenge, report, now); err != nil {
			return nil, complianceStatus(err)
		}
		resp.Accepted = true
	default:
		return nil, status.Error(codes.InvalidArgument, "missing compliance operation")
	}
	return pb.Marshal(resp)
}

func complianceObservation(o *proto.KarstComplianceObservation) compliance.Observation {
	if o == nil {
		return compliance.Observation{}
	}
	state := compliance.ObservationStatus("invalid")
	switch o.Status {
	case proto.KarstComplianceObservation_MISSING:
		state = ""
	case proto.KarstComplianceObservation_COLLECTED:
		state = compliance.Collected
	case proto.KarstComplianceObservation_UNSUPPORTED:
		state = compliance.NotSupported
	case proto.KarstComplianceObservation_COLLECTION_ERROR:
		state = compliance.CollectionError
	}
	return compliance.Observation{Status: state, Version: o.Version}
}

func complianceStatus(err error) error {
	switch {
	case errors.Is(err, compliance.ErrChallenge):
		return status.Error(codes.FailedPrecondition, "compliance challenge invalid, expired or consumed")
	case errors.Is(err, compliance.ErrNotEnrolled):
		return status.Error(codes.NotFound, "node is not registered")
	case errors.Is(err, compliance.ErrInvalidReport):
		return status.Error(codes.InvalidArgument, "invalid compliance report")
	default:
		return status.Error(codes.Internal, "compliance storage failed")
	}
}
