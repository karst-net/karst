// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package control

import (
	"context"
	"errors"
	"fmt"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	pb "google.golang.org/protobuf/proto"

	"github.com/netbirdio/netbird/management/internals/karst/compliance"
	"github.com/netbirdio/netbird/management/internals/karst/node"
	"github.com/netbirdio/netbird/management/internals/karst/policy"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// KindCompliancePermit serves the reserved permit snapshot contract
// (spec/device-compliance-v1.md's "reserved permit wire contract" section,
// #363). This wires the already-tested issuance path onto a real request
// kind for the first time; it does not activate enforcement by itself —
// no running client installs or enforces what it returns yet (that is
// PR2's scope), and no server advertises this kind's capability until
// bootstrap.go wires it.
const KindCompliancePermit byte = 6

// UnconfiguredComplianceRevision is the PolicyRevision a PermitHandler issues
// when Draft is nil, or returns one itself. It is deliberately not empty —
// compliance.ValidatePermitSnapshot requires a nonempty, bounded revision —
// but it names what it is: no persisted admin policy-write API exists yet
// (policy.ComplianceDraft's own doc comment is why), so every snapshot this
// issues without a Draft is compiled from a tenant-scoped draft with zero
// guardrails. A zero-guardrail snapshot is valid and has no enforcement
// effect: unprotected traffic is unconstrained by compliance either way.
const UnconfiguredComplianceRevision = "unconfigured"

// PermitHandler issues KarstCompliancePermitSnapshot from the already-tested
// policy.CompileCompliance, over the authenticated control channel. It
// receives the identity Service's handshake already authenticated, exactly
// like ComplianceHandler.
type PermitHandler struct {
	Store *compliance.Store
	Peers PeerLister

	// Draft supplies the current compliance draft and its revision for a
	// tenant. A nil Draft, or TenantID == "", means "no persisted draft yet":
	// the handler compiles against an empty draft (zero guardrails, revision
	// UnconfiguredComplianceRevision) rather than refusing the request —
	// matching ComplianceIngestion's own "advertise and serve, even before
	// there is anything real behind it" shape. This is the seam a future
	// persisted admin policy-write API plugs into without reshaping the
	// handler.
	Draft func(ctx context.Context, tenantID string) (draft policy.ComplianceDraft, revision string, err error)

	Now func() time.Time // nil uses the server clock
}

func (h *PermitHandler) now() time.Time {
	if h.Now != nil {
		return h.Now().UTC()
	}
	return time.Now().UTC()
}

func (h *PermitHandler) Handle(ctx context.Context, _, identity, payload []byte) ([]byte, error) {
	req := &proto.KarstCompliancePermitRequest{}
	if err := pb.Unmarshal(payload, req); err != nil {
		return nil, status.Error(codes.InvalidArgument, "malformed compliance permit request")
	}
	if err := compliance.ValidatePermitRequest(req); err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid compliance permit request")
	}
	if h.Store == nil || h.Peers == nil {
		return nil, status.Error(codes.Unimplemented, "compliance permits are unavailable")
	}

	handle := node.Handle(identity)
	self, err := h.Peers.GetPeerByPeerPubKey(ctx, handle)
	if err != nil || self == nil || self.Key != handle || self.AccountID == "" || self.ID == "" {
		return nil, status.Error(codes.NotFound, "node is not registered")
	}
	now := h.now()

	draft := policy.ComplianceDraft{TenantID: self.AccountID}
	revision := UnconfiguredComplianceRevision
	if h.Draft != nil {
		d, r, err := h.Draft(ctx, self.AccountID)
		if err != nil {
			return nil, status.Error(codes.Internal, "compliance: load draft")
		}
		if d.TenantID != "" {
			if d.TenantID != self.AccountID {
				return nil, status.Error(codes.Internal, "compliance: draft tenant mismatch")
			}
			draft, revision = d, r
		}
	}
	if revision == "" {
		revision = UnconfiguredComplianceRevision
	}

	peers, err := h.Peers.GetPeersFromAccount(ctx, self.AccountID, "", "")
	if err != nil {
		return nil, status.Error(codes.Internal, "compliance: load roster")
	}

	devices := make([]policy.ComplianceDevice, 0, len(peers))
	generations := make(map[string]uint64, len(peers))
	deviceIDs := make(map[string]string, len(peers))
	for _, p := range peers {
		subject := compliance.Subject{TenantID: self.AccountID, DeviceID: p.ID}
		var evidence *compliance.Evidence
		accepted, err := h.Store.Latest(ctx, subject, p.Key, now)
		switch {
		case err == nil:
			e := accepted.Evidence
			evidence = &e
			generations[p.Key] = accepted.Generation
		case errors.Is(err, compliance.ErrNoEvidence), errors.Is(err, compliance.ErrNotEnrolled), errors.Is(err, compliance.ErrInvalidSubject):
			// No usable evidence yet: compliance.Evaluate treats a nil
			// Evidence as unknown/nonpassing, never as an error.
		default:
			return nil, status.Error(codes.Internal, "compliance: load evidence")
		}
		deviceIDs[p.Key] = p.ID
		devices = append(devices, policy.ComplianceDevice{
			Node:     policy.Node{Handle: p.Key, Addresses: allowedIPsOf(p)},
			Subject:  subject,
			Evidence: evidence,
		})
	}

	// An empty Document is sufficient today: CompileCompliance only calls
	// Document.matches (which needs real group definitions) for a guardrail
	// resource selector that isn't a CIDR or "*", and an empty draft has no
	// guardrails to compile at all. A future persisted draft referencing
	// real groups needs the account's real identity policy document here —
	// deliberately deferred rather than guessed at before that API exists.
	doc := &policy.Document{}
	compiled, err := doc.CompileCompliance(draft, devices, handle, nil, now)
	if err != nil {
		return nil, status.Error(codes.Internal, fmt.Sprintf("compliance: compile: %v", err))
	}

	snapshot := &proto.KarstCompliancePermitSnapshot{
		SchemaVersion:    1,
		RequestNonce:     req.Nonce,
		TenantId:         self.AccountID,
		EnforcerDeviceId: self.ID,
		EnforcerHandle:   handle,
		PolicyRevision:   revision,
		ValidForMillis:   compliance.PermitLifetimeMillis,
		Ingress:          permitGates(compiled.Ingress, now, generations, deviceIDs),
		Egress:           permitGates(compiled.Egress, now, generations, deviceIDs),
	}

	binding := compliance.PermitBinding{
		Subject:        compliance.Subject{TenantID: self.AccountID, DeviceID: self.ID},
		Handle:         handle,
		PolicyRevision: revision,
		Nonce:          req.Nonce,
	}
	if err := compliance.ValidatePermitSnapshot(snapshot, binding); err != nil {
		// The compiled snapshot must already satisfy the contract it will be
		// validated against on the receiving end; failing here (rather than
		// shipping something the client would reject) is a server bug to
		// surface, not a client-facing denial.
		return nil, status.Error(codes.Internal, fmt.Sprintf("compliance: issued an invalid permit snapshot: %v", err))
	}
	return pb.Marshal(snapshot)
}

// permitGates converts the internal diagnostic gates policy.CompileCompliance
// produces into the wire contract, filling in each source's device ID and
// evidence generation from the roster this request compiled against, and
// each source's own validity budget from its remaining evidence freshness —
// never more than compliance.PermitLifetimeMillis. A source whose evidence
// deadline has already passed by now is dropped, not sent with a zero or
// negative budget; an empty result is still a valid mandatory denial, never a
// dropped gate.
func permitGates(gates []policy.ComplianceGate, now time.Time, generations map[string]uint64, deviceIDs map[string]string) []*proto.KarstCompliancePermitGate {
	out := make([]*proto.KarstCompliancePermitGate, 0, len(gates))
	for _, gate := range gates {
		cidrs := make([]string, 0, len(gate.Destinations))
		for _, prefix := range gate.Destinations {
			cidrs = append(cidrs, prefix.String())
		}
		sources := make([]*proto.KarstComplianceSourcePermit, 0, len(gate.Sources))
		for _, decision := range gate.Sources {
			budget := permitBudgetMillis(decision.ValidUntil, now)
			generation := generations[decision.Handle]
			if budget == 0 || generation == 0 {
				// Defensive: CompileCompliance only adds a source once its
				// evaluation passed, which requires fresh accepted evidence
				// and therefore a positive generation and a future deadline.
				// Either failing here means the roster changed between
				// compiling and converting; fail closed by omitting the
				// source rather than shipping an EvidenceGeneration of 0,
				// which compliance.ValidatePermitSnapshot would refuse.
				continue
			}
			sources = append(sources, &proto.KarstComplianceSourcePermit{
				Handle:             decision.Handle,
				DeviceId:           deviceIDs[decision.Handle],
				EvidenceGeneration: generation,
				ValidForMillis:     budget,
			})
		}
		out = append(out, &proto.KarstCompliancePermitGate{
			GuardrailId:      gate.GuardrailID,
			DestinationCidrs: cidrs,
			Protocol:         permitProtocol(gate.Protocol),
			Ports:            &proto.KarstPortRange{First: uint32(gate.Ports.First), Last: uint32(gate.Ports.Last)},
			Sources:          sources,
		})
	}
	return out
}

func permitBudgetMillis(deadline, now time.Time) uint32 {
	remaining := deadline.Sub(now)
	if remaining <= 0 {
		return 0
	}
	if remaining > compliance.PermitLifetimeMillis*time.Millisecond {
		return compliance.PermitLifetimeMillis
	}
	return uint32(remaining.Milliseconds())
}

func permitProtocol(protocol string) proto.KarstCompliancePermitGate_Protocol {
	switch protocol {
	case "tcp":
		return proto.KarstCompliancePermitGate_TCP
	case "udp":
		return proto.KarstCompliancePermitGate_UDP
	default:
		return proto.KarstCompliancePermitGate_ANY
	}
}
