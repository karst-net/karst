// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package control_test

import (
	"context"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	pb "google.golang.org/protobuf/proto"

	"github.com/netbirdio/netbird/management/internals/karst/compliance"
	"github.com/netbirdio/netbird/management/internals/karst/control"
	"github.com/netbirdio/netbird/management/internals/karst/identity"
	"github.com/netbirdio/netbird/management/internals/karst/node"
	"github.com/netbirdio/netbird/management/internals/karst/policy"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/shared/management/proto"
)

func permitRequestPayload(t *testing.T, nonce []byte) []byte {
	t.Helper()
	b, err := pb.Marshal(&proto.KarstCompliancePermitRequest{SchemaVersion: 1, Nonce: nonce})
	require.NoError(t, err)
	return b
}

func fixedNonce(seed byte) []byte {
	nonce := make([]byte, 32)
	for i := range nonce {
		nonce[i] = seed + byte(i)
	}
	return nonce
}

// TestPermitHandlerUnconfiguredDraftIssuesAnEmptyValidSnapshot exercises the
// shape a tenant that has never written a persisted ComplianceDraft gets (no
// Draft func wired at all, the same as a real deployment before any admin
// configures a guardrail): the handler serves a structurally valid,
// zero-guardrail snapshot. It proves the wire path end to end with zero
// enforcement effect, not that any guardrail works.
func TestPermitHandlerUnconfiguredDraftIssuesAnEmptyValidSnapshot(t *testing.T) {
	_, store := complianceDB(t)
	key, err := identity.Generate()
	require.NoError(t, err)
	handle := node.Handle(key.Public())
	peer := &nbpeer.Peer{ID: "device-a", AccountID: "account-a", Key: handle, IP: netip.MustParseAddr("100.64.0.1")}
	peers := &fakePeers{byKey: map[string]*nbpeer.Peer{handle: peer}, list: []*nbpeer.Peer{peer}}
	h := &control.PermitHandler{Store: store, Peers: peers}
	nonce := fixedNonce(0)

	out, err := h.Handle(context.Background(), nil, key.Public(), permitRequestPayload(t, nonce))
	require.NoError(t, err)
	snap := &proto.KarstCompliancePermitSnapshot{}
	require.NoError(t, pb.Unmarshal(out, snap))

	require.Equal(t, uint32(1), snap.SchemaVersion)
	require.Equal(t, nonce, snap.RequestNonce)
	require.Equal(t, "account-a", snap.TenantId)
	require.Equal(t, "device-a", snap.EnforcerDeviceId)
	require.Equal(t, handle, snap.EnforcerHandle)
	require.Equal(t, control.UnconfiguredComplianceRevision, snap.PolicyRevision)
	require.Empty(t, snap.Ingress)
	require.Empty(t, snap.Egress)
}

// TestPermitHandlerCompilesAGuardrailIntoAWireSnapshot proves the dormant
// permit protocol actually carries a real compiled guardrail end to end: a
// test-only Draft (there is no persisted admin policy-write API to source
// one from in production yet) with one guardrail protecting the enforcing
// device's own address, two devices with passing evidence, and a third with
// none. The wire snapshot must come back structurally valid per
// compliance.ValidatePermitSnapshot and name only the two passing devices,
// each with its real device ID and evidence generation.
func TestPermitHandlerCompilesAGuardrailIntoAWireSnapshot(t *testing.T) {
	db, store := complianceDB(t)
	clock := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)

	keyA, err := identity.Generate()
	require.NoError(t, err)
	keyB, err := identity.Generate()
	require.NoError(t, err)
	keyC, err := identity.Generate()
	require.NoError(t, err)
	handleA, handleB, handleC := node.Handle(keyA.Public()), node.Handle(keyB.Public()), node.Handle(keyC.Public())

	peerA := &nbpeer.Peer{ID: "device-a", AccountID: "tenant-a", Key: handleA, IP: netip.MustParseAddr("100.64.0.1")}
	peerB := &nbpeer.Peer{ID: "device-b", AccountID: "tenant-a", Key: handleB, IP: netip.MustParseAddr("100.64.0.2")}
	peerC := &nbpeer.Peer{ID: "device-c", AccountID: "tenant-a", Key: handleC, IP: netip.MustParseAddr("100.64.0.3")}
	peers := &fakePeers{
		byKey: map[string]*nbpeer.Peer{handleA: peerA, handleB: peerB, handleC: peerC},
		list:  []*nbpeer.Peer{peerA, peerB, peerC},
	}

	submit := func(peer *nbpeer.Peer, handle string) {
		require.NoError(t, db.Create(&complianceEnrollment{ID: peer.ID, AccountID: peer.AccountID, Key: handle}).Error)
		subject := compliance.Subject{TenantID: peer.AccountID, DeviceID: peer.ID}
		challenge, err := store.Issue(context.Background(), subject, handle, clock)
		require.NoError(t, err)
		require.NoError(t, store.Submit(context.Background(), subject, handle, challenge.Token, compliance.Report{
			CollectorVersion: "1.0.0", Platform: compliance.Linux, Distribution: "ubuntu",
			ClientVersion: compliance.Observation{Status: compliance.Collected, Version: "1.0.0"},
		}, clock))
	}
	submit(peerA, handleA)
	submit(peerB, handleB)
	// peerC never reports: it must be excluded from passing sources, never
	// cause an error, and never silently drop the gate itself.

	draft := policy.ComplianceDraft{
		TenantID: "tenant-a",
		RequirementSets: map[string][]compliance.Requirement{
			"client": {{ID: "client-version", Kind: compliance.MinimumClientVersion, MinimumVersion: "1.0.0", Provenance: compliance.SelfReported}},
		},
		Guardrails: []policy.ComplianceGuardrail{{
			ID:              "guardrail-1",
			Resource:        policy.ComplianceResource{Selector: "100.64.0.1/32", Protocol: "tcp", Ports: policy.PortRange{First: 443, Last: 443}},
			RequirementSets: []string{"client"},
		}},
	}
	h := &control.PermitHandler{
		Store: store, Peers: peers,
		Draft: func(context.Context, string) (policy.ComplianceDraft, string, error) { return draft, "rev-1", nil },
		Now:   func() time.Time { return clock },
	}

	nonce := fixedNonce(7)
	out, err := h.Handle(context.Background(), nil, keyA.Public(), permitRequestPayload(t, nonce))
	require.NoError(t, err)
	snap := &proto.KarstCompliancePermitSnapshot{}
	require.NoError(t, pb.Unmarshal(out, snap))

	require.NoError(t, compliance.ValidatePermitSnapshot(snap, compliance.PermitBinding{
		Subject: compliance.Subject{TenantID: "tenant-a", DeviceID: "device-a"}, Handle: handleA, PolicyRevision: "rev-1", Nonce: nonce,
	}))
	require.Equal(t, "rev-1", snap.PolicyRevision)
	require.Len(t, snap.Ingress, 1)
	gate := snap.Ingress[0]
	require.Equal(t, "guardrail-1", gate.GuardrailId)
	require.Equal(t, []string{"100.64.0.1/32"}, gate.DestinationCidrs)
	require.Equal(t, proto.KarstCompliancePermitGate_TCP, gate.Protocol)
	require.Equal(t, uint32(443), gate.Ports.First)
	require.Equal(t, uint32(443), gate.Ports.Last)
	require.Len(t, gate.Sources, 2)
	byHandle := map[string]*proto.KarstComplianceSourcePermit{}
	for _, source := range gate.Sources {
		byHandle[source.Handle] = source
	}
	require.Contains(t, byHandle, handleA)
	require.Contains(t, byHandle, handleB)
	require.NotContains(t, byHandle, handleC)
	require.Equal(t, "device-a", byHandle[handleA].DeviceId)
	require.Equal(t, uint64(1), byHandle[handleA].EvidenceGeneration)
	require.Equal(t, uint32(compliance.PermitLifetimeMillis), byHandle[handleA].ValidForMillis)
	require.Equal(t, "device-b", byHandle[handleB].DeviceId)
	require.Equal(t, uint64(1), byHandle[handleB].EvidenceGeneration)
	// Egress is empty: the guardrail's resource is a bare destination CIDR,
	// never the enforcing device's own source decision for itself as a CIDR
	// (CompileCompliance only populates Egress when the resource also
	// resolves to an owned/selector match for the target).
}

// TestPermitHandlerReflectsAPersistedComplianceDraftWrite proves the real
// production wiring end to end (#363 PR5), not a hand-rolled test closure
// like TestPermitHandlerCompilesAGuardrailIntoAWireSnapshot above uses: a
// draft written through policy.ComplianceDraftStore.Write (the same store
// PUT /karst/v1/compliance/draft calls into) reaches PermitHandler.Handle
// via CurrentDraft, both for the device whose request triggered the test
// and for a second device enrolling afterward with no further write -- the
// store, not a per-call closure, is what Draft actually reads.
func TestPermitHandlerReflectsAPersistedComplianceDraftWrite(t *testing.T) {
	db, store := complianceDB(t)
	draftStore, err := policy.NewComplianceDraftStore(db)
	require.NoError(t, err)
	clock := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)

	keyA, err := identity.Generate()
	require.NoError(t, err)
	handleA := node.Handle(keyA.Public())
	peerA := &nbpeer.Peer{ID: "device-a", AccountID: "tenant-a", Key: handleA, IP: netip.MustParseAddr("100.64.0.1")}
	peers := &fakePeers{byKey: map[string]*nbpeer.Peer{handleA: peerA}, list: []*nbpeer.Peer{peerA}}

	require.NoError(t, db.Create(&complianceEnrollment{ID: peerA.ID, AccountID: peerA.AccountID, Key: handleA}).Error)
	subject := compliance.Subject{TenantID: peerA.AccountID, DeviceID: peerA.ID}
	challenge, err := store.Issue(context.Background(), subject, handleA, clock)
	require.NoError(t, err)
	require.NoError(t, store.Submit(context.Background(), subject, handleA, challenge.Token, compliance.Report{
		CollectorVersion: "1.0.0", Platform: compliance.Linux, Distribution: "ubuntu",
		ClientVersion: compliance.Observation{Status: compliance.Collected, Version: "1.0.0"},
	}, clock))

	draft := policy.ComplianceDraft{
		TenantID: "tenant-a",
		RequirementSets: map[string][]compliance.Requirement{
			"client": {{ID: "client-version", Kind: compliance.MinimumClientVersion, MinimumVersion: "1.0.0", Provenance: compliance.SelfReported}},
		},
		Guardrails: []policy.ComplianceGuardrail{{
			ID:              "guardrail-1",
			Resource:        policy.ComplianceResource{Selector: "100.64.0.1/32", Protocol: "tcp", Ports: policy.PortRange{First: 443, Last: 443}},
			RequirementSets: []string{"client"},
		}},
	}
	written, err := draftStore.Write(policy.WithAccount(context.Background(), "tenant-a"), draft, "admin-a", 0)
	require.NoError(t, err)

	h := &control.PermitHandler{
		Store: store, Peers: peers,
		Draft: draftStore.CurrentDraft,
		Now:   func() time.Time { return clock },
	}
	nonce := fixedNonce(9)
	out, err := h.Handle(context.Background(), nil, keyA.Public(), permitRequestPayload(t, nonce))
	require.NoError(t, err)
	snap := &proto.KarstCompliancePermitSnapshot{}
	require.NoError(t, pb.Unmarshal(out, snap))

	wantRevision := strconv.FormatUint(written.Version, 10)
	require.NoError(t, compliance.ValidatePermitSnapshot(snap, compliance.PermitBinding{
		Subject: subject, Handle: handleA, PolicyRevision: wantRevision, Nonce: nonce,
	}))
	require.Equal(t, wantRevision, snap.PolicyRevision)
	require.Len(t, snap.Ingress, 1)
	require.Equal(t, "guardrail-1", snap.Ingress[0].GuardrailId)
	require.Len(t, snap.Ingress[0].Sources, 1)
	require.Equal(t, handleA, snap.Ingress[0].Sources[0].Handle)

	// A second device enrolling later, with no further write, still gets the
	// same persisted draft via CurrentDraft.
	keyB, err := identity.Generate()
	require.NoError(t, err)
	handleB := node.Handle(keyB.Public())
	peerB := &nbpeer.Peer{ID: "device-b", AccountID: "tenant-a", Key: handleB, IP: netip.MustParseAddr("100.64.0.2")}
	peers.byKey[handleB] = peerB
	peers.list = append(peers.list, peerB)
	out2, err := h.Handle(context.Background(), nil, keyB.Public(), permitRequestPayload(t, fixedNonce(10)))
	require.NoError(t, err)
	snap2 := &proto.KarstCompliancePermitSnapshot{}
	require.NoError(t, pb.Unmarshal(out2, snap2))
	require.Equal(t, wantRevision, snap2.PolicyRevision)
}

// TestPermitHandlerResolvesGroupSelectorsAgainstTheRealIdentityDocument
// defends #363 PR5's one behavior change beyond adding a write API:
// compliance_permits.go used to hardcode an empty *policy.Document, which
// made a group: guardrail selector permanently fail to match (Document.
// Groups was always empty) regardless of what the account's real identity
// document said. With Policy/PolicyStore wired, a group guardrail must
// resolve against the real document and compile a gate naming the member
// device.
func TestPermitHandlerResolvesGroupSelectorsAgainstTheRealIdentityDocument(t *testing.T) {
	db, store := complianceDB(t)
	clock := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)

	keyA, err := identity.Generate()
	require.NoError(t, err)
	handleA := node.Handle(keyA.Public())
	peerA := &nbpeer.Peer{ID: "device-a", AccountID: "tenant-a", Key: handleA, UserID: "operator", IP: netip.MustParseAddr("100.64.0.5")}
	peers := &fakePeers{byKey: map[string]*nbpeer.Peer{handleA: peerA}, list: []*nbpeer.Peer{peerA}}

	require.NoError(t, db.Create(&complianceEnrollment{ID: peerA.ID, AccountID: peerA.AccountID, Key: handleA}).Error)
	subject := compliance.Subject{TenantID: "tenant-a", DeviceID: "device-a"}
	challenge, err := store.Issue(context.Background(), subject, handleA, clock)
	require.NoError(t, err)
	require.NoError(t, store.Submit(context.Background(), subject, handleA, challenge.Token, compliance.Report{
		CollectorVersion: "1.0.0", Platform: compliance.Linux, Distribution: "ubuntu",
		ClientVersion: compliance.Observation{Status: compliance.Collected, Version: "1.0.0"},
	}, clock))

	doc := &policy.Document{Groups: map[string][]string{"group:ops": {"operator"}}}
	draft := policy.ComplianceDraft{
		TenantID: "tenant-a",
		RequirementSets: map[string][]compliance.Requirement{
			"client": {{ID: "client-version", Kind: compliance.MinimumClientVersion, MinimumVersion: "1.0.0", Provenance: compliance.SelfReported}},
		},
		Guardrails: []policy.ComplianceGuardrail{{
			ID:              "ops-guardrail",
			Resource:        policy.ComplianceResource{Selector: "group:ops", Protocol: policy.Wildcard, Ports: policy.AllPorts},
			RequirementSets: []string{"client"},
		}},
	}
	h := &control.PermitHandler{
		Store: store, Peers: peers,
		Draft:  func(context.Context, string) (policy.ComplianceDraft, string, error) { return draft, "rev-1", nil },
		Policy: doc,
		Now:    func() time.Time { return clock },
	}
	out, err := h.Handle(context.Background(), nil, keyA.Public(), permitRequestPayload(t, fixedNonce(11)))
	require.NoError(t, err)
	snap := &proto.KarstCompliancePermitSnapshot{}
	require.NoError(t, pb.Unmarshal(out, snap))

	require.Len(t, snap.Ingress, 1)
	require.Equal(t, "ops-guardrail", snap.Ingress[0].GuardrailId)
	require.Len(t, snap.Ingress[0].Sources, 1)
	require.Equal(t, handleA, snap.Ingress[0].Sources[0].Handle)
}

// TestPermitHandlerDraftTenantMismatchFailsClosed defends the one place a
// future persisted Draft source could leak another tenant's policy across a
// connection: the handler must refuse rather than compile a mismatched draft.
func TestPermitHandlerDraftTenantMismatchFailsClosed(t *testing.T) {
	_, store := complianceDB(t)
	key, err := identity.Generate()
	require.NoError(t, err)
	handle := node.Handle(key.Public())
	peer := &nbpeer.Peer{ID: "device-a", AccountID: "tenant-a", Key: handle, IP: netip.MustParseAddr("100.64.0.1")}
	peers := &fakePeers{byKey: map[string]*nbpeer.Peer{handle: peer}, list: []*nbpeer.Peer{peer}}
	h := &control.PermitHandler{
		Store: store, Peers: peers,
		Draft: func(context.Context, string) (policy.ComplianceDraft, string, error) {
			return policy.ComplianceDraft{TenantID: "someone-elses-tenant"}, "rev-1", nil
		},
	}
	_, err = h.Handle(context.Background(), nil, key.Public(), permitRequestPayload(t, fixedNonce(1)))
	require.Equal(t, codes.Internal, status.Code(err))
}

func TestPermitHandlerInputValidation(t *testing.T) {
	_, store := complianceDB(t)
	key, err := identity.Generate()
	require.NoError(t, err)
	handle := node.Handle(key.Public())
	peer := &nbpeer.Peer{ID: "device-a", AccountID: "tenant-a", Key: handle, IP: netip.MustParseAddr("100.64.0.1")}
	peers := &fakePeers{byKey: map[string]*nbpeer.Peer{handle: peer}, list: []*nbpeer.Peer{peer}}
	h := &control.PermitHandler{Store: store, Peers: peers}

	tests := []struct {
		name    string
		payload []byte
	}{
		{"invalid protobuf", []byte{0xff}},
		{"empty", nil},
		{"unsupported schema", mustMarshalPermitRequest(t, &proto.KarstCompliancePermitRequest{SchemaVersion: 2, Nonce: fixedNonce(0)})},
		{"short nonce", mustMarshalPermitRequest(t, &proto.KarstCompliancePermitRequest{SchemaVersion: 1, Nonce: []byte{1, 2, 3}})},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := h.Handle(context.Background(), nil, key.Public(), tt.payload)
			require.Equal(t, codes.InvalidArgument, status.Code(err))
		})
	}

	t.Run("unregistered node", func(t *testing.T) {
		other, err := identity.Generate()
		require.NoError(t, err)
		_, err = h.Handle(context.Background(), nil, other.Public(), permitRequestPayload(t, fixedNonce(0)))
		require.Equal(t, codes.NotFound, status.Code(err))
	})

	t.Run("nil store is unimplemented", func(t *testing.T) {
		unconfigured := &control.PermitHandler{Peers: peers}
		_, err := unconfigured.Handle(context.Background(), nil, key.Public(), permitRequestPayload(t, fixedNonce(0)))
		require.Equal(t, codes.Unimplemented, status.Code(err))
	})
}

func mustMarshalPermitRequest(t *testing.T, r *proto.KarstCompliancePermitRequest) []byte {
	t.Helper()
	b, err := pb.Marshal(r)
	require.NoError(t, err)
	return b
}
