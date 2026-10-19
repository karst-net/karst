// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package compliance_test

import (
	"bytes"
	"encoding/base64"
	"testing"

	"github.com/netbirdio/netbird/management/internals/karst/compliance"
	"github.com/netbirdio/netbird/shared/management/proto"
	"github.com/stretchr/testify/require"
	pb "google.golang.org/protobuf/proto"
)

func permitFixture() (*proto.KarstCompliancePermitSnapshot, compliance.PermitBinding) {
	binding := compliance.PermitBinding{Subject: compliance.Subject{TenantID: "tenant-a", DeviceID: "device-a"}, Handle: base64.StdEncoding.EncodeToString(make([]byte, 32)), PolicyRevision: "revision-42", Nonce: bytes.Repeat([]byte{0x42}, 32)}
	gate := &proto.KarstCompliancePermitGate{GuardrailId: "production", DestinationCidrs: []string{"10.99.0.0/24", "fd00:99::/64"}, Protocol: proto.KarstCompliancePermitGate_TCP, Ports: &proto.KarstPortRange{First: 443, Last: 443}, Sources: []*proto.KarstComplianceSourcePermit{{Handle: binding.Handle, DeviceId: binding.Subject.DeviceID, EvidenceGeneration: 7, ValidForMillis: 119000}}}
	return &proto.KarstCompliancePermitSnapshot{SchemaVersion: 1, RequestNonce: append([]byte{}, binding.Nonce...), TenantId: binding.Subject.TenantID, EnforcerDeviceId: binding.Subject.DeviceID, EnforcerHandle: binding.Handle, PolicyRevision: binding.PolicyRevision, ValidForMillis: 120000, Ingress: []*proto.KarstCompliancePermitGate{gate}, Egress: []*proto.KarstCompliancePermitGate{pb.Clone(gate).(*proto.KarstCompliancePermitGate)}}, binding
}

func TestPermitContractBindingAndFailClosedValidation(t *testing.T) {
	valid, binding := permitFixture()
	require.NoError(t, compliance.ValidatePermitRequest(&proto.KarstCompliancePermitRequest{SchemaVersion: 1, Nonce: binding.Nonce}))
	require.NoError(t, compliance.ValidatePermitSnapshot(valid, binding))
	for _, request := range []*proto.KarstCompliancePermitRequest{nil, {}, {SchemaVersion: 2, Nonce: binding.Nonce}, {SchemaVersion: 1, Nonce: binding.Nonce[:31]}} {
		require.Error(t, compliance.ValidatePermitRequest(request))
	}
	require.Error(t, compliance.ValidatePermitSnapshot(nil, binding))
	for _, tc := range []struct {
		name   string
		change func(*proto.KarstCompliancePermitSnapshot)
	}{
		{"unknown schema", func(s *proto.KarstCompliancePermitSnapshot) { s.SchemaVersion = 2 }},
		{"old nonce", func(s *proto.KarstCompliancePermitSnapshot) { s.RequestNonce[0] ^= 1 }},
		{"wrong tenant", func(s *proto.KarstCompliancePermitSnapshot) { s.TenantId = "tenant-b" }},
		{"wrong device", func(s *proto.KarstCompliancePermitSnapshot) { s.EnforcerDeviceId = "device-b" }},
		{"wrong handle", func(s *proto.KarstCompliancePermitSnapshot) { s.EnforcerHandle = "*" }},
		{"old policy", func(s *proto.KarstCompliancePermitSnapshot) { s.PolicyRevision = "revision-41" }},
		{"zero validity", func(s *proto.KarstCompliancePermitSnapshot) { s.ValidForMillis = 0 }},
		{"long validity", func(s *proto.KarstCompliancePermitSnapshot) { s.ValidForMillis = 120001 }},
		{"nil gate", func(s *proto.KarstCompliancePermitSnapshot) { s.Ingress[0] = nil }},
		{"duplicate gate", func(s *proto.KarstCompliancePermitSnapshot) { s.Ingress = append(s.Ingress, s.Ingress[0]) }},
		{"missing guardrail", func(s *proto.KarstCompliancePermitSnapshot) { s.Ingress[0].GuardrailId = "" }},
		{"unspecified protocol", func(s *proto.KarstCompliancePermitSnapshot) { s.Ingress[0].Protocol = 0 }},
		{"unknown protocol", func(s *proto.KarstCompliancePermitSnapshot) { s.Ingress[0].Protocol = 99 }},
		{"missing ports", func(s *proto.KarstCompliancePermitSnapshot) { s.Ingress[0].Ports = nil }},
		{"reversed ports", func(s *proto.KarstCompliancePermitSnapshot) { s.Ingress[0].Ports.First = 444 }},
		{"overflow ports", func(s *proto.KarstCompliancePermitSnapshot) { s.Ingress[0].Ports.Last = 65536 }},
		{"missing destinations", func(s *proto.KarstCompliancePermitSnapshot) { s.Ingress[0].DestinationCidrs = nil }},
		{"malformed cidr", func(s *proto.KarstCompliancePermitSnapshot) { s.Ingress[0].DestinationCidrs = []string{"10.99.0.0/99"} }},
		{"unmasked cidr", func(s *proto.KarstCompliancePermitSnapshot) { s.Ingress[0].DestinationCidrs = []string{"10.99.0.1/24"} }},
		{"mapped cidr", func(s *proto.KarstCompliancePermitSnapshot) {
			s.Ingress[0].DestinationCidrs = []string{"::ffff:10.99.0.0/120"}
		}},
		{"duplicate cidr", func(s *proto.KarstCompliancePermitSnapshot) {
			s.Ingress[0].DestinationCidrs = append(s.Ingress[0].DestinationCidrs, "10.99.0.0/24")
		}},
		{"nil source", func(s *proto.KarstCompliancePermitSnapshot) { s.Ingress[0].Sources[0] = nil }},
		{"wildcard source", func(s *proto.KarstCompliancePermitSnapshot) { s.Ingress[0].Sources[0].Handle = "*" }},
		{"missing source device", func(s *proto.KarstCompliancePermitSnapshot) { s.Ingress[0].Sources[0].DeviceId = "" }},
		{"unknown generation", func(s *proto.KarstCompliancePermitSnapshot) { s.Ingress[0].Sources[0].EvidenceGeneration = 0 }},
		{"source zero validity", func(s *proto.KarstCompliancePermitSnapshot) { s.Ingress[0].Sources[0].ValidForMillis = 0 }},
		{"source outlives snapshot", func(s *proto.KarstCompliancePermitSnapshot) { s.Ingress[0].Sources[0].ValidForMillis = 120001 }},
		{"duplicate source", func(s *proto.KarstCompliancePermitSnapshot) {
			s.Ingress[0].Sources = append(s.Ingress[0].Sources, s.Ingress[0].Sources[0])
		}},
		{"inconsistent generation", func(s *proto.KarstCompliancePermitSnapshot) { s.Ingress[0].Sources[0].EvidenceGeneration++ }},
		{"inconsistent enrollment", func(s *proto.KarstCompliancePermitSnapshot) { s.Ingress[0].Sources[0].DeviceId = "device-b" }},
		{"foreign egress", func(s *proto.KarstCompliancePermitSnapshot) {
			s.Egress[0].Sources[0].Handle = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
			s.Egress[0].Sources[0].DeviceId = "device-b"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := pb.Clone(valid).(*proto.KarstCompliancePermitSnapshot)
			tc.change(candidate)
			require.Error(t, compliance.ValidatePermitSnapshot(candidate, binding))
		})
	}
	// A gate with no passing sources is a valid mandatory denial, including when
	// every source failed. An empty snapshot is distinct from a missing snapshot.
	valid.Ingress[0].Sources = nil
	valid.Egress[0].Sources = nil
	require.NoError(t, compliance.ValidatePermitSnapshot(valid, binding))
	valid.Ingress = nil
	valid.Egress = nil
	require.NoError(t, compliance.ValidatePermitSnapshot(valid, binding))
	badBinding := binding
	badBinding.Nonce = nil
	require.Error(t, compliance.ValidatePermitSnapshot(valid, badBinding))
}

func TestPermitSnapshotRejectsMixedSourceEnrollmentsAcrossResources(t *testing.T) {
	snapshot, binding := permitFixture()
	snapshot.Egress = nil
	source := snapshot.Ingress[0].Sources[0]
	source.Handle = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	source.DeviceId = "device-b"
	second := pb.Clone(snapshot.Ingress[0]).(*proto.KarstCompliancePermitGate)
	second.GuardrailId = "second-resource"
	snapshot.Ingress = append(snapshot.Ingress, second)
	require.NoError(t, compliance.ValidatePermitSnapshot(snapshot, binding))
	second.Sources[0].Handle = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))
	require.ErrorContains(t, compliance.ValidatePermitSnapshot(snapshot, binding), "inconsistent source handles")
	second.Sources[0].Handle = source.Handle
	second.Sources[0].DeviceId = "device-c"
	require.ErrorContains(t, compliance.ValidatePermitSnapshot(snapshot, binding), "inconsistent source generation or enrollment")
}
