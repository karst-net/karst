// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package control_test

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/netbirdio/netbird/management/internals/karst/compliance"
	"github.com/netbirdio/netbird/shared/management/proto"
	"github.com/stretchr/testify/require"
	pb "google.golang.org/protobuf/proto"
)

func TestVectorsCompliancePermits(t *testing.T) {
	nonce := make([]byte, 32)
	for i := range nonce {
		nonce[i] = byte(i)
	}
	handle := base64.StdEncoding.EncodeToString(make([]byte, 32))
	gate := &proto.KarstCompliancePermitGate{GuardrailId: "production", DestinationCidrs: []string{"10.99.0.0/24", "fd00:99::/64"}, Protocol: proto.KarstCompliancePermitGate_TCP, Ports: &proto.KarstPortRange{First: 443, Last: 443}, Sources: []*proto.KarstComplianceSourcePermit{{Handle: handle, DeviceId: "device-a", EvidenceGeneration: 7, ValidForMillis: 119000}}}
	snapshot := &proto.KarstCompliancePermitSnapshot{SchemaVersion: 1, RequestNonce: nonce, TenantId: "tenant-a", EnforcerDeviceId: "device-a", EnforcerHandle: handle, PolicyRevision: "revision-42", ValidForMillis: 120000, Ingress: []*proto.KarstCompliancePermitGate{gate}, Egress: []*proto.KarstCompliancePermitGate{pb.Clone(gate).(*proto.KarstCompliancePermitGate)}}
	binding := compliance.PermitBinding{Subject: compliance.Subject{TenantID: "tenant-a", DeviceID: "device-a"}, Handle: handle, PolicyRevision: "revision-42", Nonce: nonce}
	require.NoError(t, compliance.ValidatePermitSnapshot(snapshot, binding))
	denied := pb.Clone(snapshot).(*proto.KarstCompliancePermitSnapshot)
	denied.Ingress[0].Sources = nil
	denied.Egress[0].Sources = nil
	require.NoError(t, compliance.ValidatePermitSnapshot(denied, binding))
	type vector struct {
		Name string `json:"name"`
		Hex  string `json:"hex"`
	}
	file := struct {
		Spec  string   `json:"spec"`
		Cases []vector `json:"cases"`
	}{Spec: "Device compliance permit contract v1 (not activated)"}
	for _, item := range []struct {
		name    string
		message pb.Message
	}{
		{"permit-request", &proto.KarstCompliancePermitRequest{SchemaVersion: 1, Nonce: nonce}},
		{"permit-snapshot", snapshot}, {"deny-snapshot", denied},
	} {
		encoded, err := pb.Marshal(item.message)
		require.NoError(t, err)
		file.Cases = append(file.Cases, vector{Name: item.name, Hex: hex.EncodeToString(encoded)})
	}
	encoded, err := json.MarshalIndent(file, "", "  ")
	require.NoError(t, err)
	encoded = append(encoded, '\n')
	path := filepath.Join(filepath.Dir(vectorsPath(t)), "device-compliance-permits-v1.json")
	if os.Getenv("UPDATE_VECTORS") != "" {
		require.NoError(t, os.WriteFile(path, encoded, 0644))
		return
	}
	expected, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, string(expected), string(encoded), "regenerate intentionally with UPDATE_VECTORS=1")
}
