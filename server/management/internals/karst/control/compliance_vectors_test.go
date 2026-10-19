// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package control_test

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/netbirdio/netbird/shared/management/proto"
	"github.com/stretchr/testify/require"
	pb "google.golang.org/protobuf/proto"
)

func TestVectorsCompliance(t *testing.T) {
	token := make([]byte, 32)
	for i := range token {
		token[i] = byte(i)
	}
	report := complianceReport(token)
	report.GetReport().Platform = "linux"
	report.GetReport().Distribution = "ubuntu"
	report.GetReport().OsVersion.Version = "24.04"
	failed := pb.Clone(report).(*proto.KarstComplianceRequest)
	failed.GetReport().ClientVersion = &proto.KarstComplianceObservation{Status: proto.KarstComplianceObservation_UNSUPPORTED}
	failed.GetReport().OsVersion = &proto.KarstComplianceObservation{Status: proto.KarstComplianceObservation_COLLECTION_ERROR}
	messages := []struct {
		name    string
		message pb.Message
	}{
		{"challenge-request", challengeRequest()}, {"report-request", report}, {"failed-report-request", failed},
		{"challenge-response", &proto.KarstComplianceResponse{SchemaVersion: 1, Challenge: token, ValidForSeconds: 60}},
		{"accepted-response", &proto.KarstComplianceResponse{SchemaVersion: 1, Accepted: true}},
	}
	type vector struct {
		Name string `json:"name"`
		Hex  string `json:"hex"`
	}
	file := struct {
		Spec  string   `json:"spec"`
		Cases []vector `json:"cases"`
	}{Spec: "Device compliance ingestion v1"}
	for _, m := range messages {
		encoded, err := pb.Marshal(m.message)
		require.NoError(t, err)
		file.Cases = append(file.Cases, vector{Name: m.name, Hex: hex.EncodeToString(encoded)})
	}
	encoded, err := json.MarshalIndent(file, "", "  ")
	require.NoError(t, err)
	encoded = append(encoded, '\n')
	path := filepath.Join(filepath.Dir(vectorsPath(t)), "device-compliance-v1.json")
	if os.Getenv("UPDATE_VECTORS") != "" {
		require.NoError(t, os.WriteFile(path, encoded, 0644))
		return
	}
	want, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, string(want), string(encoded), "regenerate intentionally with UPDATE_VECTORS=1")
}
