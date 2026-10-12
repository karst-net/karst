// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package relayusage

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/karst/identity"
)

func signedCreditRequest(t *testing.T, key *identity.Key, relayID string, mappingVersion string) CreditRequest {
	t.Helper()
	request := CreditRequest{RelayID: relayID, DeploymentID: "deployment-a", MappingVersion: mappingVersion,
		Generation: "0102030405060708090a0b0c0d0e0f10", RequestID: "1112131415161718191a1b1c1d1e1f20", RequestedBytes: "1234567"}
	input, err := request.SigningInput()
	require.NoError(t, err)
	signature, err := key.Sign([]byte(identity.RelayCreditRequestContext), input)
	require.NoError(t, err)
	request.Signature = base64.StdEncoding.EncodeToString(signature)
	return request
}

func TestCreditRequestIsCanonicalAndAuthorizedToExactMapping(t *testing.T) {
	_, store, key, relayID, mapping := ingestionFixture(t)
	request := signedCreditRequest(t, key, relayID, mapping.Version)
	body, err := json.Marshal(request)
	require.NoError(t, err)
	parsed, err := ParseCreditRequest(body)
	require.NoError(t, err)
	require.True(t, parsed.VerifySignature(key.Public()))
	resolved, err := store.AuthorizeCreditRequest(context.Background(), parsed)
	require.NoError(t, err)
	require.Equal(t, mapping, resolved)

	modified := parsed
	modified.RequestedBytes = "1234568"
	require.False(t, modified.VerifySignature(key.Public()), "the signature covers requested credit bytes")
	_, err = store.AuthorizeCreditRequest(context.Background(), modified)
	require.ErrorIs(t, err, ErrUnauthorized)
}

func TestCreditRequestRejectsUnapprovedMappingAndProducer(t *testing.T) {
	_, store, key, relayID, mapping := ingestionFixture(t)
	request := signedCreditRequest(t, key, relayID, mapping.Version)
	require.NoError(t, store.RevokeMapping(context.Background(), relayID, mapping.DeploymentID, mapping.Version))
	_, err := store.AuthorizeCreditRequest(context.Background(), request)
	require.ErrorIs(t, err, ErrMappingNotAllowed)

	require.NoError(t, store.RevokeProducer(context.Background(), relayID))
	_, err = store.AuthorizeCreditRequest(context.Background(), request)
	require.ErrorIs(t, err, ErrProducerMissing)
}

func TestParseCreditRequestRejectsMalformedAndUnknownFields(t *testing.T) {
	for _, body := range [][]byte{
		[]byte(`{}`),
		[]byte(`{"relay_id":"r","requested_bytes":"01","extra":true}`),
		[]byte(`{"relay_id":"r"} trailing`),
		make([]byte, maxCreditRequestBytes+1),
	} {
		_, err := ParseCreditRequest(body)
		require.True(t, errors.Is(err, ErrInvalidCreditRequest), "body %q returned %v", body, err)
	}
}

func TestSharedCreditRequestSigningVectorMatchesRust(t *testing.T) {
	path := filepath.Join("..", "..", "..", "..", "..", "spec", "vectors", "relay-credit-request-v1.json")
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var vector struct {
		RelayID        string `json:"relay_id"`
		DeploymentID   string `json:"deployment_id"`
		MappingVersion string `json:"mapping_version"`
		Generation     string `json:"generation"`
		RequestID      string `json:"request_id"`
		RequestedBytes uint64 `json:"requested_bytes"`
		SigningInput   string `json:"signing_input_hex"`
	}
	require.NoError(t, json.Unmarshal(raw, &vector))
	request := CreditRequest{RelayID: vector.RelayID, DeploymentID: vector.DeploymentID, MappingVersion: vector.MappingVersion,
		Generation: vector.Generation, RequestID: vector.RequestID, RequestedBytes: strconv.FormatUint(vector.RequestedBytes, 10)}
	got, err := request.SigningInput()
	require.NoError(t, err)
	require.Equal(t, vector.SigningInput, hex.EncodeToString(got))
}
