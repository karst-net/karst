// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package relayusage

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netbirdio/netbird/management/internals/karst/identity"
)

type signingVector struct {
	EpochHex         string
	Sequence         uint64
	PayloadHex       string
	PayloadSHA256Hex string
	SigningInputHex  string
}

func TestSharedRelayUsageSigningVector(t *testing.T) {
	path := filepath.Join("..", "..", "..", "..", "..", "spec", "vectors", "relay-usage-batch-v1.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var vector signingVector
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	epoch, err := hex.DecodeString(vector.EpochHex)
	if err != nil || len(epoch) != 16 {
		t.Fatalf("epoch: %x %v", epoch, err)
	}
	payload, err := hex.DecodeString(vector.PayloadHex)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := hex.DecodeString(vector.PayloadSHA256Hex)
	if err != nil || len(digest) != 32 {
		t.Fatalf("digest: %x %v", digest, err)
	}
	var batch Batch
	copy(batch.Epoch[:], epoch)
	copy(batch.Digest[:], digest)
	batch.Sequence, batch.Payload = vector.Sequence, payload
	want, err := hex.DecodeString(vector.SigningInputHex)
	if err != nil {
		t.Fatal(err)
	}
	if got := batch.SigningInput(); !bytes.Equal(got, want) {
		t.Fatalf("signing input = %x, want %x", got, want)
	}
}

func TestParseAndVerifySignedBatch(t *testing.T) {
	key, err := identity.FromSeed(bytes.Repeat([]byte{9}, identity.SeedSize))
	if err != nil {
		t.Fatal(err)
	}
	batch := Batch{Epoch: [16]byte{1, 2, 3}, Sequence: 7, Payload: emptyHeartbeat()}
	batch.Digest = sha256.Sum256(batch.Payload)
	signature, err := key.Sign([]byte(identity.RelayUsageContext), batch.SigningInput())
	if err != nil {
		t.Fatal(err)
	}
	encoded := encodeForTest(batch, signature)
	got, err := VerifyEncoded(key.Public(), encoded)
	if err != nil {
		t.Fatal(err)
	}
	if got.Epoch != batch.Epoch || got.Sequence != batch.Sequence || !bytes.Equal(got.Payload, batch.Payload) {
		t.Fatalf("verified batch = %+v, want %+v", got, batch)
	}
	wrongContextSignature, err := key.Sign([]byte(identity.RelayTelemetryContext), batch.SigningInput())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyEncoded(key.Public(), encodeForTest(batch, wrongContextSignature)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("telemetry signature error = %v, want ErrUnauthorized", err)
	}
	if _, err := VerifyEncoded(make([]byte, identity.PublicKeySize), encoded); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("wrong key error = %v, want ErrUnauthorized", err)
	}
}

func TestFreshUploadSignatureBindsRequestAndBody(t *testing.T) {
	key, err := identity.FromSeed(bytes.Repeat([]byte{7}, identity.SeedSize))
	if err != nil {
		t.Fatal(err)
	}
	var nonce [32]byte
	for i := range nonce {
		nonce[i] = byte(i + 1)
	}
	body := []byte("immutable signed batch")
	input, err := UploadSigningInput("POST", UploadPath, 123456789, nonce, body)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := key.Sign([]byte(identity.RelayUsageUploadContext), input)
	if err != nil {
		t.Fatal(err)
	}
	if !identity.Verify(key.Public(), []byte(identity.RelayUsageUploadContext), input, signature) {
		t.Fatal("valid upload signature rejected")
	}
	changedBody, err := UploadSigningInput("POST", UploadPath, 123456789, nonce, []byte("different batch"))
	if err != nil {
		t.Fatal(err)
	}
	if identity.Verify(key.Public(), []byte(identity.RelayUsageUploadContext), changedBody, signature) {
		t.Fatal("signature accepted a different request body")
	}
	changedNonce := nonce
	changedNonce[0]++
	changedRequest, err := UploadSigningInput("POST", UploadPath, 123456789, changedNonce, body)
	if err != nil {
		t.Fatal(err)
	}
	if identity.Verify(key.Public(), []byte(identity.RelayUsageUploadContext), changedRequest, signature) {
		t.Fatal("signature accepted a reused signature with a changed nonce")
	}
	if _, err := UploadSigningInput("PUT", UploadPath, 123456789, nonce, body); err == nil {
		t.Fatal("unexpected method accepted")
	}
}

func TestSharedUsageUploadSigningVectorMatchesRust(t *testing.T) {
	path := filepath.Join("..", "..", "..", "..", "..", "spec", "vectors", "relay-usage-upload-v1.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		TimestampMicros uint64
		NonceHex        string
		BodyHex         string
		SigningInputHex string
	}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	nonceBytes, err := hex.DecodeString(vector.NonceHex)
	if err != nil || len(nonceBytes) != 32 {
		t.Fatalf("nonce: %x %v", nonceBytes, err)
	}
	var nonce [32]byte
	copy(nonce[:], nonceBytes)
	body, err := hex.DecodeString(vector.BodyHex)
	if err != nil {
		t.Fatal(err)
	}
	got, err := UploadSigningInput("POST", UploadPath, vector.TimestampMicros, nonce, body)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got) != vector.SigningInputHex {
		t.Fatalf("signing input = %x, want %s", got, vector.SigningInputHex)
	}
}

func TestParseUploadAuthorizationRequiresCanonicalFields(t *testing.T) {
	var id [32]byte
	for i := range id {
		id[i] = byte(i)
	}
	var nonce [32]byte
	for i := range nonce {
		nonce[i] = byte(31 - i)
	}
	header := "KarstUsage " + base64.RawURLEncoding.EncodeToString(id[:]) + ".123456789." + hex.EncodeToString(nonce[:]) + "." + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, identity.SignatureSize))
	auth, err := ParseUploadAuthorization(header)
	if err != nil {
		t.Fatal(err)
	}
	if auth.TimestampMicros != 123456789 || auth.Nonce != nonce || !bytes.Equal(auth.Signature, bytes.Repeat([]byte{1}, identity.SignatureSize)) {
		t.Fatalf("parsed authorization = %+v", auth)
	}
	for _, malformed := range []string{
		"Bearer " + strings.TrimPrefix(header, "KarstUsage "),
		header + ".extra",
		strings.Replace(header, ".123456789.", ".0123456789.", 1),
		strings.Replace(header, "KarstUsage ", "KarstUsage  ", 1),
		header + " ",
		strings.Repeat("x", maxAuthorizationBytes+1),
	} {
		if _, err := ParseUploadAuthorization(malformed); err == nil {
			t.Fatalf("accepted malformed header %q", malformed[:min(len(malformed), 24)])
		}
	}
	zeroNonceHeader := strings.Replace(header, hex.EncodeToString(nonce[:]), hex.EncodeToString(make([]byte, 32)), 1)
	if _, err := ParseUploadAuthorization(zeroNonceHeader); err == nil {
		t.Fatal("all-zero nonce accepted")
	}
}

func TestParseRejectsMalformedOrTamperedBatches(t *testing.T) {
	key, err := identity.FromSeed(bytes.Repeat([]byte{4}, identity.SeedSize))
	if err != nil {
		t.Fatal(err)
	}
	batch := Batch{Epoch: [16]byte{8}, Sequence: 12, Payload: emptyHeartbeat()}
	batch.Digest = sha256.Sum256(batch.Payload)
	signature, err := key.Sign([]byte(identity.RelayUsageContext), batch.SigningInput())
	if err != nil {
		t.Fatal(err)
	}
	encoded := encodeForTest(batch, signature)
	for name, mutate := range map[string]func([]byte){
		"magic":   func(b []byte) { b[0] ^= 1 },
		"version": func(b []byte) { b[5] = 2 },
		"digest":  func(b []byte) { b[34] ^= 1 },
		"payload": func(b []byte) { b[len(b)-1] ^= 1 },
		"length":  func(b []byte) { b[33]++ },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := bytes.Clone(encoded)
			mutate(candidate)
			if _, err := Parse(candidate); err == nil {
				t.Fatal("malformed batch parsed successfully")
			}
		})
	}
	if _, err := Parse(append(bytes.Clone(encoded), 0)); err == nil {
		t.Fatal("trailing bytes were accepted")
	}
	if _, err := Parse(nil); !errors.Is(err, ErrInvalidBatch) {
		t.Fatalf("empty parse error = %v, want ErrInvalidBatch", err)
	}
}

func TestParseRejectsMalformedUsagePayload(t *testing.T) {
	key, err := identity.FromSeed(bytes.Repeat([]byte{6}, identity.SeedSize))
	if err != nil {
		t.Fatal(err)
	}
	valid := emptyHeartbeat()
	for name, mutate := range map[string]func([]byte){
		"magic":           func(b []byte) { b[0] ^= 1 },
		"version":         func(b []byte) { b[5] = 2 },
		"misaligned time": func(b []byte) { b[13] = 1 },
		"duration":        func(b []byte) { b[21]-- },
		"unknown gaps":    func(b []byte) { b[len(b)-1] = 0x80 },
	} {
		t.Run(name, func(t *testing.T) {
			payload := bytes.Clone(valid)
			mutate(payload)
			batch := Batch{Epoch: [16]byte{2}, Sequence: 1, Payload: payload}
			batch.Digest = sha256.Sum256(payload)
			signature, err := key.Sign([]byte(identity.RelayUsageContext), batch.SigningInput())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Parse(encodeForTest(batch, signature)); err == nil {
				t.Fatal("malformed payload parsed successfully")
			}
		})
	}
}

func TestParseUsagePayloadReturnsExactAuthorizedMappingReferences(t *testing.T) {
	payload := emptyHeartbeat()
	payload = payload[:22]
	payload = binary.BigEndian.AppendUint16(payload, 1)
	for _, value := range []string{"deployment-a", strings.Repeat("a", 64), "aquifer-b"} {
		payload = binary.BigEndian.AppendUint16(payload, uint16(len(value)))
		payload = append(payload, value...)
	}
	payload = binary.BigEndian.AppendUint64(payload, 123)
	payload = append(payload, GapUnresolvedMapping)

	window, err := parsePayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	if window.StartMicros != 0 || window.EndMicros != minuteMicros || window.Gaps != 1 || len(window.Mappings) != 1 {
		t.Fatalf("parsed window = %+v", window)
	}
	got := window.Mappings[0]
	if got.Deployment != "deployment-a" || got.Version != strings.Repeat("a", 64) || got.Aquifer != "aquifer-b" || got.Bytes != 123 {
		t.Fatalf("parsed mapping = %+v", got)
	}
	if _, err := parsePayload(append(bytes.Clone(payload), 0)); err == nil {
		t.Fatal("trailing payload byte accepted")
	}
}

func emptyHeartbeat() []byte {
	payload := make([]byte, 25)
	copy(payload[:4], "KRUM")
	binary.BigEndian.PutUint16(payload[4:6], 1)
	binary.BigEndian.PutUint64(payload[14:22], 60_000_000)
	return payload
}

func encodeForTest(batch Batch, signature []byte) []byte {
	out := make([]byte, headerSize+len(signature)+len(batch.Payload))
	copy(out[:4], "KRUS")
	binary.BigEndian.PutUint16(out[4:6], FormatVersion)
	copy(out[6:22], batch.Epoch[:])
	binary.BigEndian.PutUint64(out[22:30], batch.Sequence)
	binary.BigEndian.PutUint32(out[30:34], uint32(len(batch.Payload)))
	copy(out[34:66], batch.Digest[:])
	binary.BigEndian.PutUint16(out[66:68], uint16(len(signature)))
	copy(out[68:], signature)
	copy(out[68+len(signature):], batch.Payload)
	return out
}
