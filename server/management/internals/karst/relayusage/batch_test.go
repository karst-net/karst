// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package relayusage

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
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
	batch := Batch{Epoch: [16]byte{1, 2, 3}, Sequence: 7, Payload: []byte("opaque aggregate")}
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

func TestParseRejectsMalformedOrTamperedBatches(t *testing.T) {
	key, err := identity.FromSeed(bytes.Repeat([]byte{4}, identity.SeedSize))
	if err != nil {
		t.Fatal(err)
	}
	batch := Batch{Epoch: [16]byte{8}, Sequence: 12, Payload: []byte("aggregate")}
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
