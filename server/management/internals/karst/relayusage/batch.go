// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// Package relayusage parses and authenticates durable relay usage batches.
// Signature verification proves which key submitted the bytes; operator policy
// must separately authorize that key as a managed producer and validate its
// deployment and mapping scope before accepting usage.
package relayusage

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/netbirdio/netbird/management/internals/karst/identity"
)

const (
	FormatVersion  = 1
	MaxPayloadSize = 8 * 1024 * 1024
	headerSize     = 68
	maxEncodedSize = headerSize + identity.SignatureSize + MaxPayloadSize
)

var (
	ErrInvalidBatch = errors.New("relay usage: invalid batch")
	ErrUnauthorized = errors.New("relay usage: producer signature rejected")
	signingPrefix   = []byte("karst-relay-usage-batch-v1\x00")
)

// Batch is an immutable aggregate payload authenticated by a registered relay
// key. Mapping and time-bound semantics live inside the versioned KRUM payload.
type Batch struct {
	Epoch     [16]byte
	Sequence  uint64
	Digest    [32]byte
	Signature []byte
	Payload   []byte
}

// Parse checks the bounded KRUS v1 envelope, its exact lengths, and payload
// digest. It does not authorize the producer or verify its signature.
func Parse(encoded []byte) (Batch, error) {
	if len(encoded) < headerSize+identity.SignatureSize+1 || len(encoded) > maxEncodedSize {
		return Batch{}, fmt.Errorf("%w: encoded size", ErrInvalidBatch)
	}
	if string(encoded[:4]) != "KRUS" || binary.BigEndian.Uint16(encoded[4:6]) != FormatVersion {
		return Batch{}, fmt.Errorf("%w: magic or version", ErrInvalidBatch)
	}
	var batch Batch
	copy(batch.Epoch[:], encoded[6:22])
	batch.Sequence = binary.BigEndian.Uint64(encoded[22:30])
	payloadLen := binary.BigEndian.Uint32(encoded[30:34])
	copy(batch.Digest[:], encoded[34:66])
	signatureLen := binary.BigEndian.Uint16(encoded[66:68])
	if payloadLen == 0 || uint64(payloadLen) > uint64(MaxPayloadSize) || int(signatureLen) != identity.SignatureSize {
		return Batch{}, fmt.Errorf("%w: field bounds", ErrInvalidBatch)
	}
	if uint64(headerSize)+uint64(signatureLen)+uint64(payloadLen) != uint64(len(encoded)) {
		return Batch{}, fmt.Errorf("%w: length mismatch", ErrInvalidBatch)
	}
	signatureEnd := headerSize + int(signatureLen)
	batch.Signature = append([]byte(nil), encoded[headerSize:signatureEnd]...)
	batch.Payload = append([]byte(nil), encoded[signatureEnd:]...)
	if sha256.Sum256(batch.Payload) != batch.Digest {
		return Batch{}, fmt.Errorf("%w: payload digest", ErrInvalidBatch)
	}
	return batch, nil
}

// SigningInput returns the v1 canonical message signed under
// identity.RelayUsageContext. The payload digest and bytes are both included.
func (batch Batch) SigningInput() []byte {
	out := make([]byte, 0, len(signingPrefix)+16+8+4+32+len(batch.Payload))
	out = append(out, signingPrefix...)
	out = append(out, batch.Epoch[:]...)
	out = binary.BigEndian.AppendUint64(out, batch.Sequence)
	out = binary.BigEndian.AppendUint32(out, uint32(len(batch.Payload)))
	out = append(out, batch.Digest[:]...)
	out = append(out, batch.Payload...)
	return out
}

// VerifyEncoded parses the bounded envelope and verifies its signature.
// Managed-producer authorization and mapping-scope checks remain the caller's
// responsibility; a valid relay key alone must never grant billing authority.
func VerifyEncoded(publicKey, encoded []byte) (Batch, error) {
	batch, err := Parse(encoded)
	if err != nil {
		return Batch{}, err
	}
	if !identity.Verify(publicKey, []byte(identity.RelayUsageContext), batch.SigningInput(), batch.Signature) {
		return Batch{}, ErrUnauthorized
	}
	return batch, nil
}
