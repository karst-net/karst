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
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/netbirdio/netbird/management/internals/karst/identity"
)

const (
	FormatVersion  = 1
	MaxPayloadSize = 8 * 1024 * 1024
	headerSize     = 68
	maxEncodedSize = headerSize + identity.SignatureSize + MaxPayloadSize
	maxMappings    = 4096
	minuteMicros   = uint64(60_000_000)
)

const (
	GapUnresolvedMapping uint8 = 1 << iota
	GapCapacity
	GapOverflow
	GapClock
	GapObservationLost
	knownGapMask = GapUnresolvedMapping | GapCapacity | GapOverflow | GapClock | GapObservationLost
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
	Window    Window
}

// MappingTotal is one account-attribution reference and its observed bytes.
// Account ownership must be resolved from durable control-plane mapping state.
type MappingTotal struct {
	Deployment string
	Version    string
	Aquifer    string
	Bytes      uint64
}

// Window is one bounded UTC minute, including explicit coverage gaps.
type Window struct {
	StartMicros uint64
	EndMicros   uint64
	Mappings    []MappingTotal
	Gaps        uint8
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
	window, err := parsePayload(batch.Payload)
	if err != nil {
		return Batch{}, err
	}
	batch.Window = window
	return batch, nil
}

func parsePayload(payload []byte) (Window, error) {
	if len(payload) < 4+2+8+8+2+1 || string(payload[:4]) != "KRUM" || binary.BigEndian.Uint16(payload[4:6]) != 1 {
		return Window{}, fmt.Errorf("%w: payload magic or version", ErrInvalidBatch)
	}
	window := Window{
		StartMicros: binary.BigEndian.Uint64(payload[6:14]),
		EndMicros:   binary.BigEndian.Uint64(payload[14:22]),
	}
	if window.StartMicros%minuteMicros != 0 || window.StartMicros > ^uint64(0)-minuteMicros || window.EndMicros != window.StartMicros+minuteMicros {
		return Window{}, fmt.Errorf("%w: payload window bounds", ErrInvalidBatch)
	}
	count := int(binary.BigEndian.Uint16(payload[22:24]))
	if count > maxMappings {
		return Window{}, fmt.Errorf("%w: mapping count", ErrInvalidBatch)
	}
	offset := 24
	window.Mappings = make([]MappingTotal, 0, count)
	previous := ""
	for i := 0; i < count; i++ {
		fields := [3]string{}
		limits := [3]int{128, 64, 1024}
		for j, limit := range limits {
			if len(payload)-offset < 2 {
				return Window{}, fmt.Errorf("%w: truncated mapping length", ErrInvalidBatch)
			}
			size := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
			offset += 2
			if size == 0 || size > limit || size > len(payload)-offset {
				return Window{}, fmt.Errorf("%w: mapping field bounds", ErrInvalidBatch)
			}
			value := payload[offset : offset+size]
			offset += size
			if !utf8.Valid(value) || strings.TrimSpace(string(value)) != string(value) || strings.IndexFunc(string(value), unicode.IsControl) >= 0 {
				return Window{}, fmt.Errorf("%w: invalid mapping text", ErrInvalidBatch)
			}
			fields[j] = string(value)
		}
		if len(payload)-offset < 8 {
			return Window{}, fmt.Errorf("%w: truncated mapping total", ErrInvalidBatch)
		}
		bytes := binary.BigEndian.Uint64(payload[offset : offset+8])
		offset += 8
		key := fields[0] + "\x00" + fields[1] + "\x00" + fields[2]
		if i > 0 && key <= previous {
			return Window{}, fmt.Errorf("%w: mapping order or duplicate", ErrInvalidBatch)
		}
		previous = key
		window.Mappings = append(window.Mappings, MappingTotal{Deployment: fields[0], Version: fields[1], Aquifer: fields[2], Bytes: bytes})
	}
	if len(payload)-offset != 1 {
		return Window{}, fmt.Errorf("%w: payload trailing bytes", ErrInvalidBatch)
	}
	window.Gaps = payload[offset]
	if window.Gaps&^knownGapMask != 0 {
		return Window{}, fmt.Errorf("%w: unknown coverage gap", ErrInvalidBatch)
	}
	return window, nil
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
