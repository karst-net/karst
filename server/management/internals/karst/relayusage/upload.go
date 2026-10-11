// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package relayusage

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"

	"github.com/netbirdio/netbird/management/internals/karst/identity"
)

const UploadPath = "/karst/v1/usage/relay-batches"
const maxAuthorizationBytes = 6400

var ErrInvalidUploadAuth = errors.New("relay usage: invalid upload authentication")

type UploadAuthorization struct {
	RelayID         string
	TimestampMicros uint64
	Nonce           [32]byte
	Signature       []byte
}

// ParseUploadAuthorization parses the compact Authorization header without
// consulting the database. Its exact canonical spelling avoids multiple
// encodings of a nonce or relay ID.
func ParseUploadAuthorization(value string) (UploadAuthorization, error) {
	var auth UploadAuthorization
	if len(value) > maxAuthorizationBytes {
		return auth, ErrInvalidUploadAuth
	}
	fields := strings.Fields(value)
	if len(fields) != 2 || fields[0] != "KarstUsage" || strings.Join(fields, " ") != value {
		return auth, ErrInvalidUploadAuth
	}
	parts := strings.Split(fields[1], ".")
	if len(parts) != 4 {
		return auth, ErrInvalidUploadAuth
	}
	relayID, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || len(relayID) != 32 || base64.RawURLEncoding.EncodeToString(relayID) != parts[0] {
		return auth, ErrInvalidUploadAuth
	}
	timestamp, err := strconv.ParseUint(parts[1], 10, 64)
	if err != nil || strconv.FormatUint(timestamp, 10) != parts[1] {
		return auth, ErrInvalidUploadAuth
	}
	nonce, err := hex.DecodeString(parts[2])
	if err != nil || len(nonce) != len(auth.Nonce) || hex.EncodeToString(nonce) != parts[2] {
		return auth, ErrInvalidUploadAuth
	}
	signature, err := base64.StdEncoding.DecodeString(parts[3])
	if err != nil || len(signature) != identity.SignatureSize || base64.StdEncoding.EncodeToString(signature) != parts[3] {
		return auth, ErrInvalidUploadAuth
	}
	auth.RelayID = parts[0]
	auth.TimestampMicros = timestamp
	copy(auth.Nonce[:], nonce)
	if auth.Nonce == [32]byte{} {
		return UploadAuthorization{}, ErrInvalidUploadAuth
	}
	auth.Signature = signature
	return auth, nil
}

// UploadSigningInput binds a fresh request authorization to the method, exact
// path, timestamp, nonce, and exact signed batch bytes. The immutable batch
// signature alone cannot provide transport freshness because retries must
// replay the same stored bytes.
func UploadSigningInput(method, path string, timestampMicros uint64, nonce [32]byte, encodedBatch []byte) ([]byte, error) {
	if method != "POST" || path != UploadPath || len(encodedBatch) == 0 || len(encodedBatch) > maxEncodedSize {
		return nil, ErrInvalidUploadAuth
	}
	var size [2]byte
	out := make([]byte, 0, len("karst-relay-usage-upload-request-v1\x00")+2+len(method)+2+len(path)+8+len(nonce)+32)
	out = append(out, []byte("karst-relay-usage-upload-request-v1\x00")...)
	binary.BigEndian.PutUint16(size[:], uint16(len(method)))
	out = append(out, size[:]...)
	out = append(out, method...)
	binary.BigEndian.PutUint16(size[:], uint16(len(path)))
	out = append(out, size[:]...)
	out = append(out, path...)
	out = binary.BigEndian.AppendUint64(out, timestampMicros)
	out = append(out, nonce[:]...)
	digest := sha256.Sum256(encodedBatch)
	out = append(out, digest[:]...)
	return out, nil
}
