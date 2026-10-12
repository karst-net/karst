// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package relayusage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/netbirdio/netbird/management/internals/karst/identity"
	"github.com/netbirdio/netbird/management/internals/karst/relayreg"
	"github.com/netbirdio/netbird/management/internals/karst/usage"
)

const CreditRequestPath = "/karst/v1/billing/relay-credits"
const CreditSurrenderPath = "/karst/v1/billing/relay-credits/"

const maxCreditRequestBytes = 8192

var ErrInvalidCreditRequest = errors.New("relay usage: invalid cap credit request")

// CreditRequest asks for an idempotent byte grant bound to one relay process
// generation and one authorized customer mapping. Account ownership is always
// resolved from the operator-approved mapping, never from this document.
type CreditRequest struct {
	RelayID        string `json:"relay_id"`
	DeploymentID   string `json:"deployment_id"`
	MappingVersion string `json:"mapping_version"`
	Generation     string `json:"generation"`
	RequestID      string `json:"request_id"`
	RequestedBytes string `json:"requested_bytes"`
	Signature      string `json:"signature"`
}

// CreditSurrender returns the unused portion of one grant. The relay reports
// bytes reserved before destination writes, so an ambiguous/queued write is
// conservatively counted as consumed. A new process generation never reuses
// an old grant; a crash therefore strands credits safely instead of guessing.
type CreditSurrender struct {
	GrantID        string `json:"grant_id"`
	RelayID        string `json:"relay_id"`
	DeploymentID   string `json:"deployment_id"`
	MappingVersion string `json:"mapping_version"`
	Generation     string `json:"generation"`
	ConsumedBytes  string `json:"consumed_bytes"`
	Signature      string `json:"signature"`
}

func ParseCreditSurrender(body []byte) (CreditSurrender, error) {
	var request CreditSurrender
	if len(body) == 0 || len(body) > maxCreditRequestBytes {
		return request, ErrInvalidCreditRequest
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return CreditSurrender{}, ErrInvalidCreditRequest
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return CreditSurrender{}, ErrInvalidCreditRequest
	}
	if _, err := request.SigningInput(); err != nil {
		return CreditSurrender{}, err
	}
	signature, err := base64.StdEncoding.DecodeString(request.Signature)
	if err != nil || len(signature) != identity.SignatureSize || base64.StdEncoding.EncodeToString(signature) != request.Signature {
		return CreditSurrender{}, ErrInvalidCreditRequest
	}
	return request, nil
}

// SigningInput is a canonical transcript shared with the Rust relay client.
func (r CreditSurrender) SigningInput() ([]byte, error) {
	if !validCreditHex(r.GrantID, 16) || !validText(r.RelayID, 64) || !validText(r.DeploymentID, 128) ||
		!validCreditHex(r.MappingVersion, 32) || !validCreditHex(r.Generation, 16) {
		return nil, ErrInvalidCreditRequest
	}
	consumed, err := strconv.ParseUint(r.ConsumedBytes, 10, 64)
	if err != nil || strconv.FormatUint(consumed, 10) != r.ConsumedBytes {
		return nil, ErrInvalidCreditRequest
	}
	fields := []string{"POST", CreditSurrenderPath + r.GrantID + "/surrender", r.GrantID, r.RelayID,
		r.DeploymentID, r.MappingVersion, r.Generation, r.ConsumedBytes}
	out := []byte("karst-relay-credit-surrender-v1\x00")
	for _, field := range fields {
		if len(field) > 65535 {
			return nil, ErrInvalidCreditRequest
		}
		var size [2]byte
		binary.BigEndian.PutUint16(size[:], uint16(len(field)))
		out = append(out, size[:]...)
		out = append(out, field...)
	}
	return out, nil
}

// Digest is the idempotency fingerprint persisted with the grant.
func (r CreditSurrender) Digest() (string, error) {
	transcript, err := r.SigningInput()
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(transcript)
	return hex.EncodeToString(digest[:]), nil
}

func (r CreditSurrender) VerifySignature(publicKey []byte) bool {
	transcript, err := r.SigningInput()
	if err != nil {
		return false
	}
	signature, err := base64.StdEncoding.DecodeString(r.Signature)
	return err == nil && identity.Verify(publicKey, []byte(identity.RelayCreditSurrenderContext), transcript, signature)
}

func ParseCreditRequest(body []byte) (CreditRequest, error) {
	var request CreditRequest
	if len(body) == 0 || len(body) > maxCreditRequestBytes {
		return request, ErrInvalidCreditRequest
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return CreditRequest{}, ErrInvalidCreditRequest
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return CreditRequest{}, ErrInvalidCreditRequest
	}
	if _, err := request.SigningInput(); err != nil {
		return CreditRequest{}, err
	}
	signature, err := base64.StdEncoding.DecodeString(request.Signature)
	if err != nil || len(signature) != identity.SignatureSize || base64.StdEncoding.EncodeToString(signature) != request.Signature {
		return CreditRequest{}, ErrInvalidCreditRequest
	}
	return request, nil
}

// SigningInput has one canonical, cross-language binary encoding. Decimal byte
// counts remain strings in JSON but are encoded as a fixed-width uint64 here.
func (r CreditRequest) SigningInput() ([]byte, error) {
	if !validText(r.RelayID, 64) || !validText(r.DeploymentID, 128) || !validCreditHex(r.MappingVersion, 32) ||
		!validCreditHex(r.Generation, 16) || !validCreditHex(r.RequestID, 16) {
		return nil, ErrInvalidCreditRequest
	}
	requested, err := strconv.ParseUint(r.RequestedBytes, 10, 64)
	if err != nil || requested == 0 || strconv.FormatUint(requested, 10) != r.RequestedBytes {
		return nil, ErrInvalidCreditRequest
	}
	fields := []string{"POST", CreditRequestPath, r.RelayID, r.DeploymentID, r.MappingVersion, r.Generation, r.RequestID}
	out := make([]byte, 0, 64+len(r.RelayID)+len(r.DeploymentID)+len(r.MappingVersion)+len(r.Generation)+len(r.RequestID))
	out = append(out, []byte("karst-relay-credit-request-v1\x00")...)
	for _, field := range fields {
		if len(field) > math.MaxUint16 {
			return nil, ErrInvalidCreditRequest
		}
		var size [2]byte
		binary.BigEndian.PutUint16(size[:], uint16(len(field)))
		out = append(out, size[:]...)
		out = append(out, field...)
	}
	out = binary.BigEndian.AppendUint64(out, requested)
	return out, nil
}

// AuthorizeCreditRequest verifies the relay signature and resolves the
// currently enabled, operator-authorized mapping. Bind this Store to the same
// transaction used for reserving credits so a concurrent revocation cannot
// race with grant issuance.
func (s *Store) AuthorizeCreditRequest(ctx context.Context, request CreditRequest) (usage.RelayMapping, error) {
	transcript, err := request.SigningInput()
	if err != nil {
		return usage.RelayMapping{}, err
	}
	signature, err := base64.StdEncoding.DecodeString(request.Signature)
	if err != nil || len(signature) != identity.SignatureSize {
		return usage.RelayMapping{}, ErrInvalidCreditRequest
	}
	var mapping usage.RelayMapping
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var producer ManagedProducer
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("relay_id = ? AND enabled = ?", request.RelayID, true).Take(&producer).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrProducerMissing
			}
			return err
		}
		publicKey, err := base64.StdEncoding.DecodeString(producer.IdentityKey)
		if err != nil || len(publicKey) != identity.PublicKeySize || producer.DeploymentID != request.DeploymentID {
			return ErrProducerMissing
		}
		relayIDBytes, err := base64.RawURLEncoding.DecodeString(request.RelayID)
		if err != nil || subtle.ConstantTimeCompare(relayIDBytes, relayreg.RelayID(publicKey)) != 1 {
			return ErrUnauthorized
		}
		if !identity.Verify(publicKey, []byte(identity.RelayCreditRequestContext), transcript, signature) {
			return ErrUnauthorized
		}
		var allowed AllowedMapping
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("relay_id = ? AND deployment_id = ? AND version = ? AND enabled = ?",
			request.RelayID, request.DeploymentID, request.MappingVersion, true).Take(&allowed).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrMappingNotAllowed
			}
			return err
		}
		mapping, err = usage.ResolveRelayMapping(ctx, tx, request.DeploymentID, request.MappingVersion)
		if err != nil {
			if errors.Is(err, usage.ErrMapping) {
				return ErrMappingNotAllowed
			}
			return err
		}
		return nil
	})
	if err != nil {
		return usage.RelayMapping{}, fmt.Errorf("relay usage: authorize cap credit request: %w", err)
	}
	return mapping, nil
}

// AuthorizeCreditSurrender verifies the relay signature and the currently
// enabled producer/mapping in the caller's transaction. Callers can safely
// return credits in the same transaction as this check, so a concurrent
// authorization revocation cannot race the surrender.
func (s *Store) AuthorizeCreditSurrender(ctx context.Context, request CreditSurrender) (usage.RelayMapping, error) {
	transcript, err := request.SigningInput()
	if err != nil {
		return usage.RelayMapping{}, err
	}
	signature, err := base64.StdEncoding.DecodeString(request.Signature)
	if err != nil || len(signature) != identity.SignatureSize {
		return usage.RelayMapping{}, ErrInvalidCreditRequest
	}
	var mapping usage.RelayMapping
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var producer ManagedProducer
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("relay_id = ? AND enabled = ?", request.RelayID, true).Take(&producer).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrProducerMissing
			}
			return err
		}
		publicKey, err := base64.StdEncoding.DecodeString(producer.IdentityKey)
		if err != nil || len(publicKey) != identity.PublicKeySize || producer.DeploymentID != request.DeploymentID {
			return ErrProducerMissing
		}
		relayIDBytes, err := base64.RawURLEncoding.DecodeString(request.RelayID)
		if err != nil || subtle.ConstantTimeCompare(relayIDBytes, relayreg.RelayID(publicKey)) != 1 {
			return ErrUnauthorized
		}
		if !identity.Verify(publicKey, []byte(identity.RelayCreditSurrenderContext), transcript, signature) {
			return ErrUnauthorized
		}
		var allowed AllowedMapping
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("relay_id = ? AND deployment_id = ? AND version = ? AND enabled = ?",
			request.RelayID, request.DeploymentID, request.MappingVersion, true).Take(&allowed).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrMappingNotAllowed
			}
			return err
		}
		mapping, err = usage.ResolveRelayMapping(ctx, tx, request.DeploymentID, request.MappingVersion)
		if err != nil {
			if errors.Is(err, usage.ErrMapping) {
				return ErrMappingNotAllowed
			}
			return err
		}
		return nil
	})
	if err != nil {
		return usage.RelayMapping{}, fmt.Errorf("relay usage: authorize cap credit surrender: %w", err)
	}
	return mapping, nil
}

func DecodeRequestedCreditBytes(request CreditRequest) (uint64, error) {
	if _, err := request.SigningInput(); err != nil {
		return 0, err
	}
	value, _ := strconv.ParseUint(request.RequestedBytes, 10, 64)
	return value, nil
}

func (r CreditRequest) VerifySignature(publicKey []byte) bool {
	transcript, err := r.SigningInput()
	if err != nil {
		return false
	}
	signature, err := base64.StdEncoding.DecodeString(r.Signature)
	return err == nil && identity.Verify(publicKey, []byte(identity.RelayCreditRequestContext), transcript, signature)
}

func validCreditHex(value string, bytes int) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == bytes && hex.EncodeToString(decoded) == value
}
