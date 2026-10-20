// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// Package cloudaccounts stores admin-entered AWS/Azure/GCP credentials for
// the console's Settings page, and uses them to discover an account's
// enabled regions/local-zones for the Authorized Locations picker
// (cloudcatalog supplies the coordinates the provider APIs don't return).
//
// ADR-0045 §6 says the control plane "must not gain cloud-account
// credentials as a side effect of this feature... A compromise of the
// control plane must not yield the ability to spend the operator's money."
// This package is a deliberate, scoped amendment to that boundary -- see
// docs/adr/0045-cost-aware-geographic-scaling-across-providers.md's
// addenda. Consequences follow directly from the ADR text:
//
//   - Mode exists so an operator can hand over read-only (status/discovery
//     only, can never place an order) credentials and keep read-write
//     ones elsewhere, or out entirely.
//   - Storing ModeReadWrite records intent for a future actuation path,
//     with exactly one narrow, named exception carved out ahead of it:
//     EnableLocalZone, which opts an AWS Local Zone's group into use
//     (ModifyAvailabilityZoneGroup) and nothing else -- no create/destroy
//     of a compute resource. Real create/destroy actuation is still
//     ADR-0045 §5/§7 Phase 2 (drivers, signed enrollment, a budget circuit
//     breaker) -- unbuilt, on purpose. Nothing in this package should grow
//     a further provisioning call without that phase's safeguards landing
//     first; EnableLocalZone is the one call this ADR's second addendum
//     deliberately lets through ahead of it, not a precedent for adding
//     more the same way.
package cloudaccounts

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/rs/xid"
	"gorm.io/gorm"

	"github.com/netbirdio/netbird/util/crypt"
)

var (
	ErrNoAccount          = errors.New("cloud accounts: account scope missing")
	ErrNotFound           = errors.New("cloud accounts: not found")
	ErrEncryptionRequired = errors.New("cloud accounts: the server has no data-store encryption key configured -- cloud credentials cannot be stored unencrypted")
)

type Provider string

const (
	ProviderAWS   Provider = "aws"
	ProviderAzure Provider = "azure"
	ProviderGCP   Provider = "gcp"
)

func (p Provider) Valid() bool {
	return p == ProviderAWS || p == ProviderAzure || p == ProviderGCP
}

// Mode says what a credential may be used for. See the package doc comment
// for why ModeReadWrite does not currently do anything more than
// ModeReadOnly -- both are discovery-only until Phase 2 actuation exists.
type Mode string

const (
	ModeReadOnly  Mode = "read_only"
	ModeReadWrite Mode = "read_write"
)

func (m Mode) Valid() bool {
	return m == ModeReadOnly || m == ModeReadWrite
}

type accountContextKey struct{}

func WithAccount(ctx context.Context, accountID string) context.Context {
	return context.WithValue(ctx, accountContextKey{}, accountID)
}

func accountFromContext(ctx context.Context) (string, error) {
	accountID, _ := ctx.Value(accountContextKey{}).(string)
	if accountID == "" {
		return "", ErrNoAccount
	}
	return accountID, nil
}

// Account is one admin-entered cloud credential. Secret is a
// provider-shaped JSON blob -- see awsSecret/azureSecret/gcpSecret in
// aws.go/azure.go/gcp.go -- encrypted at rest and never serialized back to
// the console.
type Account struct {
	ID        string `gorm:"primaryKey"`
	AccountID string `gorm:"index"`
	Provider  Provider
	Mode      Mode
	Label     string
	Secret    string
	CreatedAt time.Time
}

func (Account) TableName() string { return "karst_cloud_accounts" }

// Response is the wire shape returned to the console -- Secret is
// deliberately absent.
type Response struct {
	ID        string    `json:"id"`
	Provider  Provider  `json:"provider"`
	Mode      Mode      `json:"mode"`
	Label     string    `json:"label,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

func (a *Account) ToResponse() Response {
	return Response{ID: a.ID, Provider: a.Provider, Mode: a.Mode, Label: a.Label, CreatedAt: a.CreatedAt}
}

// CreateRequest is the console's add-credential form, decoded straight off
// the wire. Secret is the raw, provider-shaped credential object -- its
// exact fields depend on Provider (see awsSecret/azureSecret/gcpSecret).
type CreateRequest struct {
	Provider Provider        `json:"provider"`
	Mode     Mode            `json:"mode"`
	Label    string          `json:"label,omitempty"`
	Secret   json.RawMessage `json:"secret"`
}

func (r CreateRequest) validate() error {
	if !r.Provider.Valid() {
		return fmt.Errorf("provider must be one of %q, %q, %q", ProviderAWS, ProviderAzure, ProviderGCP)
	}
	if !r.Mode.Valid() {
		return fmt.Errorf("mode must be %q or %q", ModeReadOnly, ModeReadWrite)
	}
	if len(r.Secret) == 0 {
		return fmt.Errorf("secret must not be empty")
	}
	return validateSecretShape(r.Provider, r.Secret)
}

type Store struct {
	db  *gorm.DB
	enc *crypt.FieldEncrypt
}

// NewStore migrates the table. enc must be non-nil -- see
// ErrEncryptionRequired -- the one deliberate hardening over the
// agentnetwork provider precedent this package otherwise mirrors.
func NewStore(db *gorm.DB, enc *crypt.FieldEncrypt) (*Store, error) {
	if db == nil {
		return nil, fmt.Errorf("cloud accounts: nil database")
	}
	if err := db.AutoMigrate(&Account{}); err != nil {
		return nil, fmt.Errorf("cloud accounts: migrate: %w", err)
	}
	return &Store{db: db, enc: enc}, nil
}

// Create validates, encrypts, and stores a new credential.
func (s *Store) Create(ctx context.Context, req CreateRequest) (*Account, error) {
	accountID, err := accountFromContext(ctx)
	if err != nil {
		return nil, err
	}
	if s.enc == nil {
		return nil, ErrEncryptionRequired
	}
	if err := req.validate(); err != nil {
		return nil, err
	}
	encrypted, err := s.enc.Encrypt(string(req.Secret))
	if err != nil {
		return nil, fmt.Errorf("cloud accounts: encrypt secret: %w", err)
	}
	record := &Account{
		ID:        xid.New().String(),
		AccountID: accountID,
		Provider:  req.Provider,
		Mode:      req.Mode,
		Label:     req.Label,
		Secret:    encrypted,
		CreatedAt: time.Now().UTC(),
	}
	if err := s.db.WithContext(ctx).Create(record).Error; err != nil {
		return nil, fmt.Errorf("cloud accounts: create: %w", err)
	}
	return record, nil
}

// List returns every credential for the account, secrets still encrypted --
// callers that only render Response never need to decrypt at all.
func (s *Store) List(ctx context.Context) ([]Account, error) {
	accountID, err := accountFromContext(ctx)
	if err != nil {
		return nil, err
	}
	var rows []Account
	if err := s.db.WithContext(ctx).Where("account_id = ?", accountID).Order("created_at").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("cloud accounts: list: %w", err)
	}
	return rows, nil
}

// Delete removes a credential, scoped to the caller's account so one
// account can never delete another's row by guessing an id.
func (s *Store) Delete(ctx context.Context, id string) error {
	accountID, err := accountFromContext(ctx)
	if err != nil {
		return err
	}
	result := s.db.WithContext(ctx).Where("account_id = ? AND id = ?", accountID, id).Delete(&Account{})
	if result.Error != nil {
		return fmt.Errorf("cloud accounts: delete: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// get fetches one account, scoped, with its secret decrypted -- used only
// by Discover, never returned to a handler directly.
func (s *Store) get(ctx context.Context, id string) (*Account, error) {
	accountID, err := accountFromContext(ctx)
	if err != nil {
		return nil, err
	}
	if s.enc == nil {
		return nil, ErrEncryptionRequired
	}
	var record Account
	err = s.db.WithContext(ctx).Where("account_id = ? AND id = ?", accountID, id).First(&record).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("cloud accounts: get: %w", err)
	}
	decrypted, err := s.enc.Decrypt(record.Secret)
	if err != nil {
		return nil, fmt.Errorf("cloud accounts: decrypt secret: %w", err)
	}
	record.Secret = decrypted
	return &record, nil
}
