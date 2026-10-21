// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// Package infraconnections stores admin-entered AWS/Azure/GCP/Kubernetes
// credentials for the console's Settings page, and uses them to discover an
// account's enabled regions/local-zones/namespaces for the Authorized
// Locations picker (cloudcatalog supplies the coordinates the cloud
// providers' own APIs don't return; a Kubernetes connection may instead
// carry an operator-declared point, since a private cluster has no
// provider-supplied geography).
//
// This package was, until the "Infrastructure Connections" rename (issue
// #406), named cloudaccounts and covered only the three cloud providers. The
// rename is additive: the same database table/columns and row IDs are kept
// (see Account's gorm tags), and the pre-existing /cloud-accounts API routes
// (package karstapi) keep working unchanged -- see LegacyCreateRequest/
// LegacyResponse/DiscoveredRegion/DiscoverLegacy, which freeze that wire
// shape. The new, generalized CreateRequest/Response/DiscoveredResource/
// Discover is what /infrastructure-connections uses.
//
// ADR-0045 §6 says the control plane "must not gain cloud-account
// credentials as a side effect of this feature... A compromise of the
// control plane must not yield the ability to spend the operator's money."
// This package is a deliberate, scoped amendment to that boundary -- see
// docs/adr/0045-cost-aware-geographic-scaling-across-providers.md's two
// addenda (2026-10-19 for AWS/Azure/GCP, 2026-10-21 for the Infrastructure
// Connections rename and Kubernetes). Three consequences follow directly
// from the ADR text:
//
//   - Mode exists so an operator can hand over read-only (status/discovery
//     only, can never place an order or create a workload) credentials and
//     keep read-write ones elsewhere, or out entirely.
//   - Storing ModeReadWrite here records intent for a future actuation
//     path, with exactly one narrow, named exception carved out ahead of
//     it: EnableLocalZone, which opts an AWS Local Zone's group into use
//     (ModifyAvailabilityZoneGroup) and nothing else -- no create/destroy
//     of a compute resource. Real create/destroy actuation is still
//     ADR-0045 §5/§7 Phase 2 (drivers, signed enrollment, a budget circuit
//     breaker) -- unbuilt, on purpose. Nothing in this package should grow
//     a further provisioning call without that phase's safeguards landing
//     first; EnableLocalZone is the one call the ADR's second addendum
//     deliberately lets through ahead of it, not a precedent for adding
//     more the same way.
//   - Status/LastValidatedAt/LastError record whether the last Discover
//     call succeeded, as a narrow, concrete fact -- not a generic
//     capability bitmask on the credential. ADR-0016 explicitly rejected a
//     capability-bitmask-on-a-credential design ("enforces scoping by
//     rule... a verifier remembered to check a mask"); this package follows
//     that lesson by keeping Mode and Status as the only two capability-
//     adjacent fields, both narrow and both already reasoned about above.
//
// The issue that drove this generalization (#406) also asks to stay within
// ADR-0056's four component families: this package belongs to "control
// services" in that ADR's terms (it explicitly names "transport
// discovery/credentials" there), and Kubernetes/Nomad/Compose adapters are
// integrations, not new component families -- see the ADR-0045 addendum.
package infraconnections

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/rs/xid"
	"gorm.io/gorm"

	"github.com/netbirdio/netbird/management/internals/karst/geo"
	"github.com/netbirdio/netbird/util/crypt"
)

var (
	ErrNoAccount          = errors.New("cloud accounts: account scope missing")
	ErrNotFound           = errors.New("cloud accounts: not found")
	ErrEncryptionRequired = errors.New("cloud accounts: the server has no data-store encryption key configured -- cloud credentials cannot be stored unencrypted")
)

// Type identifies what kind of infrastructure a connection authenticates
// to. The legacy /cloud-accounts surface only ever sees the first three --
// TypeKubernetes can only be created/listed/discovered through
// /infrastructure-connections (see LegacyCreateRequest.toCreateRequest and
// the handler-level filtering in package karstapi).
//
// Kept as an explicit case list (here, in Valid, and in every switch over
// Type in this package) rather than a set, so a future TypeNomad is a
// small, local diff rather than a design change.
type Type string

const (
	TypeAWS        Type = "aws"
	TypeAzure      Type = "azure"
	TypeGCP        Type = "gcp"
	TypeKubernetes Type = "kubernetes"
)

func (t Type) Valid() bool {
	return t == TypeAWS || t == TypeAzure || t == TypeGCP || t == TypeKubernetes
}

// isLegacy reports whether t is one of the three types the /cloud-accounts
// surface understands.
func (t Type) isLegacy() bool {
	return t == TypeAWS || t == TypeAzure || t == TypeGCP
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

// Status is the outcome of the most recent Discover/DiscoverLegacy call for
// a connection -- empty until the first such call completes. A narrow,
// concrete fact, not a capability matrix; see the package doc comment.
type Status string

const (
	StatusUnknown Status = ""
	StatusOK      Status = "ok"
	StatusError   Status = "error"
)

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

// Account is one admin-entered infrastructure connection. Secret is a
// type-shaped JSON blob -- see awsSecret/azureSecret/gcpSecret/
// kubernetesSecret in aws.go/azure.go/gcp.go/kubernetes.go -- encrypted at
// rest and never serialized back to the console.
//
// Type keeps the pre-rename "provider" column name via its gorm tag --
// AutoMigrate matches on the tag, not the Go field name, so this rename
// needs no data migration and no column is orphaned. Lat/Lon/LocationLabel
// and Status/LastValidatedAt/LastError are new, nullable columns: existing
// rows get zero values for them, which is exactly "no declared location"/
// "not yet validated".
type Account struct {
	ID              string `gorm:"primaryKey"`
	AccountID       string `gorm:"index"`
	Type            Type   `gorm:"column:provider"`
	Mode            Mode
	Label           string
	Secret          string
	CreatedAt       time.Time
	Lat             *float64
	Lon             *float64
	LocationLabel   string
	Status          Status
	LastValidatedAt *time.Time
	LastError       string
}

func (Account) TableName() string { return "karst_cloud_accounts" }

// LegacyResponse is byte-for-byte what this package used to serialize as
// cloudaccounts.Response, before the rename -- the /cloud-accounts routes
// keep emitting exactly this, deprecated but unchanged.
type LegacyResponse struct {
	ID        string    `json:"id"`
	Provider  Type      `json:"provider"`
	Mode      Mode      `json:"mode"`
	Label     string    `json:"label,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

func (a *Account) ToLegacyResponse() LegacyResponse {
	return LegacyResponse{ID: a.ID, Provider: a.Type, Mode: a.Mode, Label: a.Label, CreatedAt: a.CreatedAt}
}

// Response is the generalized /infrastructure-connections wire shape.
type Response struct {
	ID              string     `json:"id"`
	Type            Type       `json:"type"`
	Mode            Mode       `json:"mode"`
	Label           string     `json:"label,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	Lat             *float64   `json:"lat,omitempty"`
	Lon             *float64   `json:"lon,omitempty"`
	LocationLabel   string     `json:"location_label,omitempty"`
	Status          Status     `json:"status,omitempty"`
	LastValidatedAt *time.Time `json:"last_validated_at,omitempty"`
	LastError       string     `json:"last_error,omitempty"`
}

func (a *Account) ToResponse() Response {
	return Response{
		ID: a.ID, Type: a.Type, Mode: a.Mode, Label: a.Label, CreatedAt: a.CreatedAt,
		Lat: a.Lat, Lon: a.Lon, LocationLabel: a.LocationLabel,
		Status: a.Status, LastValidatedAt: a.LastValidatedAt, LastError: a.LastError,
	}
}

// LegacyCreateRequest is decoded by the /cloud-accounts POST handler --
// same wire shape (field "provider") as before the rename.
type LegacyCreateRequest struct {
	Provider Type            `json:"provider"`
	Mode     Mode            `json:"mode"`
	Label    string          `json:"label,omitempty"`
	Secret   json.RawMessage `json:"secret"`
}

// toCreateRequest refuses TypeKubernetes so a kubernetes-typed row can never
// be created through the legacy surface -- it can only ever come from
// /infrastructure-connections.
func (r LegacyCreateRequest) toCreateRequest() (CreateRequest, error) {
	if !r.Provider.isLegacy() {
		return CreateRequest{}, fmt.Errorf("provider must be one of %q, %q, %q", TypeAWS, TypeAzure, TypeGCP)
	}
	return CreateRequest{Type: r.Provider, Mode: r.Mode, Label: r.Label, Secret: r.Secret}, nil
}

// CreateRequest is the generalized add-connection form. Secret is the raw,
// type-shaped credential object -- its exact fields depend on Type (see
// awsSecret/azureSecret/gcpSecret/kubernetesSecret). Lat/Lon/LocationLabel
// are an optional operator-declared location, meaningful for a type with no
// provider-supplied geography (Kubernetes today); both-or-neither.
type CreateRequest struct {
	Type          Type            `json:"type"`
	Mode          Mode            `json:"mode"`
	Label         string          `json:"label,omitempty"`
	Secret        json.RawMessage `json:"secret"`
	Lat           *float64        `json:"lat,omitempty"`
	Lon           *float64        `json:"lon,omitempty"`
	LocationLabel string          `json:"location_label,omitempty"`
}

func (r CreateRequest) validate() error {
	if !r.Type.Valid() {
		return fmt.Errorf("type must be one of %q, %q, %q, %q", TypeAWS, TypeAzure, TypeGCP, TypeKubernetes)
	}
	if !r.Mode.Valid() {
		return fmt.Errorf("mode must be %q or %q", ModeReadOnly, ModeReadWrite)
	}
	if len(r.Secret) == 0 {
		return fmt.Errorf("secret must not be empty")
	}
	if (r.Lat == nil) != (r.Lon == nil) {
		return fmt.Errorf("lat and lon must both be set or both omitted")
	}
	if r.Lat != nil {
		if err := geo.ValidLocation(*r.Lat, *r.Lon); err != nil {
			return err
		}
	}
	return validateSecretShape(r.Type, r.Secret)
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

// Create validates, encrypts, and stores a new connection.
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
		ID:            xid.New().String(),
		AccountID:     accountID,
		Type:          req.Type,
		Mode:          req.Mode,
		Label:         req.Label,
		Secret:        encrypted,
		CreatedAt:     time.Now().UTC(),
		Lat:           req.Lat,
		Lon:           req.Lon,
		LocationLabel: req.LocationLabel,
	}
	if err := s.db.WithContext(ctx).Create(record).Error; err != nil {
		return nil, fmt.Errorf("cloud accounts: create: %w", err)
	}
	return record, nil
}

// CreateLegacy is the /cloud-accounts POST handler's entry point -- see
// LegacyCreateRequest.toCreateRequest for why it can never create a
// TypeKubernetes row.
func (s *Store) CreateLegacy(ctx context.Context, req LegacyCreateRequest) (*Account, error) {
	converted, err := req.toCreateRequest()
	if err != nil {
		return nil, err
	}
	return s.Create(ctx, converted)
}

// List returns every connection for the account, secrets still encrypted --
// callers that only render Response/LegacyResponse never need to decrypt at
// all. Deliberately unfiltered by Type: the /cloud-accounts handler is
// responsible for filtering out TypeKubernetes rows before responding (see
// its own doc comment), since that is a wire-compatibility concern of that
// one route, not a property of the underlying store.
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

// Delete removes a connection, scoped to the caller's account so one
// account can never delete another's row by guessing an id. Deliberately
// type-agnostic: unlike List/Create/Discover, delete never echoes the row's
// type back on the wire, so there is no legacy-schema compatibility concern
// to gate here.
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

// get fetches one connection, scoped, with its secret decrypted -- used
// only by Discover/DiscoverLegacy, never returned to a handler directly.
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

// recordDiscoveryResult updates a row's Status/LastValidatedAt/LastError
// after a Discover/DiscoverLegacy call, success or failure. Best-effort: a
// failure to persist the status is logged nowhere and returned nowhere --
// it must never override discoverErr, which is what the caller actually
// asked about.
func (s *Store) recordDiscoveryResult(ctx context.Context, id string, discoverErr error) {
	accountID, err := accountFromContext(ctx)
	if err != nil {
		return
	}
	now := time.Now().UTC()
	updates := map[string]any{"last_validated_at": now}
	if discoverErr != nil {
		updates["status"] = StatusError
		updates["last_error"] = discoverErr.Error()
	} else {
		updates["status"] = StatusOK
		updates["last_error"] = ""
	}
	s.db.WithContext(ctx).Model(&Account{}).Where("account_id = ? AND id = ?", accountID, id).Updates(updates)
}
