// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// Package infraconnections stores admin-entered AWS/Azure/GCP/Kubernetes/
// Nomad/LXD credentials for the console's Settings page, and uses them to
// discover an account's enabled regions/local-zones/namespaces/datacenters/
// cluster-members for the Authorized Locations picker (cloudcatalog
// supplies the coordinates the cloud providers' own APIs don't return; a
// Kubernetes, Nomad, or LXD connection may instead carry an
// operator-declared point, since a private cluster/scheduler/hypervisor
// environment has no provider-supplied geography).
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
// docs/adr/0045-cost-aware-geographic-scaling-across-providers.md's
// addenda: 2026-10-19 for AWS/Azure/GCP, 2026-10-20 for AWS's
// EnableLocalZone, 2026-10-21 (two addenda) for the Infrastructure
// Connections rename plus Kubernetes, then Nomad, and 2026-10-24 for LXD.
// Three consequences follow directly from the ADR text:
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
// discovery/credentials" there), and Kubernetes/Nomad/LXD/Compose adapters
// are integrations, not new component families -- see the ADR-0045
// addendum.
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
	// ErrCredentialsRejected means the provider itself rejected the stored
	// secret (expired/revoked/wrong keys) -- a precondition on this
	// connection's own state, not a Karst server fault, so handlers should
	// surface it as a 4xx rather than let it fall through to a generic
	// "internal server error" (see discoverAWS).
	ErrCredentialsRejected = errors.New("cloud accounts: the provider rejected the stored credentials")
	ErrInvalid             = errors.New("cloud accounts: invalid request")
	// ErrUnsupportedType means ActuationDriver was asked to actuate a
	// connection whose Type has no infraprovision.Driver implementation
	// registered yet -- see SupportsActuation and ADR-0067. Distinct from
	// ErrInvalid so a caller (estavellealloc.Store.Create) can give a clearer,
	// type-naming message than ErrInvalid's generic one.
	ErrUnsupportedType = errors.New("cloud accounts: this connection type does not support relay allocation yet")
)

// Type identifies what kind of infrastructure a connection authenticates
// to. The legacy /cloud-accounts surface only ever sees the first three --
// every later type can only be created/listed/discovered through
// /infrastructure-connections (see LegacyCreateRequest.toCreateRequest and
// IsLegacy, which the handler-level filtering in package karstapi calls
// rather than naming each non-legacy type itself).
//
// Kept as an explicit case list (here, in Valid, and in every switch over
// Type in this package) rather than a set, so adding a type is a small,
// local diff rather than a design change -- TypeNomad was the second time
// this paid off, TypeLXD the third.
type Type string

const (
	TypeAWS        Type = "aws"
	TypeAzure      Type = "azure"
	TypeGCP        Type = "gcp"
	TypeKubernetes Type = "kubernetes"
	TypeNomad      Type = "nomad"
	TypeLXD        Type = "lxd"
)

func (t Type) Valid() bool {
	return t == TypeAWS || t == TypeAzure || t == TypeGCP || t == TypeKubernetes || t == TypeNomad || t == TypeLXD
}

// SupportsActuation reports whether t has a registered
// infraprovision.Driver implementation at all -- a static, credential-
// free fact, never an API call, so estavellealloc.Store.Create can check it
// inside its own transaction without violating ADR-0058's "no provider
// call inside a transaction" rule (ADR-0067). TypeAzure/TypeGCP/TypeLXD
// have no driver yet; see ActuationDriver and ADR-0067's "v1 driver scope"
// for why.
func (t Type) SupportsActuation() bool {
	return t == TypeAWS || t == TypeNomad || t == TypeKubernetes
}

// IsLegacy reports whether t is one of the three types the /cloud-accounts
// surface understands. Exported so callers outside this package (the
// handler-level filtering in package karstapi) can exclude every
// non-legacy type without naming each one -- see Type's own doc comment.
func (t Type) IsLegacy() bool {
	return t == TypeAWS || t == TypeAzure || t == TypeGCP
}

// Mode says what a credential may be used for. ModeReadOnly stays
// discovery-only, provably incapable of actuating anything. ModeReadWrite
// may additionally drive an ADR-0063 relay allocation against this
// connection's own LaunchDefaults (ADR-0045's 2026-11-04 addendum) -- but
// only once those defaults are set; a read_write connection with no launch
// defaults configured yet is not distinguishable in behavior from
// read_only until an admin sets them.
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
//
// LaunchRegion/LaunchAMIID/LaunchInstanceType/LaunchSubnetID/
// LaunchSecurityGroupIDs (ADR-0045's 2026-11-04 addendum) are the AWS
// launch shape ADR-0063's reconciliation loop actuates a named relay
// allocation against -- set once here, in Settings, never by an allocation
// request itself. Meaningful only for Type TypeAWS, Mode ModeReadWrite;
// zero value on every other row, including pre-existing ones, which is
// exactly "no launch defaults configured yet".
//
// LaunchNomadJobID/LaunchNomadDatacenter (ADR-0067) are the Nomad analog:
// a pre-registered, parameterized job this connection dispatches a relay
// instance from, plus an optional datacenter passed through as dispatch
// Meta. Meaningful only for Type TypeNomad, Mode ModeReadWrite, the same
// gating the AWS fields already follow.
//
// LaunchKubernetesNamespace/LaunchKubernetesImage/LaunchKubernetesCPU/
// LaunchKubernetesMemory/LaunchKubernetesServiceAccount (ADR-0067) are the
// Kubernetes analog: unlike Nomad, there is no pre-registered job to
// dispatch -- this driver builds the Pod itself, so its shape (image,
// a single CPU/memory figure used as both request and limit, an optional
// service account) is launch-defaults data the same way AMI/instance-type
// is for AWS. Meaningful only for Type TypeKubernetes, Mode ModeReadWrite.
type Account struct {
	ID                             string `gorm:"primaryKey"`
	AccountID                      string `gorm:"index"`
	Type                           Type   `gorm:"column:provider"`
	Mode                           Mode
	Label                          string
	Secret                         string
	CreatedAt                      time.Time
	Lat                            *float64
	Lon                            *float64
	LocationLabel                  string
	Status                         Status
	LastValidatedAt                *time.Time
	LastError                      string
	LaunchRegion                   string   `gorm:"column:launch_region"`
	LaunchAMIID                    string   `gorm:"column:launch_ami_id"`
	LaunchInstanceType             string   `gorm:"column:launch_instance_type"`
	LaunchSubnetID                 string   `gorm:"column:launch_subnet_id"`
	LaunchSecurityGroupIDs         []string `gorm:"column:launch_security_group_ids;serializer:json"`
	LaunchNomadJobID               string   `gorm:"column:launch_nomad_job_id"`
	LaunchNomadDatacenter          string   `gorm:"column:launch_nomad_datacenter"`
	LaunchKubernetesNamespace      string   `gorm:"column:launch_kubernetes_namespace"`
	LaunchKubernetesImage          string   `gorm:"column:launch_kubernetes_image"`
	LaunchKubernetesCPU            string   `gorm:"column:launch_kubernetes_cpu"`
	LaunchKubernetesMemory         string   `gorm:"column:launch_kubernetes_memory"`
	LaunchKubernetesServiceAccount string   `gorm:"column:launch_kubernetes_service_account"`
}

func (Account) TableName() string { return "karst_cloud_accounts" }

// AllocationReferenceChecker lets Delete refuse to remove a connection a
// live ADR-0063 relay allocation still depends on, without this package
// importing estavellealloc -- estavellealloc already imports infraconnections the
// other way, for its own Create's reverse validation, so the dependency
// has to run through a narrow interface instead. nil (the default) means
// "nothing wired yet": Delete behaves exactly as it did before this
// existed. Wired once, at boot, by SetAllocationReferenceChecker.
type AllocationReferenceChecker interface {
	// HasNonTerminalAllocations reports whether accountID has any
	// relay allocation referencing connectionID that is not yet fully
	// deprovisioned. accountID is passed explicitly rather than carried on
	// ctx: estavellealloc's own WithAccount uses a different, unexported
	// context key than this package's, so ctx alone cannot carry it across
	// the package boundary.
	HasNonTerminalAllocations(ctx context.Context, accountID, connectionID string) (bool, error)
}

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
	ID                             string     `json:"id"`
	Type                           Type       `json:"type"`
	Mode                           Mode       `json:"mode"`
	Label                          string     `json:"label,omitempty"`
	CreatedAt                      time.Time  `json:"created_at"`
	Lat                            *float64   `json:"lat,omitempty"`
	Lon                            *float64   `json:"lon,omitempty"`
	LocationLabel                  string     `json:"location_label,omitempty"`
	Status                         Status     `json:"status,omitempty"`
	LastValidatedAt                *time.Time `json:"last_validated_at,omitempty"`
	LastError                      string     `json:"last_error,omitempty"`
	LaunchRegion                   string     `json:"launch_region,omitempty"`
	LaunchAMIID                    string     `json:"launch_ami_id,omitempty"`
	LaunchInstanceType             string     `json:"launch_instance_type,omitempty"`
	LaunchSubnetID                 string     `json:"launch_subnet_id,omitempty"`
	LaunchSecurityGroupIDs         []string   `json:"launch_security_group_ids,omitempty"`
	LaunchNomadJobID               string     `json:"launch_nomad_job_id,omitempty"`
	LaunchNomadDatacenter          string     `json:"launch_nomad_datacenter,omitempty"`
	LaunchKubernetesNamespace      string     `json:"launch_kubernetes_namespace,omitempty"`
	LaunchKubernetesImage          string     `json:"launch_kubernetes_image,omitempty"`
	LaunchKubernetesCPU            string     `json:"launch_kubernetes_cpu,omitempty"`
	LaunchKubernetesMemory         string     `json:"launch_kubernetes_memory,omitempty"`
	LaunchKubernetesServiceAccount string     `json:"launch_kubernetes_service_account,omitempty"`
	// SupportsAllocation mirrors Type.SupportsActuation() -- a derived,
	// read-only convenience so a console caller never has to duplicate
	// that type-list itself (ADR-0067).
	SupportsAllocation bool `json:"supports_allocation"`
}

func (a *Account) ToResponse() Response {
	return Response{
		ID: a.ID, Type: a.Type, Mode: a.Mode, Label: a.Label, CreatedAt: a.CreatedAt,
		Lat: a.Lat, Lon: a.Lon, LocationLabel: a.LocationLabel,
		Status: a.Status, LastValidatedAt: a.LastValidatedAt, LastError: a.LastError,
		LaunchRegion: a.LaunchRegion, LaunchAMIID: a.LaunchAMIID, LaunchInstanceType: a.LaunchInstanceType,
		LaunchSubnetID: a.LaunchSubnetID, LaunchSecurityGroupIDs: a.LaunchSecurityGroupIDs,
		LaunchNomadJobID: a.LaunchNomadJobID, LaunchNomadDatacenter: a.LaunchNomadDatacenter,
		LaunchKubernetesNamespace: a.LaunchKubernetesNamespace, LaunchKubernetesImage: a.LaunchKubernetesImage,
		LaunchKubernetesCPU: a.LaunchKubernetesCPU, LaunchKubernetesMemory: a.LaunchKubernetesMemory,
		LaunchKubernetesServiceAccount: a.LaunchKubernetesServiceAccount,
		SupportsAllocation:             a.Type.SupportsActuation(),
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
	if !r.Provider.IsLegacy() {
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
		return fmt.Errorf("type must be one of %q, %q, %q, %q, %q", TypeAWS, TypeAzure, TypeGCP, TypeKubernetes, TypeNomad)
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
	db          *gorm.DB
	enc         *crypt.FieldEncrypt
	allocations AllocationReferenceChecker
}

// SetAllocationReferenceChecker wires Delete's cross-package reference
// check (see AllocationReferenceChecker's own doc comment). Called once,
// at boot (internals/karst/bootstrap), after both this Store and
// estavellealloc's own Store exist -- never from NewStore itself, so adding
// this dependency needed no change to NewStore's signature or any of its
// existing callers.
func (s *Store) SetAllocationReferenceChecker(checker AllocationReferenceChecker) {
	s.allocations = checker
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
// to gate here. Refuses while a relay allocation (ADR-0063) still
// references this connection and has not finished deprovisioning -- see
// AllocationReferenceChecker; a nil checker (nothing wired yet) skips this
// check entirely, unchanged from before it existed.
func (s *Store) Delete(ctx context.Context, id string) error {
	accountID, err := accountFromContext(ctx)
	if err != nil {
		return err
	}
	if s.allocations != nil {
		inUse, err := s.allocations.HasNonTerminalAllocations(ctx, accountID, id)
		if err != nil {
			return fmt.Errorf("cloud accounts: checking relay allocation references: %w", err)
		}
		if inUse {
			return fmt.Errorf("%w: a relay allocation still references this connection; deprovision it first", ErrInvalid)
		}
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

// UpdateLaunchDefaultsRequest is Settings' own way to set or change the AWS
// launch shape (ADR-0063; ADR-0045's 2026-11-04 addendum) a named relay
// allocation actuates against -- deliberately separate from CreateRequest
// so an admin can change these without re-entering the connection's secret.
// Every field replaces the stored value, including to empty; there is no
// partial-update shape here, matching this package's other full-replace
// writes (Create itself never merges either).
type UpdateLaunchDefaultsRequest struct {
	Region           string   `json:"region,omitempty"`
	AMIID            string   `json:"ami_id,omitempty"`
	InstanceType     string   `json:"instance_type,omitempty"`
	SubnetID         string   `json:"subnet_id,omitempty"`
	SecurityGroupIDs []string `json:"security_group_ids,omitempty"`
}

// UpdateLaunchDefaults sets this connection's AWS launch shape. Refused for
// any connection that is not currently a read-write AWS connection --
// launch defaults have no meaning on any other type/mode, and
// ActuationDriver (actuation.go) re-validates both anyway, so this is a
// clearer error at write time rather than the only check.
func (s *Store) UpdateLaunchDefaults(ctx context.Context, id string, req UpdateLaunchDefaultsRequest) (*Account, error) {
	accountID, err := accountFromContext(ctx)
	if err != nil {
		return nil, err
	}
	var record Account
	if err := s.db.WithContext(ctx).Where("account_id = ? AND id = ?", accountID, id).First(&record).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("cloud accounts: get: %w", err)
	}
	if record.Type != TypeAWS || record.Mode != ModeReadWrite {
		return nil, fmt.Errorf("%w: launch defaults only apply to a read-write AWS connection", ErrInvalid)
	}
	update := Account{
		LaunchRegion:           req.Region,
		LaunchAMIID:            req.AMIID,
		LaunchInstanceType:     req.InstanceType,
		LaunchSubnetID:         req.SubnetID,
		LaunchSecurityGroupIDs: req.SecurityGroupIDs,
	}
	err = s.db.WithContext(ctx).Model(&record).
		Select("LaunchRegion", "LaunchAMIID", "LaunchInstanceType", "LaunchSubnetID", "LaunchSecurityGroupIDs").
		Updates(update).Error
	if err != nil {
		return nil, fmt.Errorf("cloud accounts: update launch defaults: %w", err)
	}
	record.LaunchRegion, record.LaunchAMIID, record.LaunchInstanceType = update.LaunchRegion, update.LaunchAMIID, update.LaunchInstanceType
	record.LaunchSubnetID, record.LaunchSecurityGroupIDs = update.LaunchSubnetID, update.LaunchSecurityGroupIDs
	return &record, nil
}

// UpdateNomadLaunchDefaultsRequest is Settings' own way to set or change
// the Nomad launch shape (ADR-0067) a named relay allocation actuates
// against -- the Nomad analog of UpdateLaunchDefaultsRequest, same
// full-replace semantics.
type UpdateNomadLaunchDefaultsRequest struct {
	JobID      string `json:"job_id,omitempty"`
	Datacenter string `json:"datacenter,omitempty"`
}

// UpdateNomadLaunchDefaults sets this connection's Nomad launch shape.
// Refused for any connection that is not currently a read-write Nomad
// connection -- see UpdateLaunchDefaults's own doc comment for why this
// is a clearer error at write time rather than the only check;
// ActuationDriver re-validates both anyway.
func (s *Store) UpdateNomadLaunchDefaults(ctx context.Context, id string, req UpdateNomadLaunchDefaultsRequest) (*Account, error) {
	accountID, err := accountFromContext(ctx)
	if err != nil {
		return nil, err
	}
	var record Account
	if err := s.db.WithContext(ctx).Where("account_id = ? AND id = ?", accountID, id).First(&record).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("cloud accounts: get: %w", err)
	}
	if record.Type != TypeNomad || record.Mode != ModeReadWrite {
		return nil, fmt.Errorf("%w: launch defaults only apply to a read-write Nomad connection", ErrInvalid)
	}
	update := Account{LaunchNomadJobID: req.JobID, LaunchNomadDatacenter: req.Datacenter}
	err = s.db.WithContext(ctx).Model(&record).
		Select("LaunchNomadJobID", "LaunchNomadDatacenter").
		Updates(update).Error
	if err != nil {
		return nil, fmt.Errorf("cloud accounts: update nomad launch defaults: %w", err)
	}
	record.LaunchNomadJobID, record.LaunchNomadDatacenter = update.LaunchNomadJobID, update.LaunchNomadDatacenter
	return &record, nil
}

// UpdateKubernetesLaunchDefaultsRequest is Settings' own way to set or
// change the Kubernetes launch shape (ADR-0067) a named relay allocation
// actuates against -- the Kubernetes analog of UpdateLaunchDefaultsRequest,
// same full-replace semantics. CPU/Memory are parsed with Kubernetes's own
// resource.Quantity syntax (e.g. "250m", "256Mi") by
// kubernetesdriver.New's caller, not here; this just stores the strings.
type UpdateKubernetesLaunchDefaultsRequest struct {
	Namespace      string `json:"namespace,omitempty"`
	Image          string `json:"image,omitempty"`
	CPU            string `json:"cpu,omitempty"`
	Memory         string `json:"memory,omitempty"`
	ServiceAccount string `json:"service_account,omitempty"`
}

// UpdateKubernetesLaunchDefaults sets this connection's Kubernetes launch
// shape. Refused for any connection that is not currently a read-write
// Kubernetes connection -- see UpdateLaunchDefaults's own doc comment for
// why this is a clearer error at write time rather than the only check;
// ActuationDriver re-validates both anyway.
func (s *Store) UpdateKubernetesLaunchDefaults(ctx context.Context, id string, req UpdateKubernetesLaunchDefaultsRequest) (*Account, error) {
	accountID, err := accountFromContext(ctx)
	if err != nil {
		return nil, err
	}
	var record Account
	if err := s.db.WithContext(ctx).Where("account_id = ? AND id = ?", accountID, id).First(&record).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("cloud accounts: get: %w", err)
	}
	if record.Type != TypeKubernetes || record.Mode != ModeReadWrite {
		return nil, fmt.Errorf("%w: launch defaults only apply to a read-write Kubernetes connection", ErrInvalid)
	}
	update := Account{
		LaunchKubernetesNamespace: req.Namespace, LaunchKubernetesImage: req.Image,
		LaunchKubernetesCPU: req.CPU, LaunchKubernetesMemory: req.Memory,
		LaunchKubernetesServiceAccount: req.ServiceAccount,
	}
	err = s.db.WithContext(ctx).Model(&record).
		Select("LaunchKubernetesNamespace", "LaunchKubernetesImage", "LaunchKubernetesCPU", "LaunchKubernetesMemory", "LaunchKubernetesServiceAccount").
		Updates(update).Error
	if err != nil {
		return nil, fmt.Errorf("cloud accounts: update kubernetes launch defaults: %w", err)
	}
	record.LaunchKubernetesNamespace, record.LaunchKubernetesImage = update.LaunchKubernetesNamespace, update.LaunchKubernetesImage
	record.LaunchKubernetesCPU, record.LaunchKubernetesMemory = update.LaunchKubernetesCPU, update.LaunchKubernetesMemory
	record.LaunchKubernetesServiceAccount = update.LaunchKubernetesServiceAccount
	return &record, nil
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
