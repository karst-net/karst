// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// Package externalturn stores the admin-entered, account-wide list of
// externally-operated TURN servers issue #420 adds: a URI and the
// operator's own already-provisioned long-term credential for it, never a
// Karst-minted one. This is a configuration surface, not a managed
// resource -- Karst holds no registry of the servers' own state, probes no
// health, and mints no credential. It stores exactly what the admin typed
// and forwards it unchanged to every node over the authenticated netmap
// (see control.NetmapHandler's own projection), the same way DNS resolvers
// or the Relay roster are admin-configured and distributed.
//
// This package deliberately does not reuse karst_control.proto's reserved
// field 16 (the old, Karst-managed `turn_servers`) -- see
// KarstNetmapResponse.external_turn's own doc comment for why that field
// can never come back, even in this narrower shape.
//
// The credential column is encrypted at rest (mirrors infraconnections'
// own ErrEncryptionRequired hardening) and, once the console API package
// wraps this store, is write-only: an admin can set or replace it, but no
// authenticated read ever returns the stored value.
package externalturn

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/rs/xid"
	"gorm.io/gorm"

	"github.com/netbirdio/netbird/util/crypt"
)

var (
	ErrNoAccount          = errors.New("external turn: account scope missing")
	ErrNotFound           = errors.New("external turn: not found")
	ErrEncryptionRequired = errors.New("external turn: the server has no data-store encryption key configured -- TURN credentials cannot be stored unencrypted")
	// ErrInvalid wraps every validate() failure -- a bad uri scheme, an
	// empty username/credential, a malformed reorder set. Distinct from an
	// infrastructure failure (a DB error, say) so the API layer can echo
	// its message verbatim without risking an unrelated internal error
	// leaking through the same path.
	ErrInvalid = errors.New("external turn: invalid")
)

type accountKey struct{}

func WithAccount(ctx context.Context, account string) context.Context {
	return context.WithValue(ctx, accountKey{}, account)
}

func accountFromContext(ctx context.Context) (string, error) {
	account, _ := ctx.Value(accountKey{}).(string)
	if strings.TrimSpace(account) == "" {
		return "", ErrNoAccount
	}
	return account, nil
}

// Server is one admin-entered external TURN server. Credential is
// encrypted at rest and never serialized back to the console -- see the
// package doc comment. Position is the admin-settable, zero-based order a
// node tries entries in; unique only together with AccountID, enforced by
// Reorder rather than a database constraint (see its own doc comment for
// why).
type Server struct {
	ID         string `gorm:"primaryKey"`
	AccountID  string `gorm:"index"`
	Position   int
	URI        string
	Username   string
	Credential string
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

func (Server) TableName() string { return "karst_external_turn_servers" }

// Response is the console/API-facing projection -- Credential deliberately
// has no field here at all, write-only per the package doc comment.
type Response struct {
	ID        string    `json:"id"`
	Position  int       `json:"position"`
	URI       string    `json:"uri"`
	Username  string    `json:"username"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (s *Server) ToResponse() Response {
	return Response{ID: s.ID, Position: s.Position, URI: s.URI, Username: s.Username, CreatedAt: s.CreatedAt, UpdatedAt: s.UpdatedAt}
}

// CreateRequest is the add-entry form. Every field is required -- TURN's
// long-term credential mechanism has no concept of an anonymous or
// credential-less server, so there is no partial-create case to support.
type CreateRequest struct {
	URI        string `json:"uri"`
	Username   string `json:"username"`
	Credential string `json:"credential"`
}

func (r CreateRequest) validate() error {
	if err := validateURI(r.URI); err != nil {
		return err
	}
	if strings.TrimSpace(r.Username) == "" {
		return fmt.Errorf("%w: username must not be empty", ErrInvalid)
	}
	if r.Credential == "" {
		return fmt.Errorf("%w: credential must not be empty", ErrInvalid)
	}
	return nil
}

// validateURI requires turns: (TLS) rather than allowing plain turn: --
// this long-lived, shared-across-every-node credential is the real
// exposure this feature carries (issue #418 §5's risk note), and the
// node-side TURN client already verifies TLS identity, so there is no
// cost to requiring it here too.
func validateURI(uri string) error {
	if !strings.HasPrefix(uri, "turns:") {
		return fmt.Errorf("%w: uri must use the turns: scheme (plain turn: is rejected -- see issue #420)", ErrInvalid)
	}
	if strings.TrimSpace(uri) == "turns:" {
		return fmt.Errorf("%w: uri must name a host", ErrInvalid)
	}
	return nil
}

// UpdateRequest edits an existing entry. URI/Username are plain fields,
// always replaced when present. Credential behaves like a password field:
// nil means "leave the stored credential alone" (the console never has the
// current value to redisplay, so there is nothing to round-trip); a
// present, non-empty value replaces it. An explicitly empty Credential is
// rejected by validate() the same as on Create -- there is no supported
// "clear the credential" state for a server that requires one to connect
// at all.
type UpdateRequest struct {
	URI        string  `json:"uri"`
	Username   string  `json:"username"`
	Credential *string `json:"credential,omitempty"`
}

func (r UpdateRequest) validate() error {
	if err := validateURI(r.URI); err != nil {
		return err
	}
	if strings.TrimSpace(r.Username) == "" {
		return fmt.Errorf("%w: username must not be empty", ErrInvalid)
	}
	if r.Credential != nil && *r.Credential == "" {
		return fmt.Errorf("%w: credential must not be empty", ErrInvalid)
	}
	return nil
}

type Store struct {
	db  *gorm.DB
	enc *crypt.FieldEncrypt
}

// NewStore migrates the table. enc must be non-nil -- see
// ErrEncryptionRequired.
func NewStore(db *gorm.DB, enc *crypt.FieldEncrypt) (*Store, error) {
	if db == nil {
		return nil, fmt.Errorf("external turn: nil database")
	}
	if err := db.AutoMigrate(&Server{}); err != nil {
		return nil, fmt.Errorf("external turn: migrate: %w", err)
	}
	return &Store{db: db, enc: enc}, nil
}

// Create validates, encrypts, and appends a new entry at the end of the
// account's current order.
func (s *Store) Create(ctx context.Context, req CreateRequest) (*Server, error) {
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
	encrypted, err := s.enc.Encrypt(req.Credential)
	if err != nil {
		return nil, fmt.Errorf("external turn: encrypt credential: %w", err)
	}
	var nextPosition int64
	if err := s.db.WithContext(ctx).Model(&Server{}).Where("account_id = ?", accountID).Count(&nextPosition).Error; err != nil {
		return nil, fmt.Errorf("external turn: count: %w", err)
	}
	now := time.Now().UTC()
	record := &Server{
		ID:         xid.New().String(),
		AccountID:  accountID,
		Position:   int(nextPosition),
		URI:        req.URI,
		Username:   req.Username,
		Credential: encrypted,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	if err := s.db.WithContext(ctx).Create(record).Error; err != nil {
		return nil, fmt.Errorf("external turn: create: %w", err)
	}
	return record, nil
}

// Update replaces URI/Username unconditionally and the credential only
// when req.Credential is non-nil -- see UpdateRequest's own doc comment.
func (s *Store) Update(ctx context.Context, id string, req UpdateRequest) (*Server, error) {
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
	updates := map[string]any{
		"uri":        req.URI,
		"username":   req.Username,
		"updated_at": time.Now().UTC(),
	}
	if req.Credential != nil {
		encrypted, err := s.enc.Encrypt(*req.Credential)
		if err != nil {
			return nil, fmt.Errorf("external turn: encrypt credential: %w", err)
		}
		updates["credential"] = encrypted
	}
	result := s.db.WithContext(ctx).Model(&Server{}).Where("account_id = ? AND id = ?", accountID, id).Updates(updates)
	if result.Error != nil {
		return nil, fmt.Errorf("external turn: update: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return nil, ErrNotFound
	}
	var record Server
	if err := s.db.WithContext(ctx).Where("account_id = ? AND id = ?", accountID, id).First(&record).Error; err != nil {
		return nil, fmt.Errorf("external turn: reload: %w", err)
	}
	return &record, nil
}

// List returns every entry for the account in admin order, credential
// still encrypted -- List is used only by the console projection
// (ToResponse never carries it); NetmapServers below is the only reader
// that decrypts.
func (s *Store) List(ctx context.Context) ([]Server, error) {
	accountID, err := accountFromContext(ctx)
	if err != nil {
		return nil, err
	}
	var rows []Server
	if err := s.db.WithContext(ctx).Where("account_id = ?", accountID).Order("position").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("external turn: list: %w", err)
	}
	return rows, nil
}

// Delete removes one entry and closes the gap it leaves in Position, so a
// later Reorder always sees a dense 0..n-1 sequence.
func (s *Store) Delete(ctx context.Context, id string) error {
	accountID, err := accountFromContext(ctx)
	if err != nil {
		return err
	}
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var removed Server
		err := tx.Where("account_id = ? AND id = ?", accountID, id).First(&removed).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("external turn: get: %w", err)
		}
		if err := tx.Where("account_id = ? AND id = ?", accountID, id).Delete(&Server{}).Error; err != nil {
			return fmt.Errorf("external turn: delete: %w", err)
		}
		return tx.Model(&Server{}).
			Where("account_id = ? AND position > ?", accountID, removed.Position).
			UpdateColumn("position", gorm.Expr("position - 1")).Error
	})
}

// Reorder sets a new admin-chosen order in one transaction. ids must be
// exactly the account's current entry IDs, each exactly once -- not a
// subset and not a superset -- so a stale or partial reorder request
// (e.g. a console tab that loaded before another admin added an entry)
// fails explicitly instead of silently dropping or duplicating a
// position.
func (s *Store) Reorder(ctx context.Context, ids []string) error {
	accountID, err := accountFromContext(ctx)
	if err != nil {
		return err
	}
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var current []Server
		if err := tx.Where("account_id = ?", accountID).Find(&current).Error; err != nil {
			return fmt.Errorf("external turn: list: %w", err)
		}
		if len(ids) != len(current) {
			return fmt.Errorf("%w: reorder must name exactly the account's %d existing entries, got %d", ErrInvalid, len(current), len(ids))
		}
		known := make(map[string]struct{}, len(current))
		for _, row := range current {
			known[row.ID] = struct{}{}
		}
		seen := make(map[string]struct{}, len(ids))
		for _, id := range ids {
			if _, ok := known[id]; !ok {
				return fmt.Errorf("%w: reorder named an id that does not belong to this account", ErrInvalid)
			}
			if _, dup := seen[id]; dup {
				return fmt.Errorf("%w: reorder named the same id twice", ErrInvalid)
			}
			seen[id] = struct{}{}
		}
		for position, id := range ids {
			if err := tx.Model(&Server{}).Where("account_id = ? AND id = ?", accountID, id).
				UpdateColumn("position", position).Error; err != nil {
				return fmt.Errorf("external turn: reorder: %w", err)
			}
		}
		return nil
	})
}

// NetmapServers returns every entry for the account in admin order, with
// credentials decrypted -- the one reader allowed to see the plaintext,
// because its only caller forwards it unchanged to the nodes that are
// meant to use it (control.NetmapHandler), never to a console response.
func (s *Store) NetmapServers(ctx context.Context, accountID string) ([]Server, error) {
	if strings.TrimSpace(accountID) == "" {
		return nil, ErrNoAccount
	}
	if s.enc == nil {
		return nil, ErrEncryptionRequired
	}
	var rows []Server
	if err := s.db.WithContext(ctx).Where("account_id = ?", accountID).Order("position").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("external turn: list for netmap: %w", err)
	}
	for i, row := range rows {
		decrypted, err := s.enc.Decrypt(row.Credential)
		if err != nil {
			return nil, fmt.Errorf("external turn: decrypt credential: %w", err)
		}
		rows[i].Credential = decrypted
	}
	return rows, nil
}
