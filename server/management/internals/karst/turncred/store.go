// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package turncred

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/netbirdio/netbird/management/internals/karst/geo"
)

var (
	ErrNotFound = errors.New("turn registry: turn server not found")
	ErrExists   = errors.New("turn registry: turn server already exists")
)

var ErrNoAccount = errors.New("turn registry: account scope missing")

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

// StoredTurnServer is the database form of a validated registry entry. The ID
// is derived from the URI and is never accepted independently — there is no
// identity key here the way relayreg.StoredRelay has one, so the URI is the
// closest thing to a stable identifier a TURN server has.
type StoredTurnServer struct {
	AccountID string `gorm:"primaryKey;size:64" json:"-"`
	ID        string `gorm:"primaryKey" json:"id"`
	URI       string `gorm:"not null" json:"uri"`
	Region    string `gorm:"not null" json:"region"`

	// LocationLat/LocationLon/LocationLabel -- see relayreg.StoredRelay's
	// own fields of the same name for why these are flat nullable columns
	// rather than an embedded struct.
	LocationLat   *float64 `json:"-"`
	LocationLon   *float64 `json:"-"`
	LocationLabel string   `json:"-"`
}

func (StoredTurnServer) TableName() string { return "karst_turn_servers" }

type Store struct {
	db *gorm.DB
}

func NewStore(db *gorm.DB) (*Store, error) {
	if db == nil {
		return nil, fmt.Errorf("turn registry: nil database")
	}
	if err := db.AutoMigrate(&StoredTurnServer{}); err != nil {
		return nil, fmt.Errorf("turn registry: migrate: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Create(ctx context.Context, entry Entry) (*StoredTurnServer, error) {
	accountID, err := accountFromContext(ctx)
	if err != nil {
		return nil, err
	}
	validated, err := entry.validate()
	if err != nil {
		return nil, err
	}
	record := &StoredTurnServer{
		AccountID: accountID,
		ID:        base64.RawURLEncoding.EncodeToString([]byte(validated.URI)),
		URI:       validated.URI,
		Region:    validated.Region,
	}
	if validated.Location != nil {
		lat, lon := validated.Location.Lat, validated.Location.Lon
		record.LocationLat, record.LocationLon, record.LocationLabel = &lat, &lon, validated.Location.Label
	}
	var existing StoredTurnServer
	if err := s.db.Where("account_id = ? AND id = ?", accountID, record.ID).First(&existing).Error; err == nil {
		return nil, ErrExists
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("turn registry: lookup: %w", err)
	}
	// The preflight gives a clear response in the ordinary case; the conflict
	// clause handles two simultaneous creates without exposing a driver-specific
	// unique-constraint message to either caller — mirrors relayreg.Store.Create.
	result := s.db.Clauses(clause.OnConflict{DoNothing: true}).Create(record)
	if result.Error != nil {
		return nil, fmt.Errorf("turn registry: create: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return nil, ErrExists
	}
	return record, nil
}

// DeleteByURI removes the stored turn server whose ID is derived from uri
// -- the deenroll counterpart of Create, for a caller that knows the URI
// it registered (or will register) rather than the server's own generated
// ID. ADR-0045 §7b's own scaler driver is the intended caller: unlike an
// admin removing an entry by ID from a list the console already fetched,
// a driver builds an instance's URI deterministically at create() time
// (the same way karst-scaler-k8s already builds a relay's pod FQDN) and
// has no reason to List first just to recover the ID Create would derive
// from that same URI anyway.
func (s *Store) DeleteByURI(ctx context.Context, uri string) error {
	validated, err := Entry{URI: uri}.validate()
	if err != nil {
		return err
	}
	id := base64.RawURLEncoding.EncodeToString([]byte(validated.URI))
	return s.Delete(ctx, id)
}

func (s *Store) List(ctx context.Context) ([]StoredTurnServer, error) {
	accountID, err := accountFromContext(ctx)
	if err != nil {
		return nil, err
	}
	var records []StoredTurnServer
	if err := s.db.Where("account_id = ?", accountID).Order("id").Find(&records).Error; err != nil {
		return nil, err
	}
	return records, nil
}

func (s *Store) Delete(ctx context.Context, id string) error {
	accountID, err := accountFromContext(ctx)
	if err != nil {
		return err
	}
	result := s.db.Where("account_id = ? AND id = ?", accountID, id).Delete(&StoredTurnServer{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// Entries lists the account's stored servers as the [Entry] type turncred's
// own NetmapEntries consumes, so a DB-backed registry needs no changes to
// that function.
func (s *Store) Entries(ctx context.Context) ([]Entry, error) {
	records, err := s.List(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Entry, 0, len(records))
	for _, record := range records {
		entry := Entry{URI: record.URI, Region: record.Region}
		if record.LocationLat != nil {
			entry.Location = &geo.Location{Lat: *record.LocationLat, Lon: *record.LocationLon, Label: record.LocationLabel}
		}
		out = append(out, entry)
	}
	return out, nil
}

// LocationFor resolves one stored server's declared NOC-map position, the
// turncred counterpart of a relay's own locationFor (api/nodes.go) --
// turncred has no telemetry, so there is no detected alternative to prefer.
func (r StoredTurnServer) LocationFor() *geo.Location {
	if r.LocationLat == nil {
		return nil
	}
	return &geo.Location{Lat: *r.LocationLat, Lon: *r.LocationLon, Label: r.LocationLabel}
}
