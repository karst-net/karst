// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package relayreg

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/netbirdio/netbird/management/server/telemetry"
	"github.com/netbirdio/netbird/shared/management/proto"
)

var (
	ErrNotFound = errors.New("relay registry: relay not found")
	ErrExists   = errors.New("relay registry: relay already exists")
)

var ErrNoAccount = errors.New("relay registry: account scope missing")

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

// StoredRelay is the database form of a validated registry entry. The ID is
// derived from the pinned identity key and is never accepted independently.
type StoredRelay struct {
	AccountID     string `gorm:"primaryKey;size:64" json:"-"`
	ID            string `gorm:"primaryKey" json:"id"`
	Address       string `gorm:"not null" json:"address"`
	TLSServerName string `gorm:"not null" json:"tls_server_name"`
	IdentityKey   string `gorm:"not null" json:"identity_key"`
	Region        string `gorm:"not null" json:"region"`
}

func (StoredRelay) TableName() string { return "karst_relays" }

// Telemetry is what a relay reports about itself — ADR-0021. Aggregate only,
// mirroring bins/karst-relay/src/metrics.rs's own disclosure posture: no
// per-node field belongs here, ever.
type Telemetry struct {
	LocalClients  int
	MeshPeers     int
	RemoteClients int
	BytesTotal    int64
	UptimeSecs    int64
}

// RelayTelemetryRecord is the latest self-reported report a relay has pushed
// to the control plane, and the point of ADR-0021: deliberately its own
// table, not columns on StoredRelay. Registry data is operator-asserted
// configuration; this is relay-asserted, signature-authenticated
// observation, and a caller reading one must never be able to mistake it for
// the other.
type RelayTelemetryRecord struct {
	AccountID     string `gorm:"primaryKey;size:64"`
	ID            string `gorm:"primaryKey"`
	ReportedAt    time.Time
	LocalClients  int
	MeshPeers     int
	RemoteClients int
	BytesTotal    int64
	UptimeSecs    int64
}

func (RelayTelemetryRecord) TableName() string { return "karst_relay_telemetry" }

type Store struct {
	db             *gorm.DB
	compiledMu     sync.RWMutex
	compiledNetmap map[string]*proto.KarstRelay
	// Metrics is optional (nil is a valid, no-op value) and drives
	// management.karst.relay.registry.size.
	Metrics *telemetry.KarstMetrics
}

func NewStore(db *gorm.DB) (*Store, error) {
	if db == nil {
		return nil, fmt.Errorf("relay registry: nil database")
	}
	if err := db.AutoMigrate(&StoredRelay{}, &RelayTelemetryRecord{}); err != nil {
		return nil, fmt.Errorf("relay registry: migrate: %w", err)
	}
	return &Store{db: db, compiledNetmap: make(map[string]*proto.KarstRelay)}, nil
}

func (s *Store) Create(ctx context.Context, entry Entry) (*StoredRelay, error) {
	accountID, err := accountFromContext(ctx)
	if err != nil {
		return nil, err
	}
	relay, err := Compile(entry)
	if err != nil {
		return nil, err
	}
	record := &StoredRelay{AccountID: accountID, ID: base64.RawURLEncoding.EncodeToString(relay.RelayId), Address: relay.Address, TLSServerName: relay.TlsServerName, IdentityKey: entry.IdentityKey, Region: relay.Region}
	var existing StoredRelay
	if err := s.db.Where("account_id = ? AND id = ?", accountID, record.ID).First(&existing).Error; err == nil {
		return nil, ErrExists
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("relay registry: lookup: %w", err)
	}
	// The preflight gives a clear response in the ordinary case; the conflict
	// clause handles two simultaneous creates without exposing a driver-specific
	// unique-constraint message to either caller.
	result := s.db.Clauses(clause.OnConflict{DoNothing: true}).Create(record)
	if result.Error != nil {
		return nil, fmt.Errorf("relay registry: create: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return nil, ErrExists
	}
	s.invalidateCompiled(accountID, record.ID)
	s.recordSize(accountID)
	return record, nil
}

func (s *Store) List(ctx context.Context) ([]StoredRelay, error) {
	accountID, err := accountFromContext(ctx)
	if err != nil {
		return nil, err
	}
	var records []StoredRelay
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
	result := s.db.Where("account_id = ? AND id = ?", accountID, id).Delete(&StoredRelay{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}
	s.invalidateCompiled(accountID, id)
	s.recordSize(accountID)
	return nil
}

// FindByID looks up every registered relay with this id, across every
// account — ADR-0021. Unlike every other method here, deliberately not
// account-scoped: a relay authenticates a telemetry report by proving
// control of the key its own registry entry names, not by presenting an
// account context the way a user session does, so the lookup has to start
// from the id alone. Ordinarily returns at most one row; more than one means
// the same identity key was registered under two accounts, and both should
// see the report confirmed rather than this method guessing which one is
// "right".
func (s *Store) FindByID(_ context.Context, id string) ([]StoredRelay, error) {
	var records []StoredRelay
	if err := s.db.Where("id = ?", id).Find(&records).Error; err != nil {
		return nil, fmt.Errorf("relay registry: find by id: %w", err)
	}
	return records, nil
}

// RecordTelemetry stores the latest self-reported report for one relay under
// one account — ADR-0021. An upsert: a relay reports on an interval, so the
// common case after the first report is always "replace what's there".
func (s *Store) RecordTelemetry(_ context.Context, accountID, id string, t Telemetry) error {
	record := &RelayTelemetryRecord{
		AccountID:     accountID,
		ID:            id,
		ReportedAt:    time.Now(),
		LocalClients:  t.LocalClients,
		MeshPeers:     t.MeshPeers,
		RemoteClients: t.RemoteClients,
		BytesTotal:    t.BytesTotal,
		UptimeSecs:    t.UptimeSecs,
	}
	err := s.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "account_id"}, {Name: "id"}},
		UpdateAll: true,
	}).Create(record).Error
	if err != nil {
		return fmt.Errorf("relay registry: record telemetry: %w", err)
	}
	return nil
}

// LatestTelemetry returns the most recent report for a relay, or nil if none
// has ever arrived — ADR-0021.
func (s *Store) LatestTelemetry(ctx context.Context, id string) (*RelayTelemetryRecord, error) {
	accountID, err := accountFromContext(ctx)
	if err != nil {
		return nil, err
	}
	var record RelayTelemetryRecord
	err = s.db.Where("account_id = ? AND id = ?", accountID, id).First(&record).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("relay registry: latest telemetry: %w", err)
	}
	return &record, nil
}

// recordSize refreshes the cached registry-size gauge for accountID after a
// mutation. One extra indexed count query per Create/Delete, not a
// background poll — Store.Create already does a comparable round trip for
// its own preflight existence check, so this does not introduce a new class
// of cost to the write path, and it stays correct across restarts and
// multiple server processes in a way a purely in-memory increment/decrement
// would not.
func (s *Store) recordSize(accountID string) {
	if s.Metrics == nil {
		return
	}
	var n int64
	if err := s.db.Model(&StoredRelay{}).Where("account_id = ?", accountID).Count(&n).Error; err != nil {
		return
	}
	s.Metrics.SetRelayRegistrySize(accountID, int(n))
}

func (s *Store) NetmapRelays(ctx context.Context) ([]*proto.KarstRelay, error) {
	records, err := s.List(ctx)
	if err != nil {
		return nil, err
	}
	relays := make([]*proto.KarstRelay, 0, len(records))
	for _, record := range records {
		relay, err := s.compiledRelay(record)
		if err != nil {
			return nil, fmt.Errorf("relay registry: stored %s: %w", record.ID, err)
		}
		relays = append(relays, relay)
	}
	return relays, nil
}

func (s *Store) compiledRelay(record StoredRelay) (*proto.KarstRelay, error) {
	key := record.AccountID + "\x00" + record.ID
	s.compiledMu.RLock()
	cached := s.compiledNetmap[key]
	s.compiledMu.RUnlock()
	if cached != nil {
		return cloneRelay(cached), nil
	}
	relay, err := record.ToProto()
	if err != nil {
		return nil, err
	}
	s.compiledMu.Lock()
	if existing := s.compiledNetmap[key]; existing != nil {
		s.compiledMu.Unlock()
		return cloneRelay(existing), nil
	}
	s.compiledNetmap[key] = relay
	s.compiledMu.Unlock()
	return cloneRelay(relay), nil
}

func (s *Store) invalidateCompiled(accountID, id string) {
	s.compiledMu.Lock()
	delete(s.compiledNetmap, accountID+"\x00"+id)
	s.compiledMu.Unlock()
}

func cloneRelay(relay *proto.KarstRelay) *proto.KarstRelay {
	return &proto.KarstRelay{
		Address:       relay.Address,
		RelayId:       append([]byte(nil), relay.RelayId...),
		IdentityKey:   append([]byte(nil), relay.IdentityKey...),
		Region:        relay.Region,
		TlsServerName: relay.TlsServerName,
	}
}

func (r StoredRelay) ToProto() (*proto.KarstRelay, error) {
	return Compile(Entry{Address: r.Address, TLSServerName: r.TLSServerName, IdentityKey: r.IdentityKey, Region: r.Region})
}
