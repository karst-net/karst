// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package relayreg

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
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

	// LocationLat/LocationLon/LocationLabel are the operator-declared NOC-map
	// position (ADR-0046 §1), flat nullable columns rather than an embedded
	// struct to match gorm's column-per-field convention elsewhere in this
	// file. LocationLat is nil exactly when no location was declared; Lon and
	// Label are only meaningful when it isn't.
	LocationLat   *float64 `json:"-"`
	LocationLon   *float64 `json:"-"`
	LocationLabel string   `json:"-"`
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
	// DetectedLat/DetectedLon are the relay's self-reported position
	// (ADR-0048), detected via cloud instance metadata -- nil when the
	// relay didn't detect one (not running on a supported cloud, detection
	// disabled, or the probe failed/timed out). Never a default coordinate.
	DetectedLat *float64
	DetectedLon *float64
	// RTTUnder20ms/RTT20To50ms/RTT50To100ms/RTTOver100ms are ADR-0045 §4a's
	// demand-attribution signal: how many of this relay's currently
	// connected clients last measured RTT in each bucket. Aggregate counts
	// only, never a per-client value -- the same discipline every other
	// field here already follows.
	RTTUnder20ms int64
	RTT20To50ms  int64
	RTT50To100ms int64
	RTTOver100ms int64
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
	// DetectedLat/DetectedLon -- see Telemetry.DetectedLat/DetectedLon.
	DetectedLat *float64
	DetectedLon *float64
	// RTTUnder20ms/RTT20To50ms/RTT50To100ms/RTTOver100ms -- see
	// Telemetry's own fields of the same name.
	RTTUnder20ms int64
	RTT20To50ms  int64
	RTT50To100ms int64
	RTTOver100ms int64
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
	if relay.Location != nil {
		lat, lon := relay.Location.Lat, relay.Location.Lon
		record.LocationLat, record.LocationLon, record.LocationLabel = &lat, &lon, relay.Location.Label
	}
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
		DetectedLat:   t.DetectedLat,
		DetectedLon:   t.DetectedLon,
		RTTUnder20ms:  t.RTTUnder20ms,
		RTT20To50ms:   t.RTT20To50ms,
		RTT50To100ms:  t.RTT50To100ms,
		RTTOver100ms:  t.RTTOver100ms,
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

// RegionDemand is one (region, account)'s aggregated RTT histogram —
// ADR-0045 §4a's per-(region, aquifer) demand signal, summed across every
// relay in that region this account has registered. AccountID is the
// aquifer modulo the deployment-wide prefix (ADR-0033).
type RegionDemand struct {
	Region       string
	AccountID    string
	RTTUnder20ms int64
	RTT20To50ms  int64
	RTT50To100ms int64
	RTTOver100ms int64
}

// DemandByRegion aggregates every account's latest relay telemetry RTT
// buckets, grouped by (region, account) — ADR-0045 §7 Phase 1's whole
// demand-side input. Region lives on karst_relays; karst_relay_telemetry
// carries no region column of its own, so this correlates the two in Go by
// (account_id, id) rather than a SQL join — there is no precedent anywhere
// in this package for a GROUP BY query, and matching one up by hand in Go
// avoids betting this on gorm's generated column spelling for a
// multi-acronym field name (RTTUnder20ms) that nothing here has ever had to
// reference from raw SQL before.
//
// Unlike every other method on this Store — and like FindByID above, for a
// related reason — this is deliberately NOT scoped by WithAccount: a
// deployment-wide Advisor needs the full per-(region,aquifer) picture, not
// one account's slice of it. Every row still carries its own AccountID, so
// nothing here hides which aquifer a number belongs to; it is the *caller*
// of this method that must be trusted with cross-account visibility, which
// is why its only caller (the new /karst/v1/demand/regions endpoint) is
// gated behind its own dedicated role rather than the ordinary per-account
// KarstControl grant every other relayreg-backed endpoint uses.
func (s *Store) DemandByRegion(ctx context.Context) ([]RegionDemand, error) {
	var relays []StoredRelay
	if err := s.db.WithContext(ctx).Select("account_id", "id", "region").Find(&relays).Error; err != nil {
		return nil, fmt.Errorf("relay registry: demand by region: list relays: %w", err)
	}
	regionOf := make(map[string]string, len(relays))
	for _, r := range relays {
		regionOf[r.AccountID+"\x00"+r.ID] = r.Region
	}

	var reports []RelayTelemetryRecord
	if err := s.db.WithContext(ctx).Find(&reports).Error; err != nil {
		return nil, fmt.Errorf("relay registry: demand by region: list telemetry: %w", err)
	}

	type key struct{ region, accountID string }
	totals := make(map[key]*RegionDemand)
	for _, report := range reports {
		region, ok := regionOf[report.AccountID+"\x00"+report.ID]
		if !ok {
			// A telemetry row for a relay no longer in the registry (deleted
			// since its last report) names no region to attribute it to —
			// skipped rather than guessed, the same "simply unmeasured"
			// posture the rest of ADR-0045 takes for data it cannot place.
			continue
		}
		k := key{region, report.AccountID}
		d, ok := totals[k]
		if !ok {
			d = &RegionDemand{Region: region, AccountID: report.AccountID}
			totals[k] = d
		}
		d.RTTUnder20ms += report.RTTUnder20ms
		d.RTT20To50ms += report.RTT20To50ms
		d.RTT50To100ms += report.RTT50To100ms
		d.RTTOver100ms += report.RTTOver100ms
	}

	result := make([]RegionDemand, 0, len(totals))
	for _, d := range totals {
		result = append(result, *d)
	}
	// Deterministic order: callers (the HTTP handler, its tests, and any
	// future consumer) must not depend on Go's randomized map iteration.
	sort.Slice(result, func(i, j int) bool {
		if result[i].Region != result[j].Region {
			return result[i].Region < result[j].Region
		}
		return result[i].AccountID < result[j].AccountID
	})
	return result, nil
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
	cloned := &proto.KarstRelay{
		Address:       relay.Address,
		RelayId:       append([]byte(nil), relay.RelayId...),
		IdentityKey:   append([]byte(nil), relay.IdentityKey...),
		Region:        relay.Region,
		TlsServerName: relay.TlsServerName,
	}
	if relay.Location != nil {
		cloned.Location = &proto.RelayLocation{Lat: relay.Location.Lat, Lon: relay.Location.Lon, Label: relay.Location.Label}
	}
	return cloned
}

func (r StoredRelay) ToProto() (*proto.KarstRelay, error) {
	entry := Entry{Address: r.Address, TLSServerName: r.TLSServerName, IdentityKey: r.IdentityKey, Region: r.Region}
	if r.LocationLat != nil {
		entry.Location = &Location{Lat: *r.LocationLat, Lon: *r.LocationLon, Label: r.LocationLabel}
	}
	return Compile(entry)
}
