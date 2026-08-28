// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package relayreg

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

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
	AccountID     string `gorm:"primaryKey;size:64"`
	ID            string `gorm:"primaryKey"`
	Address       string `gorm:"not null"`
	TLSServerName string `gorm:"not null"`
	IdentityKey   string `gorm:"not null"`
	Region        string `gorm:"not null"`
}

func (StoredRelay) TableName() string { return "karst_relays" }

type Store struct {
	db             *gorm.DB
	compiledMu     sync.RWMutex
	compiledNetmap map[string]*proto.KarstRelay
}

func NewStore(db *gorm.DB) (*Store, error) {
	if db == nil {
		return nil, fmt.Errorf("relay registry: nil database")
	}
	if err := db.AutoMigrate(&StoredRelay{}); err != nil {
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
	return nil
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
