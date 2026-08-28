// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// Package bedrock persists the small piece of Bedrock state owned by the
// coordination server. Authority signatures and private material never enter
// this store: it tracks coverage and the operator-selected enforcement mode.
package bedrock

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"gorm.io/gorm"
)

const (
	ModeOff       = "off"
	ModeAdvisory  = "advisory"
	ModeEnforcing = "enforcing"
)

var ErrAcknowledgementMismatch = errors.New("bedrock: acknowledgement list does not match uncovered nodes")

// Configuration is the account-scoped operator-controlled Bedrock configuration.
// It intentionally has no key columns: roots and authority private keys stay
// on offline signer devices.
type Configuration struct {
	AccountID string `gorm:"primaryKey;size:64"`
	Mode      string `gorm:"not null"`
	Quorum    uint   `gorm:"not null"`
	UpdatedAt time.Time
}

func (Configuration) TableName() string { return "karst_bedrock_configuration" }

// There is deliberately no coverage table here.
//
// One existed: a `karst_bedrock_coverage` row per covered handle, described as
// "the derived state needed to make the enforcement decision deterministic".
// **Nothing ever wrote one**, so every node read as uncovered and the lockout
// guard below demanded that an operator acknowledge cutting off the entire
// network in order to enable enforcement — including nodes that were fully
// countersigned. A guard that always asks for everything is one an operator
// learns to confirm without reading, which is the opposite of what it is for
// (FINDINGS 57).
//
// It is gone rather than filled in. Coverage is a property of the verified
// chain and `State.IsCovered` computes it; a table alongside would be a second
// answer to a question with one, free to disagree with the log the nodes
// themselves enforce against.

type Store struct{ db *gorm.DB }

func NewStore(db *gorm.DB) (*Store, error) {
	if db == nil {
		return nil, errors.New("bedrock: nil database")
	}
	if err := db.AutoMigrate(&Configuration{}); err != nil {
		return nil, fmt.Errorf("bedrock: migrate: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Configuration(ctx context.Context, accountID string) (*Configuration, error) {
	var c Configuration
	if err := s.db.WithContext(ctx).Where("account_id = ?", accountID).Attrs(Configuration{AccountID: accountID, Mode: ModeOff, Quorum: 1}).FirstOrCreate(&c).Error; err != nil {
		return nil, fmt.Errorf("bedrock: configuration: %w", err)
	}
	return &c, nil
}

// SetMode requires an exact acknowledgement set when moving to enforcing.
// Exactness matters: accepting a superset makes a stale console confirmation
// appear valid after a new uncovered node joins; accepting a subset hides a
// node that will be cut off.
//
// The uncovered set is computed here from the verified chain rather than taken
// from the caller, so the guard cannot be satisfied by a caller that computed
// it wrongly or not at all. A nil state means no log, under which nothing is
// covered and every enrolled node is about to be cut off — which an operator
// must still acknowledge by name.
func (s *Store) SetMode(ctx context.Context, accountID, mode string, acknowledged []string, state *State, enrolled map[string]PeerKeys, at int64) (*Configuration, error) {
	if mode != ModeOff && mode != ModeAdvisory && mode != ModeEnforcing {
		return nil, fmt.Errorf("bedrock: invalid mode %q", mode)
	}
	if mode == ModeEnforcing {
		uncovered := UncoveredAt(state, enrolled, at)
		if !sameStrings(uncovered, acknowledged) {
			return nil, fmt.Errorf("%w: required %v", ErrAcknowledgementMismatch, uncovered)
		}
	}
	if _, err := s.Configuration(ctx, accountID); err != nil {
		return nil, err
	}
	if err := s.db.WithContext(ctx).Model(&Configuration{}).Where("account_id = ?", accountID).Update("mode", mode).Error; err != nil {
		return nil, fmt.Errorf("bedrock: update mode: %w", err)
	}
	return s.Configuration(ctx, accountID)
}

// UncoveredAt returns the enrolled handles a verified chain does not cover at
// time at, sorted.
//
// The single answer to "who would be cut off", used by the lockout guard and by
// whatever renders the confirmation. A nil state means no log and so covers
// nobody.
func UncoveredAt(state *State, enrolled map[string]PeerKeys, at int64) []string {
	if state == nil {
		out := make([]string, 0, len(enrolled))
		for handle := range enrolled {
			out = append(out, handle)
		}
		sort.Strings(out)
		return out
	}
	return state.Uncovered(enrolled, at)
}

func sameStrings(a, b []string) bool {
	a = append([]string(nil), a...)
	b = append([]string(nil), b...)
	sort.Strings(a)
	sort.Strings(b)
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
