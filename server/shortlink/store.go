// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// Package shortlink implements the keyword -> URL table behind
// karst-shortlink (ADR-0042) and the HTTP surface that serves it.
//
// One running instance belongs to exactly one account's mesh: it is
// deployed on a single enrolled device, and reachability is scoped by the
// mesh itself rather than by anything in this package. There is
// deliberately no AccountID column here — see ADR-0042's "Data model and
// scope" section for why that absence is the design, not an oversight.
package shortlink

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// ErrNotFound is returned when a keyword has no mapping.
var ErrNotFound = errors.New("shortlink: not found")

// ErrExists is returned by Create when the keyword is already mapped.
var ErrExists = errors.New("shortlink: keyword already exists")

// ErrInvalidKeyword is returned for an empty, reserved, or malformed keyword.
var ErrInvalidKeyword = errors.New("shortlink: invalid keyword")

// ErrInvalidTargetURL is returned when the target does not parse as an
// absolute http(s) URL.
var ErrInvalidTargetURL = errors.New("shortlink: invalid target URL")

// reservedKeywords never resolve as a link, because the HTTP surface (see
// handler.go) reserves these paths for itself.
var reservedKeywords = map[string]struct{}{
	"api":     {},
	"healthz": {},
}

// Link is a single keyword -> URL mapping, as stored and as returned by the
// API.
type Link struct {
	Keyword   string    `gorm:"primaryKey" json:"keyword"`
	TargetURL string    `json:"target_url"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// TableName pins the table name so it does not depend on gorm's pluralization
// of the type name.
func (Link) TableName() string { return "shortlinks" }

// Store is the persistence layer for the keyword table.
type Store struct {
	db *gorm.DB
}

// NewStore opens (and migrates) the shortlink table on an already-open
// database handle.
func NewStore(db *gorm.DB) (*Store, error) {
	if db == nil {
		return nil, fmt.Errorf("shortlink: nil database")
	}
	if err := db.AutoMigrate(&Link{}); err != nil {
		return nil, fmt.Errorf("shortlink: migrate: %w", err)
	}
	return &Store{db: db}, nil
}

// ValidateKeyword reports whether keyword is acceptable as a link name:
// non-empty and not one of the paths this service reserves for itself.
func ValidateKeyword(keyword string) error {
	if keyword == "" {
		return ErrInvalidKeyword
	}
	if _, reserved := reservedKeywords[keyword]; reserved {
		return ErrInvalidKeyword
	}
	return nil
}

// ValidateTargetURL reports whether target is an absolute http(s) URL.
func ValidateTargetURL(target string) error {
	u, err := url.Parse(target)
	if err != nil || !u.IsAbs() || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return ErrInvalidTargetURL
	}
	return nil
}

// Create adds a new mapping. It fails with ErrExists if the keyword is
// already mapped, and with ErrInvalidKeyword / ErrInvalidTargetURL if either
// input fails validation.
func (s *Store) Create(_ context.Context, keyword, targetURL string) (*Link, error) {
	if err := ValidateKeyword(keyword); err != nil {
		return nil, err
	}
	if err := ValidateTargetURL(targetURL); err != nil {
		return nil, err
	}
	link := &Link{Keyword: keyword, TargetURL: targetURL}
	result := s.db.Clauses(clause.OnConflict{DoNothing: true}).Create(link)
	if result.Error != nil {
		return nil, fmt.Errorf("shortlink: create: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return nil, ErrExists
	}
	return link, nil
}

// Get returns the mapping for keyword, or ErrNotFound.
func (s *Store) Get(_ context.Context, keyword string) (*Link, error) {
	var link Link
	if err := s.db.First(&link, "keyword = ?", keyword).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("shortlink: get: %w", err)
	}
	return &link, nil
}

// List returns every mapping, ordered by keyword.
func (s *Store) List(_ context.Context) ([]Link, error) {
	var links []Link
	if err := s.db.Order("keyword").Find(&links).Error; err != nil {
		return nil, fmt.Errorf("shortlink: list: %w", err)
	}
	return links, nil
}

// Update changes an existing mapping's target. It fails with ErrNotFound if
// the keyword is not mapped, and with ErrInvalidTargetURL if the target
// fails validation.
func (s *Store) Update(_ context.Context, keyword, targetURL string) (*Link, error) {
	if err := ValidateTargetURL(targetURL); err != nil {
		return nil, err
	}
	result := s.db.Model(&Link{}).Where("keyword = ?", keyword).Update("target_url", targetURL)
	if result.Error != nil {
		return nil, fmt.Errorf("shortlink: update: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return nil, ErrNotFound
	}
	return s.Get(context.Background(), keyword)
}

// Delete removes a mapping. It fails with ErrNotFound if the keyword is not
// mapped.
func (s *Store) Delete(_ context.Context, keyword string) error {
	result := s.db.Delete(&Link{}, "keyword = ?", keyword)
	if result.Error != nil {
		return fmt.Errorf("shortlink: delete: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}
