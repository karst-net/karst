// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// Package regionallow backs ADR-0045 §4c's deployment-wide region allowlist:
// the (provider, region) pairs any pool may ever be declared in, and the
// ones §4b's anchor dispatcher may ever enumerate or probe. Declarative and
// boot-time only (karst-control/main.go's KARST_ALLOWED_REGIONS_FILE), the
// same operational shape tenancy grants and the relay/TURN registries
// already use — see Reconcile.
//
// Deployment-wide, not per-account: ADR-0045 §4c's own section title calls
// this "a deployment-wide region allowlist" — one list for the whole control
// server, projected identically into every account's netmap.
package regionallow

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"

	"gorm.io/gorm"
)

// Document is {provider: [region, ...]}, matching karst-scaler's own
// cost_model::Document.allowed_regions shape and spelling exactly (see
// cost_model.rs's Provider::as_str): "aws", "aws-gov-cloud", "azure",
// "azure-gov-cloud", "gcp". Not validated against that set here — karstd's
// anchor dispatcher is the thing that knows what to do with a given
// provider key, not the server; an unrecognized key is simply never matched
// by any dispatcher arm, the same "unmeasured, not an error" posture §4b's
// own doc comment describes for an anchor that fails to resolve.
type Document map[string][]string

type document struct {
	AllowedRegions Document `json:"allowed_regions"`
}

// Parse validates a KARST_ALLOWED_REGIONS_FILE document.
func Parse(raw []byte) (Document, error) {
	var doc document
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("allowed regions: %w", err)
	}
	for provider, regions := range doc.AllowedRegions {
		if provider == "" {
			return nil, fmt.Errorf("allowed regions: a provider key must not be empty")
		}
		for _, region := range regions {
			if region == "" {
				return nil, fmt.Errorf("allowed regions: provider %q: a region must not be empty", provider)
			}
		}
	}
	return doc.AllowedRegions, nil
}

// Load reads and validates a KARST_ALLOWED_REGIONS_FILE document.
func Load(path string) (Document, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("allowed regions: %w", err)
	}
	doc, err := Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("allowed regions %s: %w", path, err)
	}
	return doc, nil
}

type regionRow struct {
	Provider string `gorm:"primaryKey;size:32"`
	Region   string `gorm:"primaryKey;size:64"`
}

func (regionRow) TableName() string { return "karst_allowed_regions" }

// Store is the allowlist table. Safe for concurrent use.
type Store struct {
	db *gorm.DB
}

// NewStore migrates and returns the allowlist store.
func NewStore(db *gorm.DB) (*Store, error) {
	if err := db.AutoMigrate(&regionRow{}, &bucketRow{}); err != nil {
		return nil, fmt.Errorf("allowed regions: migrate: %w", err)
	}
	return &Store{db: db}, nil
}

// Reconcile makes the table match wanted exactly: entries present in wanted
// but missing from the table are added, entries present in the table but
// absent from wanted are removed. Declarative, not additive — the file is
// the source of truth on every boot, the same convention
// tenancy.Store.Reconcile and the relay/TURN registries already use. An
// empty/nil wanted (KARST_ALLOWED_REGIONS_FILE unset) clears any allowlist a
// previous run left — §4c's own fail-closed default, not a special case.
func (s *Store) Reconcile(ctx context.Context, wanted Document) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var existing []regionRow
		if err := tx.Find(&existing).Error; err != nil {
			return fmt.Errorf("allowed regions: reconcile: list existing: %w", err)
		}

		type key struct{ provider, region string }
		want := make(map[key]bool)
		for provider, regions := range wanted {
			for _, region := range regions {
				want[key{provider, region}] = true
			}
		}
		have := make(map[key]bool, len(existing))
		for _, r := range existing {
			have[key{r.Provider, r.Region}] = true
		}

		for k := range have {
			if !want[k] {
				if err := tx.Where("provider = ? AND region = ?", k.provider, k.region).Delete(&regionRow{}).Error; err != nil {
					return fmt.Errorf("allowed regions: reconcile: revoke %s/%s: %w", k.provider, k.region, err)
				}
			}
		}
		for k := range want {
			if !have[k] {
				if err := tx.Create(&regionRow{Provider: k.provider, Region: k.region}).Error; err != nil {
					return fmt.Errorf("allowed regions: reconcile: allow %s/%s: %w", k.provider, k.region, err)
				}
			}
		}
		return nil
	})
}

// AllowedRegions returns the current allowlist, with each provider's
// regions sorted. Both ends of the netmap content hash (karstd's
// content_version, control/netmap.go's NetmapVersion) must see the same
// deterministic order, since map iteration order is not part of either
// side's contract.
func (s *Store) AllowedRegions(ctx context.Context) (Document, error) {
	var rows []regionRow
	if err := s.db.WithContext(ctx).Order("provider, region").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("allowed regions: list: %w", err)
	}
	doc := make(Document)
	for _, r := range rows {
		doc[r.Provider] = append(doc[r.Provider], r.Region)
	}
	return doc, nil
}
