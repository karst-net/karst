// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// Package ephemeralanchor backs ADR-0045 §4d's admin-maintained list of
// pre-provisioned, pre-enrolled AWS Local Zone probe instances — never a
// karst-relay, never part of any pool — kept reachable only in short,
// published duty-cycle windows. Declarative and boot-time configurable
// (karst-control/main.go's KARST_EPHEMERAL_ANCHORS_FILE), the same
// operational shape regionallow's own allowlist already uses — see
// Reconcile.
//
// Deployment-wide, not per-account: like regionallow, one list for the
// whole control server, projected identically into every account's netmap.
//
// **Absent or empty means never probed, by construction, not by
// convention.** An empty anchor list must make both the client probe pass
// and bins/karst-anchor-scheduler do nothing at all — no TCP connection, no
// AWS API call — the same fail-closed default regionallow.go documents for
// allowed_regions. This package only stores the list; the zero-cost
// guarantee lives in the two readers (karstd's ephemeral_anchor_probe.rs,
// karst-anchor-scheduler), each independently tested for it.
package ephemeralanchor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var (
	// ErrExists is returned by AddAnchor for a label already registered.
	ErrExists = errors.New("ephemeral anchors: anchor already exists")
	// ErrNotFound is returned by RemoveAnchor for a label not currently
	// registered.
	ErrNotFound = errors.New("ephemeral anchors: anchor not found")
)

// defaultPort is the port every ephemeral anchor instance is reached on:
// its own default sshd, never a custom listener. See the module doc comment
// for why these instances run nothing else — validated empirically by the
// #348 measurement run, docs/measurements/local-zone-rtt-us-2026-10-18.
const defaultPort = 22

// AnchorEntry is one ephemeral anchor. Region and InstanceID are operator/
// scheduler-only bookkeeping (bins/karst-anchor-scheduler needs them to call
// EC2's DescribeInstances/StartInstances/StopInstances) and are never
// projected into the netmap — karstd clients only ever see Label, Address,
// and Port (karst_control.proto's KarstEphemeralAnchors.Entry).
type AnchorEntry struct {
	Label      string
	Region     string
	InstanceID string
	Address    string
	Port       uint32
}

// Document is the KARST_EPHEMERAL_ANCHORS_FILE shape.
type Document struct {
	Anchors             []AnchorEntry
	WindowPeriodSeconds uint32
	DutyCycleSeconds    uint32
}

type document struct {
	Anchors []struct {
		Label      string `json:"label"`
		Region     string `json:"region"`
		InstanceID string `json:"instance_id"`
		Address    string `json:"address"`
		Port       uint32 `json:"port"`
	} `json:"ephemeral_anchors"`
	WindowPeriodSeconds uint32 `json:"window_period_seconds"`
	DutyCycleSeconds    uint32 `json:"duty_cycle_seconds"`
}

// Parse validates a KARST_EPHEMERAL_ANCHORS_FILE document.
func Parse(raw []byte) (Document, error) {
	var doc document
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return Document{}, fmt.Errorf("ephemeral anchors: %w", err)
	}
	seen := make(map[string]bool, len(doc.Anchors))
	out := Document{
		Anchors:             make([]AnchorEntry, 0, len(doc.Anchors)),
		WindowPeriodSeconds: doc.WindowPeriodSeconds,
		DutyCycleSeconds:    doc.DutyCycleSeconds,
	}
	for _, a := range doc.Anchors {
		if a.Label == "" {
			return Document{}, fmt.Errorf("ephemeral anchors: a label must not be empty")
		}
		if seen[a.Label] {
			return Document{}, fmt.Errorf("ephemeral anchors: duplicate label %q", a.Label)
		}
		seen[a.Label] = true
		if a.Address == "" {
			return Document{}, fmt.Errorf("ephemeral anchors: %q: an address must not be empty", a.Label)
		}
		if a.InstanceID == "" {
			return Document{}, fmt.Errorf("ephemeral anchors: %q: an instance_id must not be empty", a.Label)
		}
		if a.Region == "" {
			// bins/karst-anchor-scheduler needs a real AWS region to build
			// an EC2 client for this anchor -- an empty region here is not
			// a request for "ambient default," it is a config that would
			// silently never be reconciled against any client.
			return Document{}, fmt.Errorf("ephemeral anchors: %q: a region must not be empty", a.Label)
		}
		port := a.Port
		if port == 0 {
			port = defaultPort
		}
		out.Anchors = append(out.Anchors, AnchorEntry{
			Label:      a.Label,
			Region:     a.Region,
			InstanceID: a.InstanceID,
			Address:    a.Address,
			Port:       port,
		})
	}
	return out, nil
}

// Load reads and validates a KARST_EPHEMERAL_ANCHORS_FILE document.
func Load(path string) (Document, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Document{}, fmt.Errorf("ephemeral anchors: %w", err)
	}
	doc, err := Parse(raw)
	if err != nil {
		return Document{}, fmt.Errorf("ephemeral anchors %s: %w", path, err)
	}
	return doc, nil
}

type anchorRow struct {
	Label      string `gorm:"primaryKey;size:128"`
	Region     string `gorm:"size:32"`
	InstanceID string `gorm:"size:32"`
	Address    string `gorm:"size:255"`
	Port       uint32
}

func (anchorRow) TableName() string { return "karst_ephemeral_anchors" }

// scheduleRow is the one deployment-wide duty-cycle schedule. A fixed,
// always-present singleton row (ID always 1, never created a second time)
// rather than a table keyed some other way: unlike anchors, there is
// exactly one schedule for the whole deployment, the same "one list for the
// whole control server" posture the package doc comment describes for the
// anchor list itself.
type scheduleRow struct {
	ID                  uint8 `gorm:"primaryKey"`
	WindowPeriodSeconds uint32
	DutyCycleSeconds    uint32
}

func (scheduleRow) TableName() string { return "karst_ephemeral_anchor_schedule" }

const scheduleRowID = 1

// Store is the ephemeral-anchor table pair. Safe for concurrent use.
type Store struct {
	db *gorm.DB
}

// NewStore migrates and returns the ephemeral-anchor store.
func NewStore(db *gorm.DB) (*Store, error) {
	if err := db.AutoMigrate(&anchorRow{}, &scheduleRow{}, &bucketRow{}); err != nil {
		return nil, fmt.Errorf("ephemeral anchors: migrate: %w", err)
	}
	return &Store{db: db}, nil
}

// Reconcile makes the anchor table match wanted.Anchors exactly (declarative
// replace, the identical convention regionallow.Store.Reconcile uses) and
// sets the schedule singleton to wanted's two schedule fields. An empty/zero
// wanted (KARST_EPHEMERAL_ANCHORS_FILE unset) clears any anchors a previous
// run left and zeroes the schedule — this package's own fail-closed default,
// not a special case.
func (s *Store) Reconcile(ctx context.Context, wanted Document) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var existing []anchorRow
		if err := tx.Find(&existing).Error; err != nil {
			return fmt.Errorf("ephemeral anchors: reconcile: list existing: %w", err)
		}

		want := make(map[string]AnchorEntry, len(wanted.Anchors))
		for _, a := range wanted.Anchors {
			want[a.Label] = a
		}
		have := make(map[string]bool, len(existing))
		for _, r := range existing {
			have[r.Label] = true
		}

		for label := range have {
			if _, ok := want[label]; !ok {
				if err := tx.Where("label = ?", label).Delete(&anchorRow{}).Error; err != nil {
					return fmt.Errorf("ephemeral anchors: reconcile: remove %s: %w", label, err)
				}
			}
		}
		for label, a := range want {
			if !have[label] {
				row := anchorRow{Label: a.Label, Region: a.Region, InstanceID: a.InstanceID, Address: a.Address, Port: a.Port}
				if err := tx.Create(&row).Error; err != nil {
					return fmt.Errorf("ephemeral anchors: reconcile: add %s: %w", label, err)
				}
			}
		}

		row := scheduleRow{ID: scheduleRowID, WindowPeriodSeconds: wanted.WindowPeriodSeconds, DutyCycleSeconds: wanted.DutyCycleSeconds}
		if err := tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "id"}},
			DoUpdates: clause.AssignmentColumns([]string{"window_period_seconds", "duty_cycle_seconds"}),
		}).Create(&row).Error; err != nil {
			return fmt.Errorf("ephemeral anchors: reconcile: set schedule: %w", err)
		}
		return nil
	})
}

// AddAnchor registers one more ephemeral anchor, for a future console
// editor -- a single-row addition alongside Reconcile's own whole-document
// replace, which boot-time file loading keeps using unchanged. Neither goes
// through the other, the same discipline regionallow.Store.AddRegion
// documents for the identical reason.
func (s *Store) AddAnchor(ctx context.Context, entry AnchorEntry) error {
	if entry.Label == "" || entry.Address == "" || entry.InstanceID == "" || entry.Region == "" {
		return fmt.Errorf("ephemeral anchors: label, address, instance_id, and region must not be empty")
	}
	port := entry.Port
	if port == 0 {
		port = defaultPort
	}
	db := s.db.WithContext(ctx)
	var existing anchorRow
	if err := db.Where("label = ?", entry.Label).First(&existing).Error; err == nil {
		return ErrExists
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return fmt.Errorf("ephemeral anchors: lookup: %w", err)
	}
	row := anchorRow{Label: entry.Label, Region: entry.Region, InstanceID: entry.InstanceID, Address: entry.Address, Port: port}
	result := db.Clauses(clause.OnConflict{DoNothing: true}).Create(&row)
	if result.Error != nil {
		return fmt.Errorf("ephemeral anchors: add %s: %w", entry.Label, result.Error)
	}
	if result.RowsAffected == 0 {
		return ErrExists
	}
	return nil
}

// RemoveAnchor revokes one ephemeral anchor by label.
func (s *Store) RemoveAnchor(ctx context.Context, label string) error {
	result := s.db.WithContext(ctx).Where("label = ?", label).Delete(&anchorRow{})
	if result.Error != nil {
		return fmt.Errorf("ephemeral anchors: remove %s: %w", label, result.Error)
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// Anchors returns every ephemeral anchor, sorted by label. Both ends of the
// netmap content hash (karstd's content_version, control/netmap.go's
// NetmapVersion) must see the same deterministic order, since map/slice
// iteration order from a plain query is not part of either side's contract.
func (s *Store) Anchors(ctx context.Context) ([]AnchorEntry, error) {
	var rows []anchorRow
	if err := s.db.WithContext(ctx).Order("label").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("ephemeral anchors: list: %w", err)
	}
	entries := make([]AnchorEntry, 0, len(rows))
	for _, r := range rows {
		entries = append(entries, AnchorEntry{Label: r.Label, Region: r.Region, InstanceID: r.InstanceID, Address: r.Address, Port: r.Port})
	}
	return entries, nil
}

// SetSchedule sets the one deployment-wide duty-cycle schedule, for a future
// console editor -- independent of Reconcile, the same non-interaction
// discipline AddAnchor documents.
func (s *Store) SetSchedule(ctx context.Context, windowPeriodSeconds, dutyCycleSeconds uint32) error {
	row := scheduleRow{ID: scheduleRowID, WindowPeriodSeconds: windowPeriodSeconds, DutyCycleSeconds: dutyCycleSeconds}
	if err := s.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		DoUpdates: clause.AssignmentColumns([]string{"window_period_seconds", "duty_cycle_seconds"}),
	}).Create(&row).Error; err != nil {
		return fmt.Errorf("ephemeral anchors: set schedule: %w", err)
	}
	return nil
}

// Schedule returns the current duty-cycle schedule. Both zero
// (0, 0, nil) when no schedule row has ever been written -- Reconcile
// always writes one (even a zero one), so this only happens before the
// first boot-time Reconcile ever runs.
func (s *Store) Schedule(ctx context.Context) (windowPeriodSeconds, dutyCycleSeconds uint32, err error) {
	var row scheduleRow
	if err := s.db.WithContext(ctx).Where("id = ?", scheduleRowID).First(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return 0, 0, nil
		}
		return 0, 0, fmt.Errorf("ephemeral anchors: get schedule: %w", err)
	}
	return row.WindowPeriodSeconds, row.DutyCycleSeconds, nil
}
