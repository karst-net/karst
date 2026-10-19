// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// Package routetelemetry stores issues #281 and #371's per-route egress and
// ingress byte/packet counts, self-reported by each route's current gateway
// over the existing,
// already-authenticated control channel (karst_control.proto's
// KarstNetmapRequest.route_observations) — the same channel
// KarstSessionObservation and ADR-0045 §4b's KarstAnchorRtt already use,
// not a second signed endpoint the way relay telemetry (ADR-0021) needs,
// since a node already has a live session here and a relay does not.
//
// Latest snapshot only, by design: the same posture relayreg's own
// RecordTelemetry already takes for ADR-0021, and the one ADR-0047 expects
// of any new control-plane metric field (history belongs in an operator's
// own Prometheus, reached through its re-export, not a bespoke store here).
// A route's current gateway can change (exit-node gateway groups are
// active-passive, #281's own background), so "latest" naturally tracks
// whichever node most recently reported — there is nothing to reconcile
// across a handover, only a new latest value.
package routetelemetry

import (
	"context"
	"fmt"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// StoredRouteBytes is at most one row per (account, route): the latest
// egress and ingress counters self-reported by whichever node is currently
// that route's gateway (issues #281, #371).
type StoredRouteBytes struct {
	AccountID      string `gorm:"primaryKey;size:64"`
	RouteID        string `gorm:"primaryKey"`
	Bytes          uint64
	Packets        uint64
	IngressBytes   uint64
	IngressPackets uint64
	ReportedAt     time.Time
}

func (StoredRouteBytes) TableName() string { return "karst_route_telemetry" }

type Store struct{ db *gorm.DB }

func NewStore(db *gorm.DB) (*Store, error) {
	if db == nil {
		return nil, fmt.Errorf("route telemetry: nil database")
	}
	if err := db.AutoMigrate(&StoredRouteBytes{}); err != nil {
		return nil, fmt.Errorf("route telemetry: migrate: %w", err)
	}
	return &Store{db: db}, nil
}

// RouteReport is one gateway's self-reported egress/ingress counters for
// one route — grouped rather than four positional uint64s, so a caller
// cannot transpose egress and ingress by positional accident.
type RouteReport struct {
	Bytes          uint64
	Packets        uint64
	IngressBytes   uint64
	IngressPackets uint64
}

// RecordRouteBytes replaces the stored counters for one route. An upsert,
// not an accumulation: the reported values are already running totals from
// the gateway's own long-lived nftables counter (gateway.rs's own doc
// comment on route_bytes), so summing successive reports would double what
// the kernel already counted once.
func (s *Store) RecordRouteBytes(ctx context.Context, accountID, routeID string, report RouteReport) error {
	if accountID == "" || routeID == "" {
		return fmt.Errorf("route telemetry: account and route id must not be empty")
	}
	record := &StoredRouteBytes{
		AccountID:      accountID,
		RouteID:        routeID,
		Bytes:          report.Bytes,
		Packets:        report.Packets,
		IngressBytes:   report.IngressBytes,
		IngressPackets: report.IngressPackets,
		ReportedAt:     time.Now(),
	}
	err := s.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "account_id"}, {Name: "route_id"}},
		UpdateAll: true,
	}).Create(record).Error
	if err != nil {
		return fmt.Errorf("route telemetry: record %s: %w", routeID, err)
	}
	return nil
}

// LatestByRoute reads back every route this account has a stored report
// for, keyed by route_id for an O(1) caller-side lookup.
func (s *Store) LatestByRoute(ctx context.Context, accountID string) (map[string]StoredRouteBytes, error) {
	var records []StoredRouteBytes
	if err := s.db.WithContext(ctx).Where("account_id = ?", accountID).Find(&records).Error; err != nil {
		return nil, fmt.Errorf("route telemetry: list: %w", err)
	}
	byRoute := make(map[string]StoredRouteBytes, len(records))
	for _, record := range records {
		byRoute[record.RouteID] = record
	}
	return byRoute, nil
}
