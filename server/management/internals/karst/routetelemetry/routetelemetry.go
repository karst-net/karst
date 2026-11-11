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
// Latest snapshot only, by design: the same posture estavellereg's own
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

	"github.com/netbirdio/netbird/management/server/migration"
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
	// ForwardingActive is issue #404's Gateway readiness signal: whether
	// this route's forward-accept rule was actually installed and live in
	// its gateway's own nftables table at the moment of the report, not
	// merely whether any bytes have moved yet. See gateway.rs's
	// `KarstRouteObservation.forwarding_active` doc comment.
	ForwardingActive bool
	ReportedAt       time.Time
}

func (StoredRouteBytes) TableName() string { return "karst_route_telemetry" }

// StoredAvenHealth keeps candidate health independent of route-wide counters.
// Legacy route rows cannot be attributed to a node and are never backfilled.
type StoredAvenHealth struct {
	ReadinessReported bool
	AccountID         string `gorm:"primaryKey;size:64"`
	AvenID            string `gorm:"primaryKey"`
	RouteID           string `gorm:"primaryKey"`
	ForwardingActive  bool
	// ObservedEgressIP is issue #554's verification half of ADR-0068's
	// pinned_egress_ip: this candidate's own self-reported outbound
	// address toward the route, read back from
	// `KarstRouteObservation.observed_egress_ip`. Empty when the route
	// carries no pinned_egress_ip (nothing to compare against) or the
	// node's local probe failed. Never compared to a stored copy of
	// pinned_egress_ip here -- the live route record is the only source
	// of truth for that, read at query time, so the two can never drift
	// apart from each other independently of the real world.
	ObservedEgressIP string
	ReportedAt       time.Time
}

func (StoredAvenHealth) TableName() string { return "karst_aven_health" }

type Store struct{ db *gorm.DB }

func NewStore(db *gorm.DB) (*Store, error) {
	if db == nil {
		return nil, fmt.Errorf("route telemetry: nil database")
	}
	// ADR-0069's clean-break Gateway->Aven rename: idempotent, no-op once
	// the rename has happened.
	if err := migration.RenameTable[StoredAvenHealth](context.Background(), db, "karst_gateway_health"); err != nil {
		return nil, fmt.Errorf("route telemetry: migrate: %w", err)
	}
	if err := db.AutoMigrate(&StoredRouteBytes{}, &StoredAvenHealth{}); err != nil {
		return nil, fmt.Errorf("route telemetry: migrate: %w", err)
	}
	return &Store{db: db}, nil
}

// RouteReport is one gateway's self-reported egress/ingress counters for
// one route — grouped rather than four positional uint64s, so a caller
// cannot transpose egress and ingress by positional accident.
type RouteReport struct {
	ReadinessReported bool
	// AvenID comes from the authenticated session, never the report payload.
	AvenID           string
	Bytes            uint64
	Packets          uint64
	IngressBytes     uint64
	IngressPackets   uint64
	ForwardingActive bool
	// ObservedEgressIP, issue #554 -- see StoredAvenHealth's own doc
	// comment on this field.
	ObservedEgressIP string
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
		AccountID:        accountID,
		RouteID:          routeID,
		Bytes:            report.Bytes,
		Packets:          report.Packets,
		IngressBytes:     report.IngressBytes,
		IngressPackets:   report.IngressPackets,
		ForwardingActive: report.ForwardingActive,
		ReportedAt:       time.Now(),
	}
	err := s.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "account_id"}, {Name: "route_id"}},
		UpdateAll: true,
	}).Create(record).Error
	if err != nil {
		return fmt.Errorf("route telemetry: record %s: %w", routeID, err)
	}
	if report.AvenID != "" {
		health := StoredAvenHealth{AccountID: accountID, AvenID: report.AvenID,
			RouteID: routeID, ForwardingActive: report.ForwardingActive, ReportedAt: record.ReportedAt,
			ReadinessReported: report.ReadinessReported || report.ForwardingActive,
			ObservedEgressIP:  report.ObservedEgressIP}
		if err := s.db.WithContext(ctx).Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "account_id"}, {Name: "aven_id"}, {Name: "route_id"}},
			UpdateAll: true,
		}).Create(&health).Error; err != nil {
			return fmt.Errorf("gateway health: record: %w", err)
		}
	}
	return nil
}

// LatestByAven returns account-scoped reports keyed first by node, then resource.
func (s *Store) LatestByAven(ctx context.Context, accountID string) (map[string]map[string]StoredAvenHealth, error) {
	var rows []StoredAvenHealth
	if err := s.db.WithContext(ctx).Where("account_id = ?", accountID).Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("gateway health: list: %w", err)
	}
	result := make(map[string]map[string]StoredAvenHealth)
	for _, row := range rows {
		if result[row.AvenID] == nil {
			result[row.AvenID] = make(map[string]StoredAvenHealth)
		}
		result[row.AvenID][row.RouteID] = row
	}
	return result, nil
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
