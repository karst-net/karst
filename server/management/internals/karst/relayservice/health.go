// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package relayservice

import (
	"context"
	"sync"
	"time"

	"github.com/netbirdio/netbird/management/internals/karst/turncred"
	"github.com/netbirdio/netbird/management/internals/karst/turnhealth"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	"gorm.io/gorm/clause"
)

const healthInterval = time.Minute
const healthMaxAge = 3 * time.Minute

type turnObservation struct {
	AccountID  string `gorm:"primaryKey;size:64"`
	TurnID     string `gorm:"primaryKey"`
	State      string
	ObservedAt time.Time
	DurationMS int64
}

func (turnObservation) TableName() string { return "karst_relay_turn_health" }

// TurnHealth is deliberately separate from operator-asserted configuration.
// Its readiness describes authenticated allocation from control's network
// vantage, not data delivery, TLS identity for plain TURN, or client paths.
type TurnHealth struct {
	Source     string     `json:"source"`
	State      string     `json:"state"`
	LastResult string     `json:"last_result,omitempty"`
	ObservedAt *time.Time `json:"observed_at,omitempty"`
	DurationMS *int64     `json:"duration_ms,omitempty"`
}

func (s *Store) turnHealth(ctx context.Context, account, id string, now time.Time) (TurnHealth, error) {
	health := TurnHealth{Source: "control_allocation_probe", State: "unknown"}
	var records []turnObservation
	if err := s.db.WithContext(ctx).Where("account_id = ? AND turn_id = ?", account, id).Limit(1).Find(&records).Error; err != nil {
		return health, err
	}
	if len(records) == 0 {
		return health, nil
	}
	record := records[0]
	health.State, health.LastResult = record.State, record.State
	health.ObservedAt, health.DurationMS = &record.ObservedAt, &record.DurationMS
	if record.ObservedAt.After(now) || now.Sub(record.ObservedAt) > healthMaxAge {
		health.State = "stale"
	}
	return health, nil
}

type allocationProbe func(context.Context, string, turncred.Credential) turnhealth.Result

// CheckHealth checks each distinct account/backend association once, with at
// most four allocations in flight. A new bounded credential is minted for
// every check. Observation storage never receives credentials or raw errors.
func (s *Store) CheckHealth(ctx context.Context, minter *turncred.Minter, probe allocationProbe) error {
	var targets []struct{ AccountID, TurnID, URI string }
	err := s.db.WithContext(ctx).Table("karst_relay_services AS service").
		Select("DISTINCT service.account_id, service.turn_id, backend.uri").
		Joins("JOIN karst_turn_servers AS backend ON backend.account_id = service.account_id AND backend.id = service.turn_id").
		Where("service.turn_id <> ?", "").Order("service.account_id, service.turn_id").Scan(&targets).Error
	if err != nil {
		return err
	}
	group, jobCtx := errgroup.WithContext(ctx)
	group.SetLimit(4)
	var writeMu sync.Mutex
	for _, target := range targets {
		if jobCtx.Err() != nil {
			break
		}
		group.Go(func() error {
			result := turnhealth.Result{State: "credentials_unavailable", ObservedAt: time.Now().UTC()}
			if minter != nil {
				credential, err := minter.Mint()
				if err == nil {
					probeCtx, cancel := context.WithTimeout(jobCtx, 5*time.Second)
					result = probe(probeCtx, target.URI, credential)
					cancel()
				}
			}
			if jobCtx.Err() != nil {
				return jobCtx.Err()
			}
			record := turnObservation{AccountID: target.AccountID, TurnID: target.TurnID, State: result.State, ObservedAt: result.ObservedAt, DurationMS: result.DurationMS}
			// Network checks run concurrently; serialize their short writes so
			// the SQLite deployment does not contend with its own probe batch.
			writeMu.Lock()
			defer writeMu.Unlock()
			return s.db.WithContext(jobCtx).Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "account_id"}, {Name: "turn_id"}}, DoUpdates: clause.AssignmentColumns([]string{"state", "observed_at", "duration_ms"})}).Create(&record).Error
		})
	}
	return group.Wait()
}

func (s *Store) StartHealthWorker(ctx context.Context, minter *turncred.Minter) {
	go func() {
		ticker := time.NewTicker(healthInterval)
		defer ticker.Stop()
		for {
			if err := s.CheckHealth(ctx, minter, turnhealth.Probe); err != nil && ctx.Err() == nil {
				log.WithError(err).Error("karst: Relay TURN health checks failed")
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}
