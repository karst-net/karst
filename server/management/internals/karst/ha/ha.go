// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// Package ha coordinates the small pieces of Karst control-plane state that
// must be shared by replicas. PostgreSQL is deliberately the only dependency:
// it is already required by an HA deployment, so adding a lock service would
// introduce another quorum and another failure mode.
package ha

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const DefaultNotifyChannel = "karst_ha"

// ControlSession is the durable owner record for one authenticated identity.
// IdentityPubKey holds the SHA-256 commitment of its ML-DSA public key, not a
// caller-controlled node ID. A commitment is required because an ML-DSA key
// itself is too large for PostgreSQL's B-tree primary-key limit.
type ControlSession struct {
	IdentityPubKey string    `gorm:"primaryKey"`
	ReplicaID      string    `gorm:"not null"`
	SessionToken   string    `gorm:"not null"`
	LastSeenAt     time.Time `gorm:"not null"`
}

func (ControlSession) TableName() string { return "control_sessions" }

type event struct {
	Kind      string `json:"kind"`
	Identity  string `json:"identity,omitempty"`
	ReplicaID string `json:"replica_id,omitempty"`
	Token     string `json:"token,omitempty"`
	PeerID    string `json:"peer_id,omitempty"`
}

// Hub owns one replica's LISTEN connection and publishes compact invalidation
// events. Payloads never travel through NOTIFY: receivers re-fetch their
// authoritative state from Postgres.
type Hub struct {
	db      *gorm.DB
	pool    *pgxpool.Pool
	replica string
	channel string

	mu       sync.RWMutex
	sessions []func(identity, replica, token string)
	peers    []func(peerID string)
}

var channelName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,62}$`)

// New migrates the ownership table, starts the listener, and returns a hub.
// A malformed channel is rejected rather than interpolated into LISTEN.
func New(ctx context.Context, db *gorm.DB, pool *pgxpool.Pool, replica, channel string) (*Hub, error) {
	if pool == nil {
		return nil, fmt.Errorf("karst ha: Postgres pool is required")
	}
	if channel == "" {
		channel = DefaultNotifyChannel
	}
	if !channelName.MatchString(channel) {
		return nil, fmt.Errorf("karst ha: invalid notify channel %q", channel)
	}
	if err := db.AutoMigrate(&ControlSession{}); err != nil {
		return nil, fmt.Errorf("karst ha: migrate control sessions: %w", err)
	}
	h := &Hub{db: db, pool: pool, replica: replica, channel: channel}
	ready := make(chan error, 1)
	go h.listen(ctx, ready)
	// A claim published before LISTEN is installed is intentionally covered by
	// reconciliation, but waiting here removes that avoidable gap for normal
	// startup and makes an unusable notification connection fail at boot.
	select {
	case err := <-ready:
		if err != nil {
			return nil, err
		}
	case <-ctx.Done():
		return nil, fmt.Errorf("karst ha: starting listener: %w", ctx.Err())
	}
	return h, nil
}

func (h *Hub) OnSession(f func(identity, replica, token string)) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sessions = append(h.sessions, f)
}
func (h *Hub) OnPeer(f func(peerID string)) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.peers = append(h.peers, f)
}

// Claim fails closed: callers must reject a new authenticated stream if its
// ownership row cannot be persisted, because accepting it would defeat
// cross-replica duplicate-identity eviction.
func (h *Hub) Claim(ctx context.Context, identity, token string) error {
	row := ControlSession{IdentityPubKey: identity, ReplicaID: h.replica, SessionToken: token, LastSeenAt: time.Now().UTC()}
	if err := h.db.WithContext(ctx).Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "identity_pub_key"}}, DoUpdates: clause.AssignmentColumns([]string{"replica_id", "session_token", "last_seen_at"})}).Create(&row).Error; err != nil {
		return fmt.Errorf("claim control session: %w", err)
	}
	return h.publish(ctx, event{Kind: "session", Identity: identity, ReplicaID: h.replica, Token: token})
}

func (h *Hub) Release(ctx context.Context, identity, token string) {
	// Never delete a newer owner's row when an old stream finally exits.
	h.db.WithContext(ctx).Where("identity_pub_key = ? AND replica_id = ? AND session_token = ?", identity, h.replica, token).Delete(&ControlSession{})
}

// PublishPeer broadcasts an edge-triggered invalidation, never a netmap.
func (h *Hub) PublishPeer(ctx context.Context, peerID string) error {
	return h.publish(ctx, event{Kind: "peer", PeerID: peerID})
}

// Reconcile closes any local session whose durable owner changed while this
// replica was offline or its LISTEN connection was reconnecting.
func (h *Hub) Reconcile(ctx context.Context) error {
	var rows []ControlSession
	if err := h.db.WithContext(ctx).Find(&rows).Error; err != nil {
		return err
	}
	for _, row := range rows {
		h.dispatchSession(row.IdentityPubKey, row.ReplicaID, row.SessionToken)
	}
	return nil
}

func (h *Hub) publish(ctx context.Context, e event) error {
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if err := h.db.WithContext(ctx).Exec("SELECT pg_notify(?, ?)", h.channel, string(b)).Error; err != nil {
		return fmt.Errorf("publish HA notification: %w", err)
	}
	return nil
}

func (h *Hub) listen(ctx context.Context, ready chan<- error) {
	first := true
	for ctx.Err() == nil {
		conn, err := h.pool.Acquire(ctx)
		if err != nil {
			if first {
				ready <- fmt.Errorf("karst ha: acquire LISTEN connection: %w", err)
				return
			}
			log.WithError(err).Warn("karst ha: acquiring LISTEN connection")
			time.Sleep(time.Second)
			continue
		}
		_, err = conn.Conn().Exec(ctx, "LISTEN "+h.channel)
		if err == nil {
			if first {
				ready <- nil
				first = false
			}
			for ctx.Err() == nil {
				n, waitErr := conn.Conn().WaitForNotification(ctx)
				if waitErr != nil {
					err = waitErr
					break
				}
				var e event
				if json.Unmarshal([]byte(n.Payload), &e) == nil {
					h.dispatch(e)
				}
			}
		}
		if first {
			conn.Release()
			ready <- fmt.Errorf("karst ha: LISTEN %s: %w", h.channel, err)
			return
		}
		conn.Release()
		if ctx.Err() == nil {
			log.WithError(err).Warn("karst ha: LISTEN connection lost; reconnecting")
			time.Sleep(time.Second)
		}
	}
}

func (h *Hub) dispatch(e event) {
	if e.Kind == "session" {
		h.dispatchSession(e.Identity, e.ReplicaID, e.Token)
	} else if e.Kind == "peer" {
		h.mu.RLock()
		fs := append([]func(string){}, h.peers...)
		h.mu.RUnlock()
		for _, f := range fs {
			f(e.PeerID)
		}
	}
}
func (h *Hub) dispatchSession(identity, replica, token string) {
	h.mu.RLock()
	fs := append([]func(string, string, string){}, h.sessions...)
	h.mu.RUnlock()
	for _, f := range fs {
		f(identity, replica, token)
	}
}
