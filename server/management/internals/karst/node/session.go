// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package node

import (
	"fmt"
	"net"
	"time"

	"gorm.io/gorm"
)

// DeviceSession is one control-channel connection: a device attached to the
// coordination server from an address, between two times.
//
// # Why this is not SessionObservation
//
// [SessionObservation] is a node's report about its *peers* — which path it
// has to each of them, over which suite. It is replaced wholesale on every
// report, so it holds no history at all and answers "how is this node reaching
// its peers right now".
//
// This answers a different question, and the one the portal asks on a user's
// behalf: "when was my laptop connected, and from where". Nothing else in the
// tree could answer it, which is why `/me/sessions` used to derive its rows
// from the audit log and return a null end time and a null address for every
// one of them (plans/phase-5/05-user-portal.md §1).
//
// # What the address means, and what it does not
//
// ClientAddr is the peer address of the gRPC connection: the address the
// coordination server was actually talking to. Behind a reverse proxy or a
// load balancer that is the proxy, not the device — the control channel
// carries its own authentication (ADR-0011) and does not trust, or read, a
// forwarded-for header, because a header a client can set is not evidence of
// where a client is. An operator who terminates TLS in front of this server
// should expect every session to report the proxy's address, and the portal
// says as much rather than implying a device location it cannot know.
type DeviceSession struct {
	ID     uint64 `gorm:"primaryKey;autoIncrement"`
	Handle string `gorm:"size:64;not null;index"`
	// ClientAddr is an IP without a port. The port is the ephemeral source of
	// one TCP connection and identifies nothing a user would recognize.
	ClientAddr string    `gorm:"size:64"`
	StartedAt  time.Time `gorm:"not null;index"`
	// LastSeenAt advances on every request the device makes on this stream.
	//
	// It exists for the case EndedAt cannot cover: a coordination server that
	// is killed does not run the deferred close for any stream it is serving,
	// so those rows would stay open forever, and a later "close whatever is
	// still open" pass at startup has no idea when they really ended. Closing
	// them at the last request the server actually saw is accurate to the
	// node's refresh interval, and honest about being an estimate — which
	// stamping the restart time on a session that ended three days earlier
	// would not be.
	LastSeenAt time.Time `gorm:"not null"`
	// EndedAt is nil while the session is live.
	EndedAt *time.Time
}

func (DeviceSession) TableName() string { return "karst_device_sessions" }

// SessionRetention is how long a closed session is kept.
//
// Session history is a record of where an account was used from, so it is
// worth keeping and it is not worth keeping forever: it is personal data whose
// usefulness to the person it describes falls off long before its value to
// somebody who steals the database does. Ninety days is the same window the
// packaging retention tag uses and is long enough to answer "was that me, last
// quarter?".
const SessionRetention = 90 * 24 * time.Hour

// OpenSession records a device attaching, returning the row id to close it
// with. addr may be a host:port — the port is dropped.
func (s *Store) OpenSession(handle, addr string, at time.Time) (uint64, error) {
	if handle == "" || len(handle) > HandleLength {
		return 0, fmt.Errorf("node: invalid session handle")
	}
	at = at.UTC()
	session := DeviceSession{
		Handle:     handle,
		ClientAddr: clientAddr(addr),
		StartedAt:  at,
		LastSeenAt: at,
	}
	if err := s.db.Create(&session).Error; err != nil {
		return 0, fmt.Errorf("node: open session: %w", err)
	}
	return session.ID, nil
}

// TouchSession advances a live session's last-seen time.
func (s *Store) TouchSession(id uint64, at time.Time) error {
	if id == 0 {
		return nil
	}
	err := s.db.Model(&DeviceSession{}).
		Where("id = ? AND ended_at IS NULL", id).
		Update("last_seen_at", at.UTC()).Error
	if err != nil {
		return fmt.Errorf("node: touch session: %w", err)
	}
	return nil
}

// CloseSession marks a session ended. Closing an already-closed or unknown
// session is not an error: the caller is a deferred close on a stream that may
// have been ended from either side, and it must not turn a normal disconnect
// into a logged failure.
func (s *Store) CloseSession(id uint64, at time.Time) error {
	if id == 0 {
		return nil
	}
	ended := at.UTC()
	err := s.db.Model(&DeviceSession{}).
		Where("id = ? AND ended_at IS NULL", id).
		Updates(map[string]any{"ended_at": ended, "last_seen_at": ended}).Error
	if err != nil {
		return fmt.Errorf("node: close session: %w", err)
	}
	return nil
}

// CloseSessionsForHandle ends every live session for a device.
//
// Revocation calls this. A revoked device's stream is torn down by the peer
// update, and the deferred close will normally record the end itself — but a
// user who has just revoked a stolen laptop should not see it listed as still
// connected because the teardown and this write raced.
func (s *Store) CloseSessionsForHandle(handle string, at time.Time) error {
	if handle == "" {
		return nil
	}
	ended := at.UTC()
	err := s.db.Model(&DeviceSession{}).
		Where("handle = ? AND ended_at IS NULL", handle).
		Updates(map[string]any{"ended_at": ended, "last_seen_at": ended}).Error
	if err != nil {
		return fmt.Errorf("node: close sessions for handle: %w", err)
	}
	return nil
}

// RecoverSessions closes sessions left open by a server that stopped without
// running their deferred closes, and drops history past [SessionRetention].
//
// Called once at startup. The close time is each row's own last-seen time, not
// now: see the field comment on LastSeenAt.
func (s *Store) RecoverSessions(now time.Time) (recovered int64, pruned int64, err error) {
	result := s.db.Model(&DeviceSession{}).
		Where("ended_at IS NULL").
		Update("ended_at", gorm.Expr("last_seen_at"))
	if result.Error != nil {
		return 0, 0, fmt.Errorf("node: recover sessions: %w", result.Error)
	}
	cutoff := now.UTC().Add(-SessionRetention)
	prune := s.db.Where("ended_at IS NOT NULL AND ended_at < ?", cutoff).Delete(&DeviceSession{})
	if prune.Error != nil {
		return result.RowsAffected, 0, fmt.Errorf("node: prune sessions: %w", prune.Error)
	}
	return result.RowsAffected, prune.RowsAffected, nil
}

// SessionsForHandles returns sessions for the given devices, newest first.
//
// Handles come from the caller's own authorized device list, never from a
// request parameter — plans/phase-5/05-user-portal.md §2: a handler that
// cannot express another user's identity cannot leak one. An empty list
// returns no rows rather than every row.
func (s *Store) SessionsForHandles(handles []string, limit int) ([]DeviceSession, error) {
	if len(handles) == 0 {
		return nil, nil
	}
	if limit <= 0 || limit > maxSessionHistory {
		limit = maxSessionHistory
	}
	var sessions []DeviceSession
	err := s.db.Where("handle IN ?", handles).
		Order("started_at DESC").
		Limit(limit).
		Find(&sessions).Error
	if err != nil {
		return nil, fmt.Errorf("node: list sessions: %w", err)
	}
	return sessions, nil
}

const maxSessionHistory = 200

// clientAddr strips the port from a gRPC peer address.
//
// The address arrives as host:port for TCP, and an IPv6 host is bracketed —
// `[2001:db8::1]:44321` — so this cannot be a split on the last colon.
func clientAddr(addr string) string {
	if addr == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	// Not host:port at all: a unix socket in a test, or a bare address. Keep
	// whatever it is rather than discarding the only evidence there is.
	return addr
}
