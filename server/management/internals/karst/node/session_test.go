// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package node_test

import (
	"testing"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/netbirdio/netbird/management/internals/karst/node"
)

// newSessionStore is newStore plus a clean session table. The shared in-memory
// DSN is per-process, so without the drop these tests see each other's rows.
func newSessionStore(t *testing.T) *node.Store {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Exec("DROP TABLE IF EXISTS karst_device_sessions").Error; err != nil {
		t.Fatalf("reset: %v", err)
	}
	s, err := node.NewStore(db)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	return s
}

func TestALiveSessionHasNoEndAndKeepsItsAddress(t *testing.T) {
	s := newSessionStore(t)
	start := time.Now().Add(-time.Hour)
	if _, err := s.OpenSession("laptop", "203.0.113.7:44321", start); err != nil {
		t.Fatalf("open: %v", err)
	}
	sessions, err := s.SessionsForHandles([]string{"laptop"}, 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("expected one session, got %d", len(sessions))
	}
	if sessions[0].EndedAt != nil {
		t.Errorf("a live session has an end time: %v", sessions[0].EndedAt)
	}
	// The port is the ephemeral source of one TCP connection and identifies
	// nothing; the address is the whole point of the field.
	if sessions[0].ClientAddr != "203.0.113.7" {
		t.Errorf("address = %q, want 203.0.113.7", sessions[0].ClientAddr)
	}
}

func TestAnIPv6AddressKeepsAllOfItself(t *testing.T) {
	s := newSessionStore(t)
	// The regression a split on the last colon produces: "2001:db8::1" becomes
	// "2001:db8:" and the user is shown an address that does not exist.
	if _, err := s.OpenSession("laptop", "[2001:db8::1]:44321", time.Now()); err != nil {
		t.Fatalf("open: %v", err)
	}
	sessions, _ := s.SessionsForHandles([]string{"laptop"}, 0)
	if len(sessions) != 1 || sessions[0].ClientAddr != "2001:db8::1" {
		t.Fatalf("address = %q, want 2001:db8::1", sessions[0].ClientAddr)
	}
}

func TestClosingASessionRecordsWhenItEnded(t *testing.T) {
	s := newSessionStore(t)
	id, err := s.OpenSession("laptop", "203.0.113.7:1", time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	end := time.Now().Truncate(time.Second)
	if err := s.CloseSession(id, end); err != nil {
		t.Fatalf("close: %v", err)
	}
	sessions, _ := s.SessionsForHandles([]string{"laptop"}, 0)
	if sessions[0].EndedAt == nil {
		t.Fatal("a closed session still has no end time")
	}
	if got := sessions[0].EndedAt.Truncate(time.Second); !got.Equal(end.UTC()) {
		t.Errorf("ended at %v, want %v", got, end.UTC())
	}
}

// The deferred close runs on every exit path including a client hangup, and it
// can race a revocation that closed the same row. Neither must be an error.
func TestClosingTwiceIsNotAnError(t *testing.T) {
	s := newSessionStore(t)
	id, _ := s.OpenSession("laptop", "203.0.113.7:1", time.Now())
	first := time.Now()
	if err := s.CloseSession(id, first); err != nil {
		t.Fatalf("first close: %v", err)
	}
	if err := s.CloseSession(id, first.Add(time.Hour)); err != nil {
		t.Fatalf("second close: %v", err)
	}
	sessions, _ := s.SessionsForHandles([]string{"laptop"}, 0)
	// And the second close must not move the end time: the session ended when
	// it ended.
	if sessions[0].EndedAt.After(first.UTC().Add(time.Minute)) {
		t.Errorf("the second close moved the end time to %v", sessions[0].EndedAt)
	}
}

func TestClosingAnUnknownSessionIsNotAnError(t *testing.T) {
	s := newSessionStore(t)
	if err := s.CloseSession(0, time.Now()); err != nil {
		t.Errorf("close(0): %v", err)
	}
	if err := s.CloseSession(999, time.Now()); err != nil {
		t.Errorf("close(999): %v", err)
	}
}

// The case the LastSeenAt field exists for. A killed server runs no deferred
// closes, so the rows it was serving stay open; closing them at restart time
// would report a session that ended on Friday as having ended on Monday.
func TestRecoveryClosesADanglingSessionAtItsLastRequestNotAtRestart(t *testing.T) {
	s := newSessionStore(t)
	start := time.Now().Add(-72 * time.Hour)
	id, err := s.OpenSession("laptop", "203.0.113.7:1", start)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	lastSeen := start.Add(30 * time.Minute)
	if err := s.TouchSession(id, lastSeen); err != nil {
		t.Fatalf("touch: %v", err)
	}

	recovered, _, err := s.RecoverSessions(time.Now())
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if recovered != 1 {
		t.Fatalf("recovered %d sessions, want 1", recovered)
	}
	sessions, _ := s.SessionsForHandles([]string{"laptop"}, 0)
	if sessions[0].EndedAt == nil {
		t.Fatal("recovery left the session open")
	}
	if got := sessions[0].EndedAt.Truncate(time.Second); !got.Equal(lastSeen.UTC().Truncate(time.Second)) {
		t.Errorf("ended at %v, want the last-seen time %v", got, lastSeen.UTC())
	}
}

func TestRecoveryDropsHistoryPastRetention(t *testing.T) {
	s := newSessionStore(t)
	old, _ := s.OpenSession("laptop", "203.0.113.7:1", time.Now().Add(-2*node.SessionRetention))
	if err := s.CloseSession(old, time.Now().Add(-2*node.SessionRetention)); err != nil {
		t.Fatalf("close: %v", err)
	}
	recent, _ := s.OpenSession("laptop", "203.0.113.7:1", time.Now().Add(-time.Hour))
	if err := s.CloseSession(recent, time.Now()); err != nil {
		t.Fatalf("close: %v", err)
	}

	_, pruned, err := s.RecoverSessions(time.Now())
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if pruned != 1 {
		t.Errorf("pruned %d, want 1", pruned)
	}
	sessions, _ := s.SessionsForHandles([]string{"laptop"}, 0)
	if len(sessions) != 1 {
		t.Errorf("expected the recent session to survive, got %d rows", len(sessions))
	}
}

// Revocation. The stream teardown normally records the end itself, but a user
// who has just revoked a stolen laptop must not be shown it as still connected
// because the two raced.
func TestRevokingADeviceClosesItsLiveSessions(t *testing.T) {
	s := newSessionStore(t)
	if _, err := s.OpenSession("stolen", "203.0.113.7:1", time.Now().Add(-time.Hour)); err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := s.OpenSession("kept", "203.0.113.8:1", time.Now().Add(-time.Hour)); err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := s.CloseSessionsForHandle("stolen", time.Now()); err != nil {
		t.Fatalf("close for handle: %v", err)
	}
	stolen, _ := s.SessionsForHandles([]string{"stolen"}, 0)
	if stolen[0].EndedAt == nil {
		t.Error("the revoked device's session is still open")
	}
	kept, _ := s.SessionsForHandles([]string{"kept"}, 0)
	if kept[0].EndedAt != nil {
		t.Error("revoking one device ended another device's session")
	}
}

// Pins the contract that a caller with no devices gets no rows.
//
// It does **not** demonstrate the explicit guard in SessionsForHandles: with
// that guard deleted this test still passes, because gorm renders an empty
// `IN ?` as a condition matching nothing on SQLite. The guard stays as defense
// in depth — what an empty IN does is a property of the driver, not of this
// package — and this comment says so rather than letting the test read as
// proof of something it does not show.
//
// The property that actually matters is enforced a layer up and tested there:
// api.TestMemberSessionHistoryCarriesRealEndTimesAndAddresses drives the
// endpoint with two users' devices in the table, and fails when a handle the
// caller does not own reaches the store.
func TestNoHandlesReturnsNoSessionsRatherThanAll(t *testing.T) {
	s := newSessionStore(t)
	if _, err := s.OpenSession("someone-elses-laptop", "203.0.113.7:1", time.Now()); err != nil {
		t.Fatalf("open: %v", err)
	}
	sessions, err := s.SessionsForHandles(nil, 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(sessions) != 0 {
		t.Fatalf("a caller with no devices was shown %d sessions", len(sessions))
	}
}

func TestSessionsAreNewestFirstAndBounded(t *testing.T) {
	s := newSessionStore(t)
	base := time.Now().Add(-24 * time.Hour)
	for i := range 5 {
		if _, err := s.OpenSession("laptop", "203.0.113.7:1", base.Add(time.Duration(i)*time.Hour)); err != nil {
			t.Fatalf("open: %v", err)
		}
	}
	sessions, err := s.SessionsForHandles([]string{"laptop"}, 3)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(sessions) != 3 {
		t.Fatalf("limit ignored: got %d rows", len(sessions))
	}
	for i := 1; i < len(sessions); i++ {
		if sessions[i].StartedAt.After(sessions[i-1].StartedAt) {
			t.Fatalf("sessions are not newest-first at %d", i)
		}
	}
}
