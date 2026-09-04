// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package control_test

import (
	"context"
	"testing"
	"time"

	"github.com/netbirdio/netbird/management/internals/controllers/network_map/update_channel"
	"github.com/netbirdio/netbird/management/internals/karst/control"
)

// The epoch is a pure function of the clock, so every instance agrees
// without coordinating and a restart cannot lose its place. Moved here from
// bootstrap_test.go with CurrentEpoch itself (control/epoch.go).
func TestCurrentEpochIsDerivedFromTheClock(t *testing.T) {
	base := time.Unix(1_700_000_000, 0).UTC()

	first, second := control.CurrentEpoch(base), control.CurrentEpoch(base)
	if first != second {
		t.Fatal("the epoch is not a function of its input")
	}
	if control.CurrentEpoch(base) != control.CurrentEpoch(base.Add(time.Hour)) {
		t.Fatal("the epoch changed within a single period")
	}
	if control.CurrentEpoch(base) == control.CurrentEpoch(base.Add(control.EpochSeconds*time.Second)) {
		t.Fatal("the epoch did not advance after a full period")
	}
	if control.CurrentEpoch(base.Add(control.EpochSeconds*time.Second)) != control.CurrentEpoch(base)+1 {
		t.Fatal("the epoch advanced by more than one across one period")
	}
}

// §7.3 accepts epochs n and n-1, so the tolerance to clock skew is one full
// period. Recorded as a test because it is the number an operator needs when
// deciding how much NTP failure is survivable.
func TestClockSkewToleranceIsOnePeriod(t *testing.T) {
	base := time.Unix(1_700_000_000, 0).UTC()
	within := control.CurrentEpoch(base.Add(-control.EpochSeconds * time.Second))
	if control.CurrentEpoch(base)-within != 1 {
		t.Fatal("a full period of skew is not exactly one epoch")
	}
}

// The bug this file exists to close: a handler's Epoch used to be set once
// at construction and never revisited, so PSKs only ever rotated on a
// process restart. tick, called directly rather than through Run, is what
// makes this deterministic against a synthetic clock instead of racing a
// real ticker.
func TestEpochSchedulerAdvancesTheHandlerOnRotation(t *testing.T) {
	h := &control.NetmapHandler{}
	base := time.Unix(1_700_000_000, 0).UTC()
	h.Epoch.Store(control.CurrentEpoch(base))

	s := &control.EpochScheduler{Handler: h}
	s.Tick(context.Background(), base.Add(time.Hour))
	if got, want := h.Epoch.Load(), control.CurrentEpoch(base); got != want {
		t.Fatalf("epoch moved within a single period: got %d, want %d", got, want)
	}

	s.Tick(context.Background(), base.Add(time.Duration(control.EpochSeconds)*time.Second))
	if got, want := h.Epoch.Load(), control.CurrentEpoch(base)+1; got != want {
		t.Fatalf("epoch did not advance after a full period: got %d, want %d", got, want)
	}
}

// A rotation must reach every Karst node subscribed via
// CreateNotificationChannel — GetAllNotifiedPeers, not GetAllConnectedPeers
// (updatechannel_test.go's TestGetAllNotifiedPeersIsDistinctFromGetAllConnectedPeers
// covers why those two differ). A real PeersUpdateManager is used
// deliberately, not a mock: the property under test is which of its two
// internal maps EpochScheduler reads from, and a hand-rolled mock could get
// that wrong in a way that hid the exact bug this test exists to catch.
func TestEpochSchedulerNotifiesOnlyOnRotation(t *testing.T) {
	ctx := context.Background()
	updates := update_channel.NewPeersUpdateManager(nil)
	defer updates.CloseChannel(ctx, "node-a")

	notifications := updates.CreateNotificationChannel(ctx, "node-a")

	h := &control.NetmapHandler{}
	base := time.Unix(1_700_000_000, 0).UTC()
	h.Epoch.Store(control.CurrentEpoch(base))
	s := &control.EpochScheduler{Handler: h, Updates: updates}

	// Same epoch: no notification.
	s.Tick(ctx, base.Add(time.Minute))
	select {
	case <-notifications:
		t.Fatal("a tick within the same epoch must not notify")
	default:
	}

	// New epoch: every subscribed node is notified.
	s.Tick(ctx, base.Add(time.Duration(control.EpochSeconds)*time.Second))
	select {
	case <-notifications:
	default:
		t.Fatal("a rotation must notify every node holding a notification channel")
	}
}

// Updates is optional, matching Service.SubscribeToUpdatesWith's own
// optionality — a nil Updates must still advance the epoch, it just can't
// push.
func TestEpochSchedulerToleratesNilUpdates(t *testing.T) {
	h := &control.NetmapHandler{}
	base := time.Unix(1_700_000_000, 0).UTC()
	s := &control.EpochScheduler{Handler: h}

	s.Tick(context.Background(), base.Add(time.Duration(control.EpochSeconds)*time.Second))
	if got, want := h.Epoch.Load(), control.CurrentEpoch(base.Add(time.Duration(control.EpochSeconds)*time.Second)); got != want {
		t.Fatalf("epoch did not advance with a nil Updates: got %d, want %d", got, want)
	}
}
