// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package control

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/internals/controllers/network_map"
	"github.com/netbirdio/netbird/management/server/telemetry"
)

// EpochSeconds is the PSK rotation period (PLAN.md §2.6: "epochs rotate
// every 86400 s"). Lives here, not in the bootstrap package that used to own
// it, because CurrentEpoch is something this package needs to call directly
// (EpochScheduler, below) and bootstrap imports control, not the other way
// around — a home for it in bootstrap would make that call a circular
// import.
const EpochSeconds = 86400

// CurrentEpoch is a pure function of the clock: every server instance
// computes the same value with nothing to persist, and a restart cannot
// lose track of where it was. See EpochScheduler's own doc comment for why a
// value derived this way still needs an active refresher — deriving it does
// not, by itself, make anything call it again after the first time.
func CurrentEpoch(now time.Time) uint32 {
	return uint32(now.UTC().Unix() / EpochSeconds)
}

// EpochScheduler keeps a NetmapHandler's Epoch field live across the life of
// a long-running process.
//
// CurrentEpoch is a pure function of the clock, which is necessary for the
// property described on it but is not sufficient on its own: a value
// computed once at startup and stored in a field is correct at t=0 and
// silently wrong the moment real time crosses an epoch boundary, because
// nothing revisits it. That was this package's actual bug before this file
// existed — NetmapHandler.Epoch was set once in bootstrap.Install and never
// touched again, so PHREATIC §7.3's PSK epoch only ever advanced on a
// process restart, not on the 86400s schedule PLAN.md §2.6 and the epoch
// grace-period work (GitHub issue #77) both assume. Found while building
// the PSK-epoch-age metric for plans/phase-6/08-observability.md, which
// would otherwise have reported a value that climbs forever and never
// resets — a real symptom of this bug, not a metric bug.
type EpochScheduler struct {
	Handler *NetmapHandler
	// Updates is optional, matching Service.SubscribeToUpdatesWith's own
	// optionality: nil means a rotation is still detected and applied to
	// Handler.Epoch, it just isn't pushed — a connected node still notices
	// within its own 60s poll floor, the same fallback GitHub issues #72 and
	// #73 already rely on for every other server-initiated change.
	Updates network_map.PeersUpdateManager

	// Metrics is optional (nil is a valid, no-op value) and drives
	// management.karst.psk.epoch.age.seconds.
	Metrics *telemetry.KarstMetrics
}

// Run recomputes the epoch on every tick and, when it changed, swaps it into
// Handler.Epoch and pushes a "netmap changed" notification to every
// currently connected peer, so nodes learn of the rotation promptly rather
// than waiting out the poll floor — the same push path #72/#73 built for
// deprovisioning. It makes one immediate, synchronous-to-the-goroutine pass
// at startup before entering the ticker loop, matching every other ticked
// worker in this codebase (audit.Log.StartDeliveryWorker,
// bedrock.Scheduler.Run): a restart should not serve a stale epoch for a
// full interval before its first correction. Callers that need the very
// first value available before any request can possibly be served — as
// bootstrap.Install does — set Handler.Epoch directly before starting Run,
// rather than relying on Run's own first tick to win a race with the first
// inbound request.
func (s *EpochScheduler) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = time.Minute
	}
	tick := func() { s.Tick(ctx, time.Now()) }
	tick()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			tick()
		}
	}
}

// Tick runs one pass against now, exported (mirroring bedrock.Scheduler.Tick)
// so a test can drive it deterministically against a synthetic clock instead
// of racing a real ticker.
func (s *EpochScheduler) Tick(ctx context.Context, now time.Time) {
	next := CurrentEpoch(now)
	prev := s.Handler.Epoch.Swap(next)
	if prev == next {
		return
	}
	log.WithContext(ctx).Infof("karst: psk epoch rotated %d -> %d", prev, next)
	s.Metrics.SetPSKEpochLastBumpAt(now)
	if s.Updates == nil {
		return
	}
	// GetAllNotifiedPeers, deliberately not GetAllConnectedPeers: every Karst
	// node subscribes via CreateNotificationChannel exclusively
	// (control/service.go's subscribeOnce), and GetAllConnectedPeers only
	// reflects the separate peerChannels map legacy full-sync clients use —
	// see GetAllNotifiedPeers' own doc comment for why using the wrong one
	// here would silently push to zero Karst nodes.
	for peerID := range s.Updates.GetAllNotifiedPeers() {
		s.Updates.SendNotification(ctx, peerID)
	}
}
