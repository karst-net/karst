// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// The multi-account Bedrock scheduler fleet — ADR-0033 §2.
//
// # What this replaces
//
// Before this file, exactly one account's Scheduler ever ran, chosen once at
// process startup (main.go's old startBedrockAnchorScheduler resolved a
// single AccountID via GetAccountIDFromUserAuth and started one goroutine
// for it). Any other account, even with Bedrock explicitly enabled for it
// in its own Configuration, got no automated anchoring at all — silently,
// the same failure mode ADR-0016 named for the manual ceremony this whole
// mechanism replaced.
//
// # Why one shared Key is safe across accounts
//
// ADR-0016's capability scoping restricts what an AnchorKey can sign —
// `anchor` operations only, never `node-sign`, the one capability Bedrock
// exists to keep out of a server's reach. Every anchor entry PrepareAnchor
// builds is already bound to one specific account's chain head. Reusing one
// online signer key across tenants' independent chains does not, on that
// reasoning, grant any tenant privilege over another's chain — see
// ADR-0033's Decision §2 and Negative-consequences sections for the full
// argument and its explicit "judgment call, not a proof" caveat.
package bedrock

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server/telemetry"
)

// EnabledAccounts is the slice of *Store a Fleet needs: which accounts
// currently have Bedrock enabled. An interface for the same testability
// reason as AuditHead — Fleet's own tests drive it without a database.
type EnabledAccounts interface {
	EnabledAccounts(ctx context.Context) ([]string, error)
}

// schedulerRunner is the slice of *Scheduler a Fleet drives. An interface so
// Fleet's own tests can verify its start/stop bookkeeping directly, without
// exercising a full anchor-signing Scheduler per account — that behavior
// already has its own tests in scheduler_test.go.
type schedulerRunner interface {
	Run(ctx context.Context, interval time.Duration)
}

// Fleet keeps one Scheduler running per account with Bedrock enabled,
// starting and stopping them as accounts enable or disable it, with no
// process restart required.
type Fleet struct {
	Log        *Log
	Audit      AuditHead
	Key        *AnchorKey
	MinEntries uint64
	MaxAge     time.Duration
	Metrics    *telemetry.KarstMetrics
	Accounts   EnabledAccounts

	// newScheduler builds the runner for one account. A field rather than a
	// *Scheduler literal inlined into Reconcile, so tests can substitute a
	// fake — see schedulerRunner's own doc comment. NewFleet sets it to
	// build real Schedulers; a zero-value Fleet (as a test builds directly)
	// must set it before calling Reconcile or Run.
	newScheduler func(accountID string) schedulerRunner

	mu      sync.Mutex
	running map[string]context.CancelFunc
}

// NewFleet returns a Fleet wired to run real Schedulers, sharing one
// AnchorKey and one set of thresholds across every account it manages.
func NewFleet(chain *Log, audit AuditHead, key *AnchorKey, minEntries uint64, maxAge time.Duration,
	metrics *telemetry.KarstMetrics, accounts EnabledAccounts) *Fleet {
	f := &Fleet{
		Log: chain, Audit: audit, Key: key, MinEntries: minEntries, MaxAge: maxAge,
		Metrics: metrics, Accounts: accounts, running: make(map[string]context.CancelFunc),
	}
	f.newScheduler = func(accountID string) schedulerRunner {
		return &Scheduler{
			Log: f.Log, Audit: f.Audit, AccountID: accountID, Key: f.Key,
			MinEntries: f.MinEntries, MaxAge: f.MaxAge, Metrics: f.Metrics,
		}
	}
	return f
}

// Run reconciles the running scheduler set immediately and then on every
// reconcileInterval tick until ctx ends — the same "make an immediate pass
// at startup" reasoning as Scheduler.Run itself, so a restart does not wait
// a full interval to notice an account that was enabled while this process
// was down. Each running account's own Scheduler ticks independently at
// tickInterval.
func (f *Fleet) Run(ctx context.Context, reconcileInterval, tickInterval time.Duration) {
	if reconcileInterval <= 0 {
		reconcileInterval = 5 * time.Minute
	}
	tick := func() {
		if err := f.Reconcile(ctx, tickInterval); err != nil && ctx.Err() == nil {
			log.WithContext(ctx).Errorf("karst: bedrock scheduler fleet: %v", err)
		}
	}
	tick()
	ticker := time.NewTicker(reconcileInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			f.stopAll()
			return
		case <-ticker.C:
			tick()
		}
	}
}

// Reconcile starts a Scheduler for every enabled account that has none
// running yet, and stops one for every running account no longer enabled
// (disabled, or deleted). Safe to call directly — Run is a thin ticking
// wrapper around it, and a test drives it the same way without a ticker.
//
// A failure listing accounts changes nothing about the schedulers already
// running: an account already being anchored keeps being anchored, the same
// "logged and not fatal" posture roster.Refresher.Run takes toward its own
// per-tick failures.
func (f *Fleet) Reconcile(ctx context.Context, tickInterval time.Duration) error {
	accounts, err := f.Accounts.EnabledAccounts(ctx)
	if err != nil {
		return fmt.Errorf("bedrock: fleet: list enabled accounts: %w", err)
	}
	want := make(map[string]bool, len(accounts))
	for _, id := range accounts {
		want[id] = true
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if f.running == nil {
		f.running = make(map[string]context.CancelFunc)
	}
	for _, accountID := range accounts {
		if _, ok := f.running[accountID]; ok {
			continue
		}
		schedCtx, cancel := context.WithCancel(ctx)
		runner := f.newScheduler(accountID)
		f.running[accountID] = cancel
		log.WithContext(ctx).Infof("karst: bedrock anchor scheduler fleet: starting for account %s", accountID)
		go runner.Run(schedCtx, tickInterval)
	}
	for accountID, cancel := range f.running {
		if want[accountID] {
			continue
		}
		cancel()
		delete(f.running, accountID)
		log.WithContext(ctx).Infof("karst: bedrock anchor scheduler fleet: stopping for account %s (no longer enabled)", accountID)
	}
	return nil
}

func (f *Fleet) stopAll() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for accountID, cancel := range f.running {
		cancel()
		delete(f.running, accountID)
	}
}

// Running reports which accounts currently have a scheduler running, sorted.
// Exposed for tests and any future status surface; Fleet's own operation
// does not need it.
func (f *Fleet) Running() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.running))
	for accountID := range f.running {
		out = append(out, accountID)
	}
	sort.Strings(out)
	return out
}
