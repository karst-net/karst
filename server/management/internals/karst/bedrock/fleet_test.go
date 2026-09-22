// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package bedrock

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// fakeEnabledAccounts is a settable Store stand-in — ADR-0033 §2's own
// testability reasoning: Fleet's lifecycle logic should not need a database
// to verify.
type fakeEnabledAccounts struct {
	mu  sync.Mutex
	ids []string
	err error
}

func (f *fakeEnabledAccounts) set(ids []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ids = ids
}

func (f *fakeEnabledAccounts) EnabledAccounts(context.Context) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	out := make([]string, len(f.ids))
	copy(out, f.ids)
	return out, nil
}

// fakeRunner records whether it was ever started, and blocks on ctx so a
// test can assert it was stopped by watching runningUntilCanceled return.
type fakeRunner struct {
	mu      sync.Mutex
	started bool
	stopped chan struct{}
}

func newFakeRunner() *fakeRunner {
	return &fakeRunner{stopped: make(chan struct{})}
}

func (r *fakeRunner) Run(ctx context.Context, _ time.Duration) {
	r.mu.Lock()
	r.started = true
	r.mu.Unlock()
	<-ctx.Done()
	close(r.stopped)
}

func (r *fakeRunner) wasStarted() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.started
}

// fleetFixture wires a Fleet to fakeEnabledAccounts and a factory recording
// every runner it built, keyed by account ID.
type fleetFixture struct {
	accounts *fakeEnabledAccounts
	fleet    *Fleet

	mu      sync.Mutex
	runners map[string]*fakeRunner
}

func newFleetFixture() *fleetFixture {
	fx := &fleetFixture{
		accounts: &fakeEnabledAccounts{},
		runners:  make(map[string]*fakeRunner),
	}
	fx.fleet = &Fleet{
		Accounts: fx.accounts,
		running:  make(map[string]context.CancelFunc),
	}
	fx.fleet.newScheduler = func(accountID string) schedulerRunner {
		r := newFakeRunner()
		fx.mu.Lock()
		fx.runners[accountID] = r
		fx.mu.Unlock()
		return r
	}
	return fx
}

func (fx *fleetFixture) runnerFor(accountID string) *fakeRunner {
	fx.mu.Lock()
	defer fx.mu.Unlock()
	return fx.runners[accountID]
}

func TestReconcileStartsASchedulerForEachEnabledAccount(t *testing.T) {
	fx := newFleetFixture()
	fx.accounts.set([]string{"acct-1", "acct-2"})

	if err := fx.fleet.Reconcile(context.Background(), time.Second); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	for _, id := range []string{"acct-1", "acct-2"} {
		r := fx.runnerFor(id)
		if r == nil {
			t.Fatalf("no scheduler was built for %s", id)
		}
		// Run is a goroutine started by Reconcile; give it a moment to reach
		// its first statement rather than racing wasStarted against it.
		waitUntil(t, func() bool { return r.wasStarted() })
	}
}

func TestReconcileDoesNotRestartAnAlreadyRunningAccount(t *testing.T) {
	fx := newFleetFixture()
	fx.accounts.set([]string{"acct-1"})

	ctx := context.Background()
	if err := fx.fleet.Reconcile(ctx, time.Second); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	first := fx.runnerFor("acct-1")
	waitUntil(t, first.wasStarted)

	// Same account, reported again -- a second reconcile pass must not build
	// a second runner for it (which would mean two Schedulers racing to
	// anchor the same account's chain).
	if err := fx.fleet.Reconcile(ctx, time.Second); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if second := fx.runnerFor("acct-1"); second != first {
		t.Fatal("a second reconcile started a second scheduler for an already-running account")
	}
}

func TestReconcileStopsAnAccountNoLongerEnabled(t *testing.T) {
	fx := newFleetFixture()
	fx.accounts.set([]string{"acct-1", "acct-2"})
	ctx := context.Background()
	if err := fx.fleet.Reconcile(ctx, time.Second); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	r1, r2 := fx.runnerFor("acct-1"), fx.runnerFor("acct-2")
	waitUntil(t, r1.wasStarted)
	waitUntil(t, r2.wasStarted)

	// acct-2 disabled Bedrock (or was deleted) between passes.
	fx.accounts.set([]string{"acct-1"})
	if err := fx.fleet.Reconcile(ctx, time.Second); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	select {
	case <-r2.stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("acct-2's scheduler was not stopped after it left the enabled set")
	}
	select {
	case <-r1.stopped:
		t.Fatal("acct-1's scheduler was stopped even though it is still enabled")
	default:
	}
	if got := fx.fleet.Running(); len(got) != 1 || got[0] != "acct-1" {
		t.Fatalf("Running() = %v, want [acct-1]", got)
	}
}

func TestRunStopsEveryRunningSchedulerWhenItsOwnContextEnds(t *testing.T) {
	fx := newFleetFixture()
	fx.accounts.set([]string{"acct-1", "acct-2"})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		fx.fleet.Run(ctx, time.Hour, time.Second) // reconcile interval irrelevant: cancel fires first
		close(done)
	}()

	waitUntil(t, func() bool { return fx.runnerFor("acct-1") != nil && fx.runnerFor("acct-2") != nil })
	waitUntil(t, func() bool { return fx.runnerFor("acct-1").wasStarted() && fx.runnerFor("acct-2").wasStarted() })

	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after its context was canceled")
	}
	for _, id := range []string{"acct-1", "acct-2"} {
		select {
		case <-fx.runnerFor(id).stopped:
		case <-time.After(2 * time.Second):
			t.Fatalf("%s's scheduler was not stopped when Run's context ended", id)
		}
	}
	if got := fx.fleet.Running(); len(got) != 0 {
		t.Fatalf("Running() after shutdown = %v, want none", got)
	}
}

func TestAFailingAccountListLeavesRunningSchedulersAlone(t *testing.T) {
	fx := newFleetFixture()
	fx.accounts.set([]string{"acct-1"})
	ctx := context.Background()
	if err := fx.fleet.Reconcile(ctx, time.Second); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	r1 := fx.runnerFor("acct-1")
	waitUntil(t, r1.wasStarted)

	fx.accounts.mu.Lock()
	fx.accounts.err = errors.New("database is down")
	fx.accounts.mu.Unlock()

	if err := fx.fleet.Reconcile(ctx, time.Second); err == nil {
		t.Fatal("a failing account list was reported as success")
	}
	select {
	case <-r1.stopped:
		t.Fatal("a failed reconcile pass stopped an already-running scheduler")
	default:
	}
}

// waitUntil polls cond for up to a second — Reconcile starts a runner's
// goroutine asynchronously, so a test observing "started" without any wait
// would be racing it.
func waitUntil(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition was never met")
		}
		time.Sleep(time.Millisecond)
	}
}
