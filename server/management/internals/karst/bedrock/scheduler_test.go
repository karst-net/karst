// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package bedrock

import (
	"context"
	"errors"
	"testing"
	"time"
)

var errAuditNotReady = errors.New("audit log has no entries yet")

// schedulerFixture is a genesis carrying one anchor key, imported into a real
// Log — the shape a Scheduler operates against.
type schedulerFixture struct {
	l       *Log
	root    *RootKey
	auth    *AuthorityKey
	anchor  *AnchorKey
	genesis *State
}

func newSchedulerFixture(t *testing.T, withAnchorKey bool) *schedulerFixture {
	t.Helper()
	root := testRoot(t, 0x10)
	auth := testAuthority(t, 0x40)
	anchor, err := GenerateAnchor()
	if err != nil {
		t.Fatalf("generate anchor: %v", err)
	}

	var anchorPKs [][]byte
	if withAnchorKey {
		anchorPKs = [][]byte{anchor.Public()}
	}

	b := NewBuilder()
	e, input := b.Prepare(1000, OpGenesis, GenesisBody("z.karst.", [][]byte{root.Public()}, 1,
		[][]byte{auth.Public()}, 1, anchorPKs))
	sigs, err := SignRoots(input, RootSigner{Index: 0, Key: root})
	if err != nil {
		t.Fatalf("sign genesis: %v", err)
	}
	if err := b.Commit(e, sigs); err != nil {
		t.Fatalf("commit genesis: %v", err)
	}

	l := testLog(t)
	if err := l.Import(context.Background(), acct, b.Entries()); err != nil {
		t.Fatalf("import genesis: %v", err)
	}
	st, err := b.Verify()
	if err != nil {
		t.Fatalf("verify genesis: %v", err)
	}
	return &schedulerFixture{l: l, root: root, auth: auth, anchor: anchor, genesis: st}
}

func (f *schedulerFixture) scheduler(audit AuditHead) *Scheduler {
	return &Scheduler{
		Log:        f.l,
		Audit:      audit,
		AccountID:  acct,
		Key:        f.anchor,
		MinEntries: 100,
		MaxAge:     24 * time.Hour,
	}
}

// The payoff: a due anchor, signed by a locally held anchor key rather than
// an offline ceremony, ends up in the stored chain under the correct
// concatenated signer index — AnchorDue and PrepareAnchor's first production
// caller, ADR-0016.
func TestSchedulerAnchorsWhenDue(t *testing.T) {
	ctx := context.Background()
	f := newSchedulerFixture(t, true)
	audit := &fakeAudit{seq: 500, hash: "head-at-500"}
	s := f.scheduler(audit)

	if err := s.Tick(ctx, time.Unix(2000, 0)); err != nil {
		t.Fatalf("tick: %v", err)
	}

	st, err := f.l.State(ctx, acct)
	if err != nil {
		t.Fatalf("state: %v", err)
	}
	if st.Anchor == nil {
		t.Fatal("no anchor was written")
	}
	if st.Anchor.AuditSeq != 500 || string(st.Anchor.AuditHead) != "head-at-500" {
		t.Errorf("anchor = %+v", st.Anchor)
	}
	if _, err := VerifyAnchored(ctx, st, audit); err != nil {
		t.Errorf("the scheduler's own anchor does not verify: %v", err)
	}

	// Entry 2, one authority (index 0) — so the anchor key's concatenated
	// index is 1.
	entries, err := f.l.All(ctx, acct)
	if err != nil {
		t.Fatalf("all: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("wrote %d entries, want 2", len(entries))
	}
	if got := entries[1].Sigs; len(got) != 1 || got[0].SignerIndex != 1 {
		t.Errorf("anchor signature = %+v, want one signature at index 1", got)
	}
}

// A key nobody has enabled for this account yet — the ordinary state between
// generating one with `karst-bedrock init anchor` and running the root
// ceremony that adds it — must not error and must not anchor.
func TestSchedulerDoesNothingWhileKeyIsNotEnabled(t *testing.T) {
	ctx := context.Background()
	f := newSchedulerFixture(t, false) // no anchor key in genesis
	audit := &fakeAudit{seq: 500, hash: "head-at-500"}
	s := f.scheduler(audit)

	if err := s.Tick(ctx, time.Unix(2000, 0)); err != nil {
		t.Fatalf("tick: %v", err)
	}
	entries, err := f.l.All(ctx, acct)
	if err != nil {
		t.Fatalf("all: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("an unenabled key still anchored: %d entries", len(entries))
	}
}

// A first anchor is always due — AnchorDue's "never anchored" branch — but
// once one exists, a small advance well inside MaxAge must wait rather than
// fire on every tick.
func TestSchedulerWaitsUntilDue(t *testing.T) {
	ctx := context.Background()
	f := newSchedulerFixture(t, true)
	audit := &fakeAudit{seq: 5, hash: "head-at-5"}
	s := f.scheduler(audit) // MinEntries: 100, MaxAge: 24h

	if err := s.Tick(ctx, time.Unix(1000, 0)); err != nil {
		t.Fatalf("first tick: %v", err)
	}
	entries, err := f.l.All(ctx, acct)
	if err != nil {
		t.Fatalf("all: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("a never-anchored log was not anchored on the first tick: %d entries", len(entries))
	}

	// The audit log moved by four entries — under MinEntries — and only a
	// minute passed — nowhere near MaxAge.
	audit.seq, audit.hash = 9, "head-at-9"
	if err := s.Tick(ctx, time.Unix(1060, 0)); err != nil {
		t.Fatalf("second tick: %v", err)
	}
	entries, err = f.l.All(ctx, acct)
	if err != nil {
		t.Fatalf("all: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("anchored again while nowhere near due: %d entries", len(entries))
	}
}

// A second tick after anchoring must not repeat itself: the audit log has
// not moved, so PrepareAnchor's own ErrNothingToAnchor guard applies even
// though AnchorDue would not have called it due in the first place.
func TestSchedulerTickIsIdempotentOnAnUnmovedAuditLog(t *testing.T) {
	ctx := context.Background()
	f := newSchedulerFixture(t, true)
	audit := &fakeAudit{seq: 500, hash: "head-at-500"}
	s := f.scheduler(audit)

	if err := s.Tick(ctx, time.Unix(2000, 0)); err != nil {
		t.Fatalf("first tick: %v", err)
	}
	if err := s.Tick(ctx, time.Unix(3000, 0)); err != nil {
		t.Fatalf("second tick: %v", err)
	}
	entries, err := f.l.All(ctx, acct)
	if err != nil {
		t.Fatalf("all: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("a second tick over an unmoved audit log wrote again: %d entries", len(entries))
	}
}

// No Bedrock chain at all for this account is the state of every account
// before Bedrock is turned on — not a failure the scheduler should report.
func TestSchedulerDoesNothingWithNoBedrockChain(t *testing.T) {
	ctx := context.Background()
	l := testLog(t)
	anchor, err := GenerateAnchor()
	if err != nil {
		t.Fatalf("generate anchor: %v", err)
	}
	s := &Scheduler{
		Log: l, Audit: &fakeAudit{seq: 5, hash: "x"}, AccountID: acct, Key: anchor,
		MinEntries: 100, MaxAge: 24 * time.Hour,
	}
	if err := s.Tick(ctx, time.Unix(1000, 0)); err != nil {
		t.Fatalf("tick against an account with no chain: %v", err)
	}
}

// An audit log with nothing in it yet — Head errors — is swallowed rather
// than surfaced: there is nothing actionable to do about it besides wait.
type erroringAudit struct{}

func (erroringAudit) Head(context.Context) (uint64, string, error) {
	return 0, "", errAuditNotReady
}
func (erroringAudit) VerifyFrom(context.Context, uint64, string) (uint64, error) {
	return 0, errAuditNotReady
}

func TestSchedulerToleratesAnAuditHeadError(t *testing.T) {
	ctx := context.Background()
	f := newSchedulerFixture(t, true)
	s := f.scheduler(erroringAudit{})
	if err := s.Tick(ctx, time.Unix(1000, 0)); err != nil {
		t.Fatalf("tick: %v", err)
	}
	entries, err := f.l.All(ctx, acct)
	if err != nil {
		t.Fatalf("all: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("anchored despite an unreadable audit head: %d entries", len(entries))
	}
}
