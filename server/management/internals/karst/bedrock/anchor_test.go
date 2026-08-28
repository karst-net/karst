// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package bedrock

import (
	"context"
	"errors"
	"testing"
	"time"
)

// fakeAudit stands in for audit.Log. The real one is tested in its own package;
// what matters here is the *relationship* between a Bedrock anchor and an audit
// head, which needs a head that can be moved and truncated on demand.
type fakeAudit struct {
	seq  uint64
	hash string
	// truncatedTo is the highest sequence the log still contains. Zero means
	// nothing has been removed.
	truncatedTo uint64
}

func (f *fakeAudit) Head(context.Context) (uint64, string, error) {
	return f.seq, f.hash, nil
}

func (f *fakeAudit) VerifyFrom(_ context.Context, anchorSeq uint64, anchorHash string) (uint64, error) {
	if f.truncatedTo != 0 && anchorSeq > f.truncatedTo {
		return anchorSeq, errors.New("the log has been truncated past the anchor")
	}
	if anchorHash != f.hash {
		return anchorSeq, errors.New("entry does not match the anchor")
	}
	return 0, nil
}

// anchored builds a log with one anchor committed at the given audit head.
func anchored(t *testing.T, f *fixture, seq uint64, hash string) *State {
	t.Helper()
	e, input := f.b.Prepare(1200, OpAnchor, AnchorBody([]byte(hash), seq))
	sigs, err := SignAuthorities(input, AuthoritySigner{Index: 0, Key: f.authorities[0]})
	if err != nil {
		t.Fatalf("sign anchor: %v", err)
	}
	if err := f.b.Commit(e, sigs); err != nil {
		t.Fatalf("commit anchor: %v", err)
	}
	st, err := f.b.Verify()
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	return st
}

// **The payoff.** audit.go's chain cannot detect truncation of its own tail;
// an anchor in a log the server cannot rewrite can, and this is that working
// end to end.
func TestAnAnchorCatchesAuditTruncation(t *testing.T) {
	f := newFixture(t)
	audit := &fakeAudit{seq: 500, hash: "head-at-500"}
	st := anchored(t, f, audit.seq, audit.hash)

	if broken, err := VerifyAnchored(context.Background(), st, audit); err != nil {
		t.Fatalf("an intact log failed against its own anchor: %v (at %d)", err, broken)
	}

	// The server removes everything after entry 400. The audit chain still
	// verifies internally — that is the whole problem — but it no longer
	// contains the entry the Bedrock log committed to.
	audit.truncatedTo = 400
	broken, err := VerifyAnchored(context.Background(), st, audit)
	if err == nil {
		t.Fatal("truncation past the anchor went undetected")
	}
	if broken != 500 {
		t.Errorf("broken = %d, want the anchored sequence 500", broken)
	}
}

// An anchor over a log that has merely *moved on* is not a failure. Anchors are
// periodic by nature, so treating an old one as broken would make the check
// fire constantly and mean nothing.
func TestAnOlderAnchorStillVerifies(t *testing.T) {
	f := newFixture(t)
	audit := &fakeAudit{seq: 500, hash: "head-at-500"}
	st := anchored(t, f, audit.seq, audit.hash)

	audit.seq = 900 // the log grew; the anchor did not move
	if _, err := VerifyAnchored(context.Background(), st, audit); err != nil {
		t.Fatalf("an intact log failed against an older anchor: %v", err)
	}
	if AnchorMatches(st, audit.seq, audit.hash) {
		t.Error("AnchorMatches reported an old anchor as current")
	}
}

func TestAChainWithNoAnchorSaysSo(t *testing.T) {
	f := newFixture(t)
	st, err := f.b.Verify()
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if _, err := VerifyAnchored(context.Background(), st, &fakeAudit{}); !errors.Is(err, ErrNotAnchored) {
		t.Errorf("err = %v, want ErrNotAnchored", err)
	}
	if AnchorMatches(st, 1, "x") {
		t.Error("an unanchored chain matched an anchor")
	}
}

func TestPrepareAnchorProducesASignableEntry(t *testing.T) {
	f := newFixture(t)
	l := testLog(t)
	ctx := context.Background()
	if err := l.Import(ctx, acct, f.entries()); err != nil {
		t.Fatalf("import: %v", err)
	}

	audit := &fakeAudit{seq: 42, hash: "head-at-42"}
	entry, input, err := l.PrepareAnchor(ctx, acct, audit, time.Unix(1300, 0))
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if entry.Op != OpAnchor {
		t.Fatalf("op = %q", entry.Op)
	}

	// Nothing was written. A prepared anchor nobody signs must leave no trace.
	if _, seq, err := l.Head(ctx, acct); err != nil || seq != 2 {
		t.Fatalf("preparing an anchor wrote to the log: seq %d (%v)", seq, err)
	}

	// And an authority signature over that input completes it.
	sigs, err := SignAuthorities(input, AuthoritySigner{Index: 0, Key: f.authorities[0]})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	entry.Sigs = sigs
	if err := l.Import(ctx, acct, []Entry{*entry}); err != nil {
		t.Fatalf("import signed anchor: %v", err)
	}

	st, err := l.State(ctx, acct)
	if err != nil {
		t.Fatalf("state: %v", err)
	}
	if !AnchorMatches(st, 42, "head-at-42") {
		t.Fatalf("anchor = %+v", st.Anchor)
	}
	if _, err := VerifyAnchored(ctx, st, audit); err != nil {
		t.Errorf("the anchor this log just committed does not verify: %v", err)
	}
}

// Re-anchoring the same point adds an entry that says nothing, to a log every
// node in the network replicates.
func TestPrepareAnchorRefusesToRepeatItself(t *testing.T) {
	f := newFixture(t)
	l := testLog(t)
	ctx := context.Background()
	audit := &fakeAudit{seq: 42, hash: "head-at-42"}
	anchored(t, f, audit.seq, audit.hash)
	if err := l.Import(ctx, acct, f.entries()); err != nil {
		t.Fatalf("import: %v", err)
	}

	if _, _, err := l.PrepareAnchor(ctx, acct, audit, time.Unix(1400, 0)); !errors.Is(err, ErrNothingToAnchor) {
		t.Fatalf("err = %v, want ErrNothingToAnchor", err)
	}

	// But once the audit log moves, it is due again.
	audit.seq, audit.hash = 43, "head-at-43"
	if _, _, err := l.PrepareAnchor(ctx, acct, audit, time.Unix(1400, 0)); err != nil {
		t.Fatalf("an advanced audit log was not anchorable: %v", err)
	}
}

func TestAnchorDue(t *testing.T) {
	f := newFixture(t)
	base, err := f.b.Verify()
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	now := time.Unix(100_000, 0)
	old := now.Add(-48 * time.Hour)
	recent := now.Add(-time.Minute)

	// Never anchored: anything at all is worth committing to.
	if !AnchorDue(base, 1, old, now, 100, 24*time.Hour) {
		t.Error("a never-anchored log with entries was not due")
	}
	if AnchorDue(base, 0, old, now, 100, 24*time.Hour) {
		t.Error("an empty audit log was due")
	}

	f2 := newFixture(t)
	st := anchored(t, f2, 500, "head-at-500")

	for _, tc := range []struct {
		name string
		seq  uint64
		last time.Time
		want bool
	}{
		{"unmoved", 500, recent, false},
		{"a few entries, recently anchored", 520, recent, false},
		{"a few entries, but long ago", 520, old, true},
		{"many entries, recently anchored", 700, recent, true},
		// A log *behind* its anchor has been truncated. Anchoring again would
		// paper over it; VerifyAnchored is what reports it.
		{"behind the anchor", 400, old, false},
	} {
		if got := AnchorDue(st, tc.seq, tc.last, now, 100, 24*time.Hour); got != tc.want {
			t.Errorf("%s: due = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// Anchors need one authority, not a quorum — spec §4 rule 8. Requiring q would
// mean anchoring stops exactly when the authorities are hardest to assemble,
// which is when a server is most likely to be misbehaving.
func TestAnAnchorNeedsOnlyOneAuthority(t *testing.T) {
	f := newFixture(t) // q = 2
	st := anchored(t, f, 7, "head-at-7")
	if st.Anchor == nil || st.Anchor.AuditSeq != 7 {
		t.Fatalf("a single-authority anchor was refused: %+v", st.Anchor)
	}
}
