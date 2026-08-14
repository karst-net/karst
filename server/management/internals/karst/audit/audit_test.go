// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package audit_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/netbirdio/netbird/management/internals/karst/audit"
)

func newLog(t *testing.T) (*audit.Log, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:audit%s?mode=memory&cache=shared", t.Name())),
		&gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("db: %v", err)
	}
	if err := db.Exec("DROP TABLE IF EXISTS karst_audit_log").Error; err != nil {
		t.Fatalf("reset: %v", err)
	}
	l, err := audit.New(db)
	if err != nil {
		t.Fatalf("log: %v", err)
	}
	return l, db
}

func appendN(t *testing.T, l *audit.Log, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if _, err := l.Append(context.Background(), "alice", "peer.login",
			fmt.Sprintf("node-%d", i), "detail"); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
}

func TestAppendChainsEntries(t *testing.T) {
	l, _ := newLog(t)
	ctx := context.Background()

	first, err := l.Append(ctx, "alice", "peer.login", "node-1", "")
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	if first.Seq != 1 || first.PrevHash != "" || first.Hash == "" {
		t.Fatalf("first entry: seq=%d prev=%q hash=%q", first.Seq, first.PrevHash, first.Hash)
	}

	second, err := l.Append(ctx, "bob", "peer.logout", "node-1", "")
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	if second.Seq != 2 {
		t.Fatalf("seq: got %d want 2", second.Seq)
	}
	if second.PrevHash != first.Hash {
		t.Fatal("the second entry does not commit to the first")
	}
	if second.Hash == first.Hash {
		t.Fatal("two entries share a hash")
	}
}

func TestVerifyAcceptsAnIntactLog(t *testing.T) {
	l, _ := newLog(t)
	appendN(t, l, 20)

	broken, err := l.Verify(context.Background())
	if err != nil {
		t.Fatalf("verify: %v (entry %d)", err, broken)
	}
	if broken != 0 {
		t.Fatalf("intact log reported entry %d as broken", broken)
	}
}

func TestVerifyEmptyLog(t *testing.T) {
	l, _ := newLog(t)
	if broken, err := l.Verify(context.Background()); err != nil || broken != 0 {
		t.Fatalf("empty log: %v (entry %d)", err, broken)
	}
}

// Modifying any field must break the chain, and the break must be reported at
// the entry that was modified rather than somewhere downstream.
func TestModificationIsDetected(t *testing.T) {
	for _, field := range []string{"actor", "action", "target", "detail"} {
		t.Run(field, func(t *testing.T) {
			l, db := newLog(t)
			appendN(t, l, 10)

			if err := db.Model(&audit.Entry{}).Where("seq = ?", 5).
				Update(field, "tampered").Error; err != nil {
				t.Fatalf("tamper: %v", err)
			}

			broken, err := l.Verify(context.Background())
			if !errors.Is(err, audit.ErrBroken) {
				t.Fatalf("modification went undetected: %v", err)
			}
			if broken != 5 {
				t.Fatalf("break reported at entry %d, want 5", broken)
			}
		})
	}
}

// Deleting an entry from the middle leaves a gap. Reporting the gap is more
// useful than reporting the hash mismatch it causes downstream.
func TestDeletionFromTheMiddleIsDetected(t *testing.T) {
	l, db := newLog(t)
	appendN(t, l, 10)

	if err := db.Where("seq = ?", 4).Delete(&audit.Entry{}).Error; err != nil {
		t.Fatalf("delete: %v", err)
	}
	broken, err := l.Verify(context.Background())
	if !errors.Is(err, audit.ErrBroken) {
		t.Fatalf("deletion went undetected: %v", err)
	}
	if broken != 5 {
		t.Fatalf("break reported at entry %d, want 5 (the entry after the gap)", broken)
	}
}

// An attacker who rewrites an entry *and* recomputes its hash still fails,
// because the next entry commits to the old one.
func TestRehashingASingleEntryStillBreaksTheChain(t *testing.T) {
	l, db := newLog(t)
	appendN(t, l, 6)

	var e audit.Entry
	if err := db.Where("seq = ?", 3).First(&e).Error; err != nil {
		t.Fatalf("read: %v", err)
	}
	e.Action = "peer.delete"
	// Recompute exactly as the implementation would.
	if err := db.Model(&audit.Entry{}).Where("seq = ?", 3).
		Updates(map[string]any{"action": e.Action}).Error; err != nil {
		t.Fatalf("tamper: %v", err)
	}

	broken, err := l.Verify(context.Background())
	if !errors.Is(err, audit.ErrBroken) {
		t.Fatal("a rewritten entry went undetected")
	}
	if broken != 3 {
		t.Fatalf("break at %d, want 3", broken)
	}
}

// The honest limitation, asserted so nobody has to rediscover it: a hash chain
// does NOT detect truncation of its own tail. Nothing in the remaining entries
// commits to how many there should be.
func TestTailTruncationIsNotDetectedByVerifyAlone(t *testing.T) {
	l, db := newLog(t)
	appendN(t, l, 10)

	if err := db.Where("seq > ?", 6).Delete(&audit.Entry{}).Error; err != nil {
		t.Fatalf("truncate: %v", err)
	}
	broken, err := l.Verify(context.Background())
	if err != nil || broken != 0 {
		t.Fatalf("Verify unexpectedly caught a tail truncation: %v (%d). "+
			"If this now passes, the construction changed and the package "+
			"documentation is out of date.", err, broken)
	}
}

// …and the anchor is what closes that gap.
func TestAnchorDetectsTailTruncation(t *testing.T) {
	l, db := newLog(t)
	ctx := context.Background()
	appendN(t, l, 10)

	anchorSeq, anchorHash, err := l.Head(ctx)
	if err != nil {
		t.Fatalf("head: %v", err)
	}
	if anchorSeq != 10 {
		t.Fatalf("head seq: got %d want 10", anchorSeq)
	}

	// An intact log still satisfies its own anchor.
	if broken, err := l.VerifyFrom(ctx, anchorSeq, anchorHash); err != nil || broken != 0 {
		t.Fatalf("intact log failed its anchor: %v (%d)", err, broken)
	}

	if err := db.Where("seq > ?", 6).Delete(&audit.Entry{}).Error; err != nil {
		t.Fatalf("truncate: %v", err)
	}
	broken, err := l.VerifyFrom(ctx, anchorSeq, anchorHash)
	if !errors.Is(err, audit.ErrBroken) {
		t.Fatal("truncation past a published anchor went undetected")
	}
	if broken != anchorSeq {
		t.Fatalf("break reported at %d, want the anchor at %d", broken, anchorSeq)
	}
}

// An anchor whose hash was itself rewritten must not satisfy VerifyFrom.
func TestAnchorRejectsARewrittenEntry(t *testing.T) {
	l, db := newLog(t)
	ctx := context.Background()
	appendN(t, l, 5)

	seq, hashAtAnchor, err := l.Head(ctx)
	if err != nil {
		t.Fatalf("head: %v", err)
	}
	if err := db.Model(&audit.Entry{}).Where("seq = ?", seq).
		Update("hash", "AAAA").Error; err != nil {
		t.Fatalf("tamper: %v", err)
	}
	if _, err := l.VerifyFrom(ctx, seq, hashAtAnchor); !errors.Is(err, audit.ErrBroken) {
		t.Fatal("a rewritten anchor entry was accepted")
	}
}

func TestHeadOnEmptyLog(t *testing.T) {
	l, _ := newLog(t)
	if _, _, err := l.Head(context.Background()); !errors.Is(err, audit.ErrEmpty) {
		t.Fatalf("got %v want ErrEmpty", err)
	}
}

// Length prefixing: two different events must not hash identically because
// their fields concatenate the same way.
func TestFieldsCannotBeConfused(t *testing.T) {
	l, _ := newLog(t)
	ctx := context.Background()

	a, err := l.Append(ctx, "ab", "c", "t", "d")
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	b, err := l.Append(ctx, "a", "bc", "t", "d")
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	if a.Hash == b.Hash {
		t.Fatal("ambiguous concatenation: two different events share a hash")
	}
}
