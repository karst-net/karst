// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package bedrock

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// A DSN named after the test, matching store_test.go. A shared unnamed
// in-memory database would be one database for the whole package, and these
// tests deliberately import conflicting histories.
func testLog(t *testing.T) *Log {
	t.Helper()
	db, err := gorm.Open(
		sqlite.Open(fmt.Sprintf("file:bedrock-log-%s?mode=memory&cache=shared", t.Name())),
		&gorm.Config{Logger: logger.Discard},
	)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	l, err := NewLog(db)
	if err != nil {
		t.Fatalf("new log: %v", err)
	}
	return l
}

const acct = "account-one"

func TestPendingRequestCommitsOnlyVerifiedOfflineSignatures(t *testing.T) {
	f := newFixture(t)
	l := testLog(t)
	ctx := context.Background()
	if err := l.Import(ctx, acct, f.entries()); err != nil {
		t.Fatalf("import base log: %v", err)
	}
	bob := nodeKeys(t, 0x88)
	base := f.entries()
	builder, err := FromEntries(base)
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	pending, _ := builder.Prepare(1200, OpNodeSign, signBody(bob, 0, 0))
	request, err := l.CreatePending(ctx, acct, []Entry{*pending})
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	if request.PayloadHash == "" {
		t.Fatal("request has no payload hash")
	}
	// The server recomputes the input from its verified history; the signature
	// handed back by the offline device is accepted only for that exact entry.
	input := pending.SigningInput(base[len(base)-1].Hash)
	sigs, err := SignAuthorities(input, AuthoritySigner{Index: 0, Key: f.authorities[0]}, AuthoritySigner{Index: 1, Key: f.authorities[1]})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := l.CommitPending(ctx, acct, map[uint64][]Signature{pending.Seq: sigs}); err != nil {
		t.Fatalf("commit pending: %v", err)
	}
	if request, err := l.Pending(ctx, acct); err != nil || request != nil {
		t.Fatalf("pending after commit = %#v, %v", request, err)
	}
	state, err := l.State(ctx, acct)
	if err != nil {
		t.Fatalf("state: %v", err)
	}
	if !state.IsCovered(bob.Handle, bob.Keys, 1300) {
		t.Fatal("offline-signed node is not covered")
	}
}

func TestImportStoresAVerifiedChain(t *testing.T) {
	f := newFixture(t)
	l := testLog(t)
	ctx := context.Background()

	if err := l.Import(ctx, acct, f.entries()); err != nil {
		t.Fatalf("import: %v", err)
	}

	hash, seq, err := l.Head(ctx, acct)
	if err != nil {
		t.Fatalf("head: %v", err)
	}
	if seq != 2 {
		t.Errorf("head seq = %d, want 2", seq)
	}
	if len(hash) != 64 {
		t.Errorf("head hash is %d bytes, want 64", len(hash))
	}

	st, err := l.State(ctx, acct)
	if err != nil {
		t.Fatalf("state: %v", err)
	}
	if !st.IsCovered(f.alice.Handle, f.alice.Keys, 2000) {
		t.Error("alice should be covered from the stored log")
	}
}

// The property that makes the server a cache rather than an author: it will not
// store something it cannot verify, so a corrupt log is refused at import with
// a legible error rather than propagating to every node in the network.
func TestImportRefusesAChainThatDoesNotVerify(t *testing.T) {
	f := newFixture(t)
	l := testLog(t)

	entries := f.entries()
	body := append([]byte(nil), entries[1].Body...)
	body[len(body)-1] ^= 0x01
	entries[1].Body = body

	if err := l.Import(context.Background(), acct, entries); err == nil {
		t.Fatal("stored a chain that does not verify")
	}
	if _, _, err := l.Head(context.Background(), acct); !errors.Is(err, ErrNoLog) {
		t.Errorf("a refused import left something behind: %v", err)
	}
}

func TestImportIsIncrementalAndIdempotent(t *testing.T) {
	f := newFixture(t)
	l := testLog(t)
	ctx := context.Background()

	all := f.entries()
	if err := l.Import(ctx, acct, all[:1]); err != nil {
		t.Fatalf("import genesis: %v", err)
	}
	// Re-importing what is already stored must be a no-op, not a conflict:
	// an operator who imports the same bundle twice has made no mistake.
	if err := l.Import(ctx, acct, all); err != nil {
		t.Fatalf("import rest: %v", err)
	}
	if err := l.Import(ctx, acct, all); err != nil {
		t.Fatalf("re-import: %v", err)
	}

	_, seq, err := l.Head(ctx, acct)
	if err != nil {
		t.Fatalf("head: %v", err)
	}
	if seq != 2 {
		t.Errorf("head seq = %d, want 2", seq)
	}
}

// An import that disagrees with stored history is a rewrite, and a rewrite is
// what the chain exists to make impossible. It must be refused even though the
// replacement entry is itself perfectly well-formed.
func TestImportRefusesToRewriteStoredHistory(t *testing.T) {
	f := newFixture(t)
	l := testLog(t)
	ctx := context.Background()

	stored := f.entries()
	if err := l.Import(ctx, acct, stored); err != nil {
		t.Fatalf("import: %v", err)
	}

	// A *genuinely* divergent entry 2 on the same genesis. Building a second
	// fixture would not do it: the fixtures are deterministic, so two of them
	// are byte-identical and the import would be correctly accepted as a
	// repeat. The history has to actually differ for this to test anything.
	fork := NewBuilder()
	if err := fork.Commit(&Entry{
		Seq: stored[0].Seq, Time: stored[0].Time,
		Op: stored[0].Op, Body: stored[0].Body,
	}, stored[0].Sigs); err != nil {
		t.Fatalf("commit genesis: %v", err)
	}
	e, input := fork.Prepare(1100, OpNodeSign, signBody(nodeKeys(t, 0xBB), 0, 0))
	sigs, err := SignAuthorities(input,
		AuthoritySigner{Index: 0, Key: f.authorities[0]},
		AuthoritySigner{Index: 1, Key: f.authorities[1]},
	)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := fork.Commit(e, sigs); err != nil {
		t.Fatalf("commit: %v", err)
	}

	// Every signature in the fork is genuine. It is refused because it
	// contradicts what is stored, not because it is malformed.
	if err := l.Import(ctx, acct, fork.Entries()); !errors.Is(err, ErrNotExtension) {
		t.Fatalf("a divergent history was accepted: %v", err)
	}

	// And the stored log is untouched.
	st, err := l.State(ctx, acct)
	if err != nil {
		t.Fatalf("state: %v", err)
	}
	if !st.IsCovered(f.alice.Handle, f.alice.Keys, 2000) {
		t.Error("the stored history was disturbed by a refused import")
	}
	if _, ok := st.Covered[nodeKeys(t, 0xBB).Handle]; ok {
		t.Error("the forked entry was stored")
	}
}

func TestImportRefusesAGap(t *testing.T) {
	f := newFixture(t)
	l := testLog(t)
	ctx := context.Background()

	all := f.entries()
	if err := l.Import(ctx, acct, all[:1]); err != nil {
		t.Fatalf("import genesis: %v", err)
	}
	f.appendAuth(t, 1200, OpNodeSign, signBody(nodeKeys(t, 0x88), 0, 0))
	extended := f.entries()

	// Entry 3 without entry 2.
	if err := l.Import(ctx, acct, extended[2:]); !errors.Is(err, ErrNotExtension) {
		t.Fatalf("a gap was accepted: %v", err)
	}
}

func TestEntriesServesForwardFromASequence(t *testing.T) {
	f := newFixture(t)
	f.appendAuth(t, 1200, OpNodeSign, signBody(nodeKeys(t, 0x88), 0, 0))
	l := testLog(t)
	ctx := context.Background()
	if err := l.Import(ctx, acct, f.entries()); err != nil {
		t.Fatalf("import: %v", err)
	}

	for _, tc := range []struct {
		since uint64
		want  int
	}{{0, 3}, {1, 2}, {2, 1}, {3, 0}, {99, 0}} {
		got, err := l.Entries(ctx, acct, tc.since, MaxEntriesPerResponse)
		if err != nil {
			t.Fatalf("entries since %d: %v", tc.since, err)
		}
		if len(got) != tc.want {
			t.Errorf("since %d returned %d entries, want %d", tc.since, len(got), tc.want)
		}
	}
}

// A reply is bounded so that a node with an empty log does not pull megabytes
// down a channel sized for netmaps. It fetches forward instead.
func TestEntriesAreCapped(t *testing.T) {
	l := testLog(t)
	got, err := l.Entries(context.Background(), acct, 0, 10_000)
	if err != nil {
		t.Fatalf("entries: %v", err)
	}
	if len(got) > MaxEntriesPerResponse {
		t.Errorf("returned %d entries, cap is %d", len(got), MaxEntriesPerResponse)
	}
}

func TestAnAccountWithNoLogIsNotAnError(t *testing.T) {
	l := testLog(t)
	ctx := context.Background()

	if _, _, err := l.Head(ctx, "nobody"); !errors.Is(err, ErrNoLog) {
		t.Errorf("head: %v", err)
	}
	if _, err := l.State(ctx, "nobody"); !errors.Is(err, ErrNoLog) {
		t.Errorf("state: %v", err)
	}
	entries, err := l.Entries(ctx, "nobody", 0, MaxEntriesPerResponse)
	if err != nil {
		t.Fatalf("entries: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("got %d entries for an account with no log", len(entries))
	}
}

// Logs are per-account. A node in one account must not be served another's.
func TestLogsAreScopedByAccount(t *testing.T) {
	f := newFixture(t)
	l := testLog(t)
	ctx := context.Background()
	if err := l.Import(ctx, acct, f.entries()); err != nil {
		t.Fatalf("import: %v", err)
	}

	entries, err := l.Entries(ctx, "another-account", 0, MaxEntriesPerResponse)
	if err != nil {
		t.Fatalf("entries: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("another account was served %d entries", len(entries))
	}
}

// ── exit criterion 6: rebuilding a server from a node's copy ────────────────

// **A rebuilt server, re-seeded from a node's replicated copy, produces the
// same head.**
//
// Plan §9 calls this "the strongest argument for the whole design", and it is:
// the log is not the server's, so losing the server loses nothing. Every node
// holds a full copy and the chain proves the restored one is the same history —
// not a plausible reconstruction, the *same* one, down to the head hash the
// netmap advertises.
//
// The re-seed deliberately goes through the ordinary Import path. A restore
// route that skipped verification would be a way to install a forged history on
// a server, which is the one thing this design must not have.
func TestARebuiltServerReseededFromANodeProducesTheSameHead(t *testing.T) {
	f := newFixture(t)
	f.appendAuth(t, 1200, OpNodeSign, signBody(nodeKeys(t, 0x88), 0, 0))
	f.appendAuth(t, 1300, OpNodeRevoke, NodeRevokeBody(f.alice.Handle, "rotated", 1350))

	original := testLog(t)
	ctx := context.Background()
	if err := original.Import(ctx, acct, f.entries()); err != nil {
		t.Fatalf("import: %v", err)
	}
	wantHash, wantSeq, err := original.Head(ctx, acct)
	if err != nil {
		t.Fatalf("head: %v", err)
	}

	// What a node holds: the encoded log, exactly as karstd persists it and as
	// KarstBedrockResponse carries it. Nothing server-side is involved.
	stored, err := original.All(ctx, acct)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	replicated := EncodeLog(stored)

	// The server is gone. A new one, empty, is handed that copy.
	rebuilt := &Log{db: original.db}
	if err := rebuilt.db.Where("account_id = ?", acct).Delete(&LogEntry{}).Error; err != nil {
		t.Fatalf("simulate loss: %v", err)
	}
	if _, _, err := rebuilt.Head(ctx, acct); !errors.Is(err, ErrNoLog) {
		t.Fatalf("the server was not actually emptied: %v", err)
	}

	decoded, err := DecodeLog(replicated)
	if err != nil {
		t.Fatalf("decode the node's copy: %v", err)
	}
	if err := rebuilt.Import(ctx, acct, decoded); err != nil {
		t.Fatalf("re-seed: %v", err)
	}

	gotHash, gotSeq, err := rebuilt.Head(ctx, acct)
	if err != nil {
		t.Fatalf("head: %v", err)
	}
	if gotSeq != wantSeq || !bytes.Equal(gotHash, wantHash) {
		t.Fatalf("re-seeded head %x@%d, want %x@%d", gotHash, gotSeq, wantHash, wantSeq)
	}

	// And the state it establishes is the same state, not merely the same hash.
	st, err := rebuilt.State(ctx, acct)
	if err != nil {
		t.Fatalf("state: %v", err)
	}
	if !st.IsCovered(nodeKeys(t, 0x88).Handle, nodeKeys(t, 0x88).Keys, 1400) {
		t.Error("a node covered before the loss is not covered after the restore")
	}
	if st.IsCovered(f.alice.Handle, f.alice.Keys, 1400) {
		t.Error("a revocation did not survive the restore")
	}
}

// A node's copy that has been tampered with cannot re-seed a server. The
// restore path is Import, so it verifies like any other write — an operator
// restoring from a compromised node gets a refusal rather than a forged
// history installed as authoritative.
func TestAReseedFromATamperedCopyIsRefused(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	original := testLog(t)
	if err := original.Import(ctx, acct, f.entries()); err != nil {
		t.Fatalf("import: %v", err)
	}
	stored, err := original.All(ctx, acct)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	body := append([]byte(nil), stored[1].Body...)
	body[len(body)-1] ^= 0x01
	stored[1].Body = body

	rebuilt := &Log{db: original.db}
	if err := rebuilt.db.Where("account_id = ?", acct).Delete(&LogEntry{}).Error; err != nil {
		t.Fatalf("simulate loss: %v", err)
	}
	if err := rebuilt.Import(ctx, acct, stored); err == nil {
		t.Fatal("a tampered replica re-seeded the server")
	}
	if _, _, err := rebuilt.Head(ctx, acct); !errors.Is(err, ErrNoLog) {
		t.Errorf("a refused re-seed left something behind: %v", err)
	}
}
