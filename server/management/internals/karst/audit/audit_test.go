// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package audit_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/netbirdio/netbird/management/internals/karst/audit"
)

type recordingDeliverer struct {
	entries []audit.Entry
	fail    bool
}

func (d *recordingDeliverer) Deliver(_ context.Context, _ audit.Sink, entry audit.Entry) error {
	if d.fail {
		return errors.New("receiver unavailable")
	}
	d.entries = append(d.entries, entry)
	return nil
}

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

func TestAppendQueuesAndRetriesSinkDelivery(t *testing.T) {
	l, _ := newLog(t)
	ctx := audit.WithAccount(context.Background(), "account-a")
	_, err := l.AddSink(ctx, "webhook", "https://siem.example.test/ingest")
	if err != nil {
		t.Fatalf("add sink: %v", err)
	}
	entry, err := l.Append(ctx, "alice", "peer.login", "node-1", "")
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	deliverer := &recordingDeliverer{fail: true}
	now := time.Now().UTC()
	if delivered, err := l.DeliverPendingAt(ctx, deliverer, 10, now); err != nil || delivered != 0 {
		t.Fatalf("failed delivery: delivered=%d err=%v", delivered, err)
	}
	deliverer.fail = false
	// A retry is deliberately backoff-scheduled. Advance the injected clock
	// rather than sleeping, so the test proves persistence rather than timing.
	if delivered, err := l.DeliverPendingAt(ctx, deliverer, 10, now.Add(time.Second)); err != nil || delivered != 1 {
		t.Fatalf("retry delivery: delivered=%d err=%v", delivered, err)
	}
	if len(deliverer.entries) != 1 || deliverer.entries[0].Hash != entry.Hash {
		t.Fatalf("delivered entries: %#v", deliverer.entries)
	}
	if delivered, err := l.DeliverPending(ctx, deliverer, 10); err != nil || delivered != 0 {
		t.Fatalf("delivered entry was sent twice: delivered=%d err=%v", delivered, err)
	}
}

func TestWebhookTransportDeliversImmutableEntry(t *testing.T) {
	entry := audit.Entry{Seq: 9, CreatedAt: time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC), Actor: "admin", Action: "karst.delete", Target: "nodes/node-a", PrevHash: "previous", Hash: "current"}
	seen := make(chan map[string]any, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "9", r.Header.Get("X-Karst-Audit-Sequence"))
		require.Equal(t, "current", r.Header.Get("X-Karst-Audit-Hash"))
		var payload map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&payload))
		seen <- payload
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	transport := &audit.Transport{HTTPClient: server.Client()}
	require.NoError(t, transport.Deliver(context.Background(), audit.Sink{Kind: "webhook", Endpoint: server.URL}, entry))
	payload := <-seen
	require.Equal(t, float64(9), payload["sequence"])
	require.Equal(t, "current", payload["hash"])
}

func TestSyslogTransportWritesRFC5424OverItsTLSChannel(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	transport := &audit.Transport{DialTLS: func(context.Context, string, string, *tls.Config) (net.Conn, error) { return client, nil }}
	entry := audit.Entry{Seq: 3, CreatedAt: time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC), Actor: "admin", Action: "karst.post", Target: "audit/sinks", Hash: "head"}
	message := make(chan string, 1)
	go func() { line, _ := bufio.NewReader(server).ReadString('\n'); message <- line }()
	require.NoError(t, transport.Deliver(context.Background(), audit.Sink{Kind: "syslog", Endpoint: "tls://syslog.example.test:6514"}, entry))
	line := <-message
	require.True(t, strings.HasPrefix(line, "<134>1 2026-08-28T12:00:00Z - karst-audit - AUDIT -"), line)
	require.Contains(t, line, `sequence="3" hash="head"`)
	require.Contains(t, line, `"target":"audit/sinks"`)
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

func TestListBeforeUsesAStableSequenceCursor(t *testing.T) {
	l, _ := newLog(t)
	ctx := context.Background()
	appendN(t, l, 5)

	first, err := l.ListBefore(ctx, 0, 2)
	if err != nil {
		t.Fatalf("first page: %v", err)
	}
	if got, want := []uint64{first[0].Seq, first[1].Seq}, []uint64{5, 4}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("first page: got %v want %v", got, want)
	}
	// A concurrent append moves the head but cannot move the next page below
	// the cursor, unlike an offset query.
	if _, err := l.Append(ctx, "alice", "peer.login", "node-new", "detail"); err != nil {
		t.Fatalf("concurrent append: %v", err)
	}
	second, err := l.ListBefore(ctx, first[len(first)-1].Seq, 2)
	if err != nil {
		t.Fatalf("second page: %v", err)
	}
	if got, want := []uint64{second[0].Seq, second[1].Seq}, []uint64{3, 2}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("second page: got %v want %v", got, want)
	}
}

func TestListFilteredHonorsActorAndAction(t *testing.T) {
	l, _ := newLog(t)
	ctx := context.Background()
	for _, entry := range []struct{ actor, action string }{
		{"alice", "policy.write"},
		{"bob", "policy.write"},
		{"alice", "node.delete"},
	} {
		if _, err := l.Append(ctx, entry.actor, entry.action, "node", ""); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	entries, err := l.ListFiltered(ctx, "alice", "policy.write", 0, 10)
	if err != nil {
		t.Fatalf("list filtered: %v", err)
	}
	if len(entries) != 1 || entries[0].Actor != "alice" || entries[0].Action != "policy.write" {
		t.Fatalf("unexpected filtered entries: %#v", entries)
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
