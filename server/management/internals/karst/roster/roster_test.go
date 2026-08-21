// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package roster

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/netbirdio/netbird/management/internals/karst/node"
)

// identityKeySize is ML-DSA-65's public key. The relay refuses any other
// length at load, so a fixture of the wrong size would test the error path
// while claiming to test the happy one.
const identityKeySize = 1952

func key(seed byte) []byte {
	out := make([]byte, identityKeySize)
	for i := range out {
		out[i] = seed + byte(i%251)
	}
	return out
}

type fixed struct {
	rows []node.Identity
	err  error
}

func (f fixed) All() ([]node.Identity, error) { return f.rows, f.err }

func TestRenderIsTheFormatTheRelayParses(t *testing.T) {
	out := string(Render([]node.Identity{
		{Handle: "b", PublicKey: key(2)},
		{Handle: "a", PublicKey: key(1)},
	}, "t1"))

	// Field names are the relay's, not ours: bins/karst-relay/src/roster.rs
	// deserialises `[[client]]` rows of `identity_pk` and `aquifer`. A
	// mismatch here is a relay that admits nobody and a file that looks fine.
	if strings.Count(out, "[[client]]") != 2 {
		t.Fatalf("want two client rows, got:\n%s", out)
	}
	for _, want := range []string{
		"identity_pk = \"" + base64.StdEncoding.EncodeToString(key(1)) + "\"",
		"identity_pk = \"" + base64.StdEncoding.EncodeToString(key(2)) + "\"",
		"aquifer = \"t1\"",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want[:min(len(want), 40)], out)
		}
	}
	// No node id, deliberately: the relay derives it from the key (§5.1), and
	// writing it here would make a silent mismatch a typo away.
	if strings.Contains(out, "node_id") || strings.Contains(out, "id = ") {
		t.Fatalf("the roster names an id it should derive:\n%s", out)
	}
}

func TestRenderIsOrderedRegardlessOfInput(t *testing.T) {
	// The relay reloads on any change and a shuffled file changes on every
	// write, so unordered output would swap the admission table several times
	// a minute for no reason.
	forward := Render([]node.Identity{
		{Handle: "a", PublicKey: key(1)},
		{Handle: "b", PublicKey: key(2)},
	}, "t1")
	backward := Render([]node.Identity{
		{Handle: "b", PublicKey: key(2)},
		{Handle: "a", PublicKey: key(1)},
	}, "t1")
	if string(forward) != string(backward) {
		t.Fatal("render depends on the order rows arrive in")
	}
}

func TestARowWithNoKeyIsSkippedRatherThanEmitted(t *testing.T) {
	// One unusable row must not take the rest of the deployment down with it:
	// the relay rejects a file it cannot parse *in full* and then runs on its
	// previous roster until the lease expires.
	out := string(Render([]node.Identity{
		{Handle: "a", PublicKey: nil},
		{Handle: "b", PublicKey: key(2)},
	}, "t1"))
	if strings.Count(out, "[[client]]") != 1 {
		t.Fatalf("want the one usable row, got:\n%s", out)
	}
}

func TestWriteFileReplacesAtomicallyAndSetsMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.toml")

	if err := WriteFile(path, []byte("first\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != FileMode.Perm() {
		t.Fatalf("mode %v, want %v", info.Mode().Perm(), FileMode.Perm())
	}

	if err := WriteFile(path, []byte("second\n")); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "second\n" {
		t.Fatalf("contents %q", got)
	}

	// No temp files left behind. The relay watches the directory's file by
	// name, but an operator reading a directory full of `.roster-*` would
	// reasonably wonder which one is live.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("want only the roster, got %d entries", len(entries))
	}
}

func TestARewriteMovesTheModificationTimeEvenWhenNothingChanged(t *testing.T) {
	// **The property the relay's lease depends on**, and the reason Run
	// rewrites unconditionally rather than on change. The relay's freshness
	// fingerprint is (contents, mtime): identical contents with an unchanged
	// mtime is a roster it considers stale, and after 90 seconds it admits
	// nobody. A deployment whose membership never changes is exactly the one
	// that would break.
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.toml")
	same := []byte("[[client]]\n")

	if err := WriteFile(path, same); err != nil {
		t.Fatalf("write: %v", err)
	}
	first, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	time.Sleep(10 * time.Millisecond)
	if err := WriteFile(path, same); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	second, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if !second.ModTime().After(first.ModTime()) {
		t.Fatalf("mtime did not move: %v then %v — the relay would treat this "+
			"roster as stale and stop admitting nodes", first.ModTime(), second.ModTime())
	}
}

func TestNoPathMeansNoRefresher(t *testing.T) {
	// A coordination server with no co-located relay must not write a file
	// nobody reads, and must not refuse to start because it was not told about
	// a relay it does not have.
	r, err := New(fixed{}, Config{}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r != nil {
		t.Fatal("a refresher was built for an empty path")
	}
	// And nil is safe to drive, so the caller needs no special case.
	r.Run(context.Background())
}

func TestAnAquiferIsRequired(t *testing.T) {
	// §5.4 scopes forwarding by aquifer. Defaulting it would put every node in
	// one namespace silently, which is the multi-tenant failure this rule
	// exists to prevent.
	if _, err := New(fixed{}, Config{Path: "/tmp/x"}, nil); err == nil {
		t.Fatal("an empty aquifer was accepted")
	}
}

func TestOnceWritesWhatTheSourceHas(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.toml")
	r, err := New(fixed{rows: []node.Identity{{Handle: "a", PublicKey: key(7)}}},
		Config{Path: path, Aquifer: "t1"}, nil)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := r.Once(); err != nil {
		t.Fatalf("once: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(got), base64.StdEncoding.EncodeToString(key(7))) {
		t.Fatalf("the enrolled key is not in the roster:\n%s", got)
	}
}

func TestAFailingSourceIsReportedAndNotWritten(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.toml")
	r, err := New(fixed{err: errors.New("database is down")},
		Config{Path: path, Aquifer: "t1"}, nil)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := r.Once(); err == nil {
		t.Fatal("a failing source was reported as success")
	}
	// **Nothing written.** Rendering an empty roster from a failed query would
	// hand the relay a valid file that admits nobody — a database blip would
	// become a fleet-wide outage, and the relay's own stale-roster rule is the
	// safer failure.
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("a roster was written from a failed query: %v", err)
	}
}

func TestRunKeepsGoingAfterAFailure(t *testing.T) {
	// A refresh failure must not stop the loop: the next tick is what recovers
	// admission, and a returning goroutine is a relay that fails closed
	// permanently ninety seconds later.
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.toml")
	var logged int
	r, err := New(fixed{err: errors.New("nope")},
		Config{Path: path, Aquifer: "t1", Interval: time.Millisecond},
		func(string, ...any) { logged++ })
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	r.Run(ctx)
	if logged < 2 {
		t.Fatalf("the loop stopped after %d failures", logged)
	}
}

// TestRosterVector writes the fixture bins/karst-relay parses back.
//
// The Go renderer and the Rust parser are two implementations of one format,
// and nothing else checks that they agree — the same argument as
// `spec/vectors/karst-control-v1.json` for the wire formats. Without it, a
// field rename on either side is a relay that admits nobody, discovered in a
// deployment rather than in CI.
func TestRosterVector(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate this source file")
	}
	path := filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "..", "..",
		"spec", "vectors", "relay-roster-v1.toml")

	encoded := Render([]node.Identity{
		{Handle: "second", PublicKey: key(0x22)},
		{Handle: "first", PublicKey: key(0x11)},
	}, "vector-aquifer")

	if os.Getenv("UPDATE_VECTORS") == "1" {
		if err := os.WriteFile(path, encoded, 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		t.Logf("wrote %s", path)
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read the roster vector (regenerate with UPDATE_VECTORS=1): %v", err)
	}
	if string(want) != string(encoded) {
		t.Fatal("the generated roster differs from the committed fixture. " +
			"If this is an intended format change, regenerate with " +
			"UPDATE_VECTORS=1 and check bins/karst-relay still parses it.")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
