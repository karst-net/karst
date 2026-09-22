// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// Package roster renders and refreshes the admission file a co-located
// karst-relay reads — spec/ponor-v1.md §5.3.
//
// # Why this exists
//
// Ponor's admission is structural: `ClientAuth` carries no public key, so a
// relay verifies a node against a key it finds in its roster or it does not
// verify at all. There is deliberately no flag that admits an unknown peer.
//
// The relay also refuses to serve a roster nobody is maintaining. Its lease is
// 90 seconds (`roster::MAX_AGE` in bins/karst-relay); when the file has not
// changed within that window, admission is replaced with an empty roster and
// the relay stops admitting anyone. That is the correct behavior for a
// membership list — a stale one is one nobody is curating — and it has a
// consequence that was unwritten until GitHub issue [#47](https://github.com/karst-net/karst/issues/47): **something must rewrite
// that file, forever, or every deployment stops working ninety seconds after it
// starts.** Until this package, the only thing that did was a thread inside
// bins/karstd/tests/aquifer.rs.
//
// # Scope
//
// This serves the co-located deployment PLAN.md §5 makes the default: the
// coordination server and one relay on the same host, sharing a volume. A
// relay somewhere else needs the roster to travel with provenance, which is
// spec/ponor-v1.md §13.2 and is not this.
package roster

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/netbirdio/netbird/management/internals/karst/node"
)

// DefaultInterval is how often the file is rewritten.
//
// Comfortably inside the relay's 90-second lease, and deliberately not
// 89 seconds: a rewrite that fails leaves two more attempts before a relay
// starts refusing nodes, so a transient full disk or a slow volume costs
// nothing.
const DefaultInterval = 25 * time.Second

// FileMode is the permission the roster is written with.
//
// A roster is a membership list — it names every node in the deployment — and
// spec/ponor-v1.md §11 counts what a relay operator learns as a disclosure to
// be bounded rather than ignored. It carries no private key, so this is 0640
// rather than 0600: the relay must be able to read it as its own user.
const FileMode os.FileMode = 0o640

// Entry is one enrolled identity together with the account it belongs to.
//
// AccountID is what makes an aquifer a real per-tenant boundary instead of a
// single operator-fixed string (ADR-0033): Render places each entry in an
// aquifer derived from its AccountID, not a value shared by the whole
// roster. AccountID == "" means "no live peer owns this identity right now"
// (see node.Store.AccountsByHandle) and Render skips such an entry — there
// is no safe aquifer to place it in.
type Entry struct {
	node.Identity
	AccountID string
}

// Source is the set of enrolled identities to admit, each paired with the
// account that owns it.
//
// An interface rather than *node.Store so this package can be tested without
// a database. NodeSource is the production implementation.
type Source interface {
	All() ([]Entry, error)
}

// NodeSource adapts a *node.Store into a Source, resolving each identity's
// owning account by joining against the forked server's peers table
// (node.Store.AccountsByHandle) — ADR-0033.
type NodeSource struct {
	Nodes *node.Store
}

// All implements Source.
func (s NodeSource) All() ([]Entry, error) {
	identities, err := s.Nodes.All()
	if err != nil {
		return nil, fmt.Errorf("roster: list identities: %w", err)
	}
	handles := make([]string, len(identities))
	for i := range identities {
		handles[i] = identities[i].Handle
	}
	accounts, err := s.Nodes.AccountsByHandle(handles)
	if err != nil {
		return nil, fmt.Errorf("roster: resolve accounts: %w", err)
	}
	entries := make([]Entry, len(identities))
	for i := range identities {
		entries[i] = Entry{Identity: identities[i], AccountID: accounts[identities[i].Handle]}
	}
	return entries, nil
}

// Config is what a co-located relay needs to be told.
type Config struct {
	// Path to the roster file. Empty disables the refresher entirely.
	Path string
	// AquiferPrefix optionally namespaces every derived aquifer value as
	// "{prefix}:{account-id}" instead of a bare "{account-id}" (ADR-0033).
	//
	// Meant for an operator running more than one karst-control deployment
	// against a shared relay pool who wants relay-side logs legible by
	// deployment — not required for tenant isolation itself, since account
	// IDs are already unique per deployment. Empty (the common case) is
	// fine and produces a bare account ID.
	AquiferPrefix string
	// Interval between rewrites. Zero means DefaultInterval.
	Interval time.Duration
}

// Refresher rewrites the roster file on an interval.
type Refresher struct {
	source Source
	cfg    Config
	log    func(format string, args ...any)
}

// New returns a Refresher, or nil when no path is configured.
//
// Returning nil for an absent path is deliberate: a coordination server with no
// co-located relay must not write a file nobody reads, and must not fail to
// start because it was not told about a relay it does not have.
func New(source Source, cfg Config, logf func(string, ...any)) (*Refresher, error) {
	if cfg.Path == "" {
		return nil, nil
	}
	if source == nil {
		return nil, fmt.Errorf("roster: no identity source")
	}
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultInterval
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Refresher{source: source, cfg: cfg, log: logf}, nil
}

// Run rewrites the file immediately and then on every tick until ctx ends.
//
// **The rewrite is unconditional, not change-driven**, and that is the whole
// point of the interval. The relay's lease is refreshed by the file's
// modification time, not by its contents, so a deployment whose membership is
// stable still needs the file touched — and a change-driven writer would leave
// exactly the quiet, working deployments failing closed after ninety seconds.
func (r *Refresher) Run(ctx context.Context) {
	if r == nil {
		return
	}
	ticker := time.NewTicker(r.cfg.Interval)
	defer ticker.Stop()
	for {
		if err := r.Once(); err != nil {
			// Logged and not fatal. A failure here costs admission of *new*
			// nodes after the lease expires; killing the coordination server
			// would cost every node its netmap immediately, which is worse.
			r.log("karst: roster refresh failed: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Once renders the current membership and replaces the file.
func (r *Refresher) Once() error {
	entries, err := r.source.All()
	if err != nil {
		return fmt.Errorf("roster: list identities: %w", err)
	}
	return WriteFile(r.cfg.Path, Render(entries, r.cfg.AquiferPrefix))
}

// Render returns the TOML the relay parses.
//
// The format derives rather than repeats: an entry carries the identity key and
// the aquifer, and the relay computes the node id from the key (§5.1). Writing
// an id here as well would make a silent mismatch a typo away.
func Render(entries []Entry, aquiferPrefix string) []byte {
	sorted := make([]Entry, len(entries))
	copy(sorted, entries)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Handle < sorted[j].Handle })

	var b strings.Builder
	b.WriteString("# Generated by karst-control. Do not edit: rewritten every ")
	b.WriteString(DefaultInterval.String())
	b.WriteString(".\n")
	b.WriteString("# The relay's lease is 90s; a file that stops being rewritten stops admitting nodes.\n")
	for i := range sorted {
		if len(sorted[i].PublicKey) == 0 {
			// A row with no key cannot be admitted and cannot be verified.
			// Skipping it keeps the file parseable; the relay would reject the
			// whole file over one malformed entry, which would take every
			// other node down with it.
			continue
		}
		if sorted[i].AccountID == "" {
			// No live peer owns this identity right now (ADR-0033) — most
			// often an identity row that outlived its peer's deletion. There
			// is no safe aquifer to place it in, and a deleted peer must not
			// stay relay-admitted regardless of what a fallback value would
			// have been.
			continue
		}
		b.WriteString("\n[[client]]\nidentity_pk = \"")
		b.WriteString(base64.StdEncoding.EncodeToString(sorted[i].PublicKey))
		b.WriteString("\"\naquifer = \"")
		b.WriteString(aquiferValue(aquiferPrefix, sorted[i].AccountID))
		b.WriteString("\"\n")
	}
	return []byte(b.String())
}

// aquiferValue derives the wire aquifer identity for an account — ADR-0033.
func aquiferValue(prefix, accountID string) string {
	if prefix == "" {
		return accountID
	}
	return prefix + ":" + accountID
}

// WriteFile replaces path atomically.
//
// Temp file in the same directory, then rename. The relay reloads whenever the
// file changes, so a reader that caught a half-written file would parse a
// truncated roster — and a roster that fails to parse leaves the relay on its
// previous one until the lease runs out. Rename is what makes the swap
// indivisible; a same-directory temp file is what makes rename possible, since
// it cannot cross a filesystem boundary.
func WriteFile(path string, contents []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".roster-*")
	if err != nil {
		return fmt.Errorf("roster: create temp: %w", err)
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()

	if _, err := tmp.Write(contents); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("roster: write: %w", err)
	}
	// Durable before it is visible: a rename that survives a crash while the
	// contents do not would leave a valid-looking, empty roster in place.
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("roster: sync: %w", err)
	}
	if err := tmp.Chmod(FileMode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("roster: chmod: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("roster: close: %w", err)
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("roster: rename: %w", err)
	}
	return nil
}
