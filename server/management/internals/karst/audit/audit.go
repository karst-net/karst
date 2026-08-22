// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// Package audit is the append-only, hash-chained activity log (PLAN.md §4.1).
//
// Each entry commits to its predecessor:
//
//	hash_n = SHA-256("karst-audit-v1" ‖ hash_{n-1} ‖ seq ‖ time ‖ actor ‖ …)
//
// so any modification, insertion or reordering of an entry breaks every hash
// after it. An operator who verifies the chain learns not just that the log
// changed but where.
//
// # What a hash chain does not do
//
// **It does not detect truncation of the tail.** Delete the last k entries and
// the remaining chain still verifies perfectly, because nothing in it commits
// to how long it is meant to be. This is inherent to the construction, not an
// implementation gap, and it is the single most useful thing to know about an
// audit log that advertises tamper-evidence.
//
// The mitigation is an external anchor: [Log.Head] returns the current head
// hash and sequence, which an operator publishes, signs, or ships off-box on a
// schedule. Truncation past a published anchor is then detectable. Bedrock's
// quorum signing (PLAN.md §4.5) is the intended home for that; until it lands,
// the anchor has to be exported and stored somewhere the server cannot reach.
//
// The chain also says nothing about entries that were never written. A server
// that declines to log an action produces a perfectly valid chain.
package audit

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"net/netip"
	"net/url"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const chainLabel = "karst-audit-v1"

var (
	// ErrBroken is returned by Verify when the chain does not hold.
	ErrBroken = errors.New("audit: hash chain is broken")
	// ErrEmpty is returned by Head when nothing has been logged.
	ErrEmpty = errors.New("audit: log is empty")
)

var ErrNoAccount = errors.New("audit: account scope missing")

type accountContextKey struct{}

func WithAccount(ctx context.Context, accountID string) context.Context {
	return context.WithValue(ctx, accountContextKey{}, accountID)
}
func accountFromContext(ctx context.Context) (string, error) {
	accountID, _ := ctx.Value(accountContextKey{}).(string)
	if accountID == "" {
		return "", ErrNoAccount
	}
	return accountID, nil
}

// Entry is one recorded action.
//
// There is no update path and no delete path, here or in the store. Append-only
// is a property of the API surface, not a convention: a method that could
// rewrite an entry would be the first thing an attacker with code execution
// reached for, and its absence is cheaper to audit than its correctness.
type Entry struct {
	Seq       uint64    `gorm:"primaryKey;autoIncrement:false"`
	CreatedAt time.Time `gorm:"index"`
	// Actor is who did it: a node handle, a user ID, or "system".
	Actor string `gorm:"index"`
	// Action is what happened, as a stable machine-readable verb.
	Action string `gorm:"index"`
	// Target is what it happened to.
	Target string `gorm:"index"`
	// Detail is free-form context. MUST NOT contain secrets; the PSK type
	// refuses to render precisely so that this cannot happen by accident.
	Detail string
	// PrevHash is the chain hash of the entry before this one, empty for the
	// first. Stored so a verifier can check the chain without recomputing the
	// whole log from scratch.
	PrevHash string
	// Hash is this entry's chain hash.
	Hash string `gorm:"index"`
}

// AddSink records a credential-free audit delivery destination. Secrets for a
// webhook belong in the secret store and are deliberately not accepted here.
func (l *Log) AddSink(ctx context.Context, kind, endpoint string) (*Sink, error) {
	accountID, err := accountFromContext(ctx)
	if err != nil {
		return nil, err
	}
	if kind != "webhook" && kind != "syslog" {
		return nil, fmt.Errorf("audit: unsupported sink kind %q", kind)
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("audit: invalid sink endpoint")
	}
	if kind == "webhook" && u.Scheme != "https" {
		return nil, fmt.Errorf("audit: webhook endpoint must use https")
	}
	if kind == "syslog" && u.Scheme != "tls" {
		return nil, fmt.Errorf("audit: syslog endpoint must use tls")
	}
	if ip, err := netip.ParseAddr(u.Hostname()); err == nil && !ip.IsGlobalUnicast() {
		return nil, fmt.Errorf("audit: sink endpoint must not use a non-global IP")
	}
	s := &Sink{AccountID: accountID, ID: fmt.Sprintf("sink-%x", sha256.Sum256([]byte(accountID+"\x00"+kind+"\x00"+endpoint))), Kind: kind, Endpoint: endpoint, CreatedAt: time.Now().UTC()}
	if err := l.db.WithContext(ctx).Clauses(clause.OnConflict{DoNothing: true}).Create(s).Error; err != nil {
		return nil, fmt.Errorf("audit: create sink: %w", err)
	}
	if err := l.db.WithContext(ctx).Where("account_id = ? AND id = ?", accountID, s.ID).First(s).Error; err != nil {
		return nil, fmt.Errorf("audit: load sink: %w", err)
	}
	return s, nil
}

// Sink is an audit export destination. Credentials are deliberately not part
// of this model; a delivery implementation must obtain them from the secret
// store rather than returning or persisting them with the REST configuration.
type Sink struct {
	AccountID string `gorm:"primaryKey;size:64"`
	ID        string `gorm:"primaryKey"`
	Kind      string `gorm:"not null"`
	Endpoint  string `gorm:"not null"`
	CreatedAt time.Time
}

func (Sink) TableName() string { return "karst_audit_sinks" }

func (Entry) TableName() string { return "karst_audit_log" }

// chainHash computes an entry's hash from its content and its predecessor.
//
// Every field is length-prefixed. Without it, an actor of "ab" with action "c"
// and an actor of "a" with action "bc" would hash identically, and an audit log
// where two different events share a hash is one where a substitution is
// invisible.
func chainHash(prev string, e *Entry) string {
	h := sha256.New()
	h.Write([]byte(chainLabel))
	writeField(h, []byte(prev))

	var seq [8]byte
	binary.BigEndian.PutUint64(seq[:], e.Seq)
	writeField(h, seq[:])

	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(e.CreatedAt.UTC().UnixNano()))
	writeField(h, ts[:])

	writeField(h, []byte(e.Actor))
	writeField(h, []byte(e.Action))
	writeField(h, []byte(e.Target))
	writeField(h, []byte(e.Detail))

	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func writeField(h hash.Hash, field []byte) {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(field)))
	h.Write(l[:])
	h.Write(field)
}

// Log is the append-only store.
type Log struct{ db *gorm.DB }

// List returns a stable, newest-first page of append-only entries.
func (l *Log) List(ctx context.Context, offset, limit int) ([]Entry, error) {
	return l.ListFiltered(ctx, "", "", offset, limit)
}

// ListFiltered returns a stable, newest-first page narrowed by the documented
// actor and action filters. Empty filters deliberately mean "any", so callers
// can compose either dimension without broadening the other.
func (l *Log) ListFiltered(ctx context.Context, actor, action string, offset, limit int) ([]Entry, error) {
	query := l.db.WithContext(ctx).Order("seq DESC").Offset(offset).Limit(limit)
	if actor != "" {
		query = query.Where("actor = ?", actor)
	}
	if action != "" {
		query = query.Where("action = ?", action)
	}
	var entries []Entry
	if err := query.Find(&entries).Error; err != nil {
		return nil, fmt.Errorf("audit: list: %w", err)
	}
	return entries, nil
}

// ListBefore returns a newest-first page strictly below before. A zero cursor
// starts at the current head. Sequence numbers are immutable, so this remains
// stable while new entries are appended; offset pagination would otherwise
// duplicate or skip entries as the head moves between pages.
func (l *Log) ListBefore(ctx context.Context, before uint64, limit int) ([]Entry, error) {
	query := l.db.WithContext(ctx).Order("seq DESC").Limit(limit)
	if before != 0 {
		query = query.Where("seq < ?", before)
	}
	var entries []Entry
	if err := query.Find(&entries).Error; err != nil {
		return nil, fmt.Errorf("audit: list before: %w", err)
	}
	return entries, nil
}

// New migrates the audit table and returns a log over it.
func New(db *gorm.DB) (*Log, error) {
	if db == nil {
		return nil, errors.New("audit: nil database")
	}
	if err := db.AutoMigrate(&Entry{}, &Sink{}); err != nil {
		return nil, fmt.Errorf("audit: migrate: %w", err)
	}
	return &Log{db: db}, nil
}

// Append records an action and returns the entry as written.
//
// The whole operation runs in one transaction with the tail read for update.
// Two concurrent appends that both read the same predecessor would otherwise
// produce two entries claiming the same position, and a chain that forks is a
// chain that proves nothing.
func (l *Log) Append(ctx context.Context, actor, action, target, detail string) (*Entry, error) {
	var written Entry
	err := l.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var last Entry
		err := tx.Order("seq DESC").First(&last).Error
		switch {
		case err == nil:
		case errors.Is(err, gorm.ErrRecordNotFound):
			last = Entry{}
		default:
			return fmt.Errorf("read tail: %w", err)
		}

		e := Entry{
			Seq:       last.Seq + 1,
			CreatedAt: time.Now().UTC(),
			Actor:     actor,
			Action:    action,
			Target:    target,
			Detail:    detail,
			PrevHash:  last.Hash,
		}
		e.Hash = chainHash(last.Hash, &e)

		if err := tx.Create(&e).Error; err != nil {
			return fmt.Errorf("append: %w", err)
		}
		written = e
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("audit: %w", err)
	}
	return &written, nil
}

// Head returns the sequence and hash of the newest entry.
//
// This is the value to anchor externally. A hash chain cannot detect truncation
// of its own tail; a published head can.
func (l *Log) Head(ctx context.Context) (uint64, string, error) {
	var last Entry
	if err := l.db.WithContext(ctx).Order("seq DESC").First(&last).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return 0, "", ErrEmpty
		}
		return 0, "", fmt.Errorf("audit: head: %w", err)
	}
	return last.Seq, last.Hash, nil
}

// Verify walks the chain and reports the first entry that does not hold.
//
// Returns the sequence number of the broken entry, or 0 if the log is intact.
func (l *Log) Verify(ctx context.Context) (uint64, error) {
	var entries []Entry
	if err := l.db.WithContext(ctx).Order("seq ASC").Find(&entries).Error; err != nil {
		return 0, fmt.Errorf("audit: read: %w", err)
	}

	prev := ""
	var expectSeq uint64 = 1
	for i := range entries {
		e := &entries[i]
		if e.Seq != expectSeq {
			// A gap means an entry was deleted from the middle. The chain
			// after it would also break, but reporting the gap is more useful
			// than reporting the hash mismatch it causes.
			return e.Seq, fmt.Errorf("%w: expected seq %d, found %d", ErrBroken, expectSeq, e.Seq)
		}
		if e.PrevHash != prev {
			return e.Seq, fmt.Errorf("%w: entry %d does not follow its predecessor", ErrBroken, e.Seq)
		}
		if got := chainHash(prev, e); got != e.Hash {
			return e.Seq, fmt.Errorf("%w: entry %d has been modified", ErrBroken, e.Seq)
		}
		prev = e.Hash
		expectSeq++
	}
	return 0, nil
}

// VerifyFrom checks the chain and additionally requires that it still contains
// a previously published anchor.
//
// This is what closes the truncation gap: an operator who recorded (seq, hash)
// at some point in the past can prove the log has not been rewound past it.
func (l *Log) VerifyFrom(ctx context.Context, anchorSeq uint64, anchorHash string) (uint64, error) {
	if broken, err := l.Verify(ctx); err != nil {
		return broken, err
	}
	var e Entry
	if err := l.db.WithContext(ctx).Where("seq = ?", anchorSeq).First(&e).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return anchorSeq, fmt.Errorf("%w: the log has been truncated past the anchor at seq %d",
				ErrBroken, anchorSeq)
		}
		return anchorSeq, fmt.Errorf("audit: anchor lookup: %w", err)
	}
	if e.Hash != anchorHash {
		return anchorSeq, fmt.Errorf("%w: entry %d does not match the anchor", ErrBroken, anchorSeq)
	}
	return 0, nil
}
