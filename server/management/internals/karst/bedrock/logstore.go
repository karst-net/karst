// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// Server-side persistence for the Bedrock log — spec/bedrock-v1.md §5.
//
// # The server is a cache of the log, not its author
//
// Every write here verifies the whole extended chain before committing, and
// every read that produces state verifies again. That is more work than
// strictly necessary and it is the point: the server holds no key that can
// sign an entry, so the only thing it can contribute is corruption, and the
// only defence against corruption it can offer is to refuse to store anything
// that does not verify.
//
// A node never trusts this store either — it re-verifies everything it is sent
// (§4). What verifying here buys is that a broken log is refused at the moment
// an operator imports it, with a legible error, rather than propagating to
// every node in the network and being refused there.
package bedrock

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"
)

// MaxEntriesPerResponse bounds one KarstBedrockResponse.
//
// A genesis entry with three root signatures is roughly 50 KB, so a naive
// "send everything" reply to a node with an empty log would be megabytes on a
// control channel sized for netmaps. Nodes fetch forward from their last
// verified sequence, so a bounded reply costs an extra round trip and nothing
// else.
const MaxEntriesPerResponse = 32

// LogEntry is one stored entry.
//
// Encoded is the §3.6 serialisation, kept verbatim. The parsed fields beside it
// exist for indexing and for the console; they are derived from Encoded and are
// never the thing that is verified or served. If the two could disagree,
// Encoded is right — it is what the signatures cover.
type LogEntry struct {
	AccountID string `gorm:"primaryKey;size:64"`
	Seq       uint64 `gorm:"primaryKey;autoIncrement:false"`
	Encoded   []byte `gorm:"not null"`
	Op        string `gorm:"index"`
	Hash      []byte
	EntryTime int64
	CreatedAt time.Time
}

func (LogEntry) TableName() string { return "karst_bedrock_log" }

// PendingSigningRequest is the server's durable half of the offline ceremony.
// It contains prepared, unsigned entries only; no authority private material
// ever reaches this table. One request per account prevents a response bundle
// from being applied to a different history while an operator has it offline.
type PendingSigningRequest struct {
	AccountID   string `gorm:"primaryKey;size:64"`
	ID          string `gorm:"uniqueIndex;size:80"`
	Entries     []byte `gorm:"not null"`
	PayloadHash string `gorm:"not null;size:64"`
	CreatedAt   time.Time
}

func (PendingSigningRequest) TableName() string { return "karst_bedrock_pending_requests" }

var (
	// ErrNoLog is returned when an account has no Bedrock log at all.
	ErrNoLog = errors.New("bedrock: no log for this account")
	// ErrNotExtension is returned when an import would rewrite history rather
	// than extend it.
	ErrNotExtension = errors.New("bedrock: entries do not extend the stored log")
)

// MigrateLog adds the log table. Separate from NewStore so that a deployment
// with no Bedrock configuration still gets the table and can be seeded later.
func MigrateLog(db *gorm.DB) error {
	if db == nil {
		return errors.New("bedrock: nil database")
	}
	if err := db.AutoMigrate(&LogEntry{}, &PendingSigningRequest{}); err != nil {
		return fmt.Errorf("bedrock: migrate log: %w", err)
	}
	return nil
}

// Pending returns the sole outstanding request for an account.
func (l *Log) Pending(ctx context.Context, accountID string) (*PendingSigningRequest, error) {
	var request PendingSigningRequest
	if err := l.db.WithContext(ctx).Where("account_id = ?", accountID).First(&request).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("bedrock: read pending request: %w", err)
	}
	return &request, nil
}

// CreatePending persists entries prepared against the current verified log.
// Repeated calls return the existing request: an administrator may export a
// bundle again, but must never receive two competing next entries.
func (l *Log) CreatePending(ctx context.Context, accountID string, entries []Entry) (*PendingSigningRequest, error) {
	if len(entries) == 0 {
		return nil, errors.New("bedrock: no entries to request")
	}
	if existing, err := l.Pending(ctx, accountID); err != nil || existing != nil {
		return existing, err
	}
	stored, err := l.All(ctx, accountID)
	if err != nil {
		return nil, err
	}
	if len(stored) == 0 {
		return nil, ErrNoLog
	}
	state, err := VerifyLog(stored)
	if err != nil {
		return nil, err
	}
	for index := range entries {
		if entries[index].Seq != state.HeadSeq+uint64(index)+1 || len(entries[index].Sigs) != 0 {
			return nil, errors.New("bedrock: pending entries do not extend the verified log")
		}
	}
	encoded := EncodeLog(entries)
	digest := sha256.Sum256(encoded)
	request := &PendingSigningRequest{
		AccountID: accountID,
		ID:        "request-" + hex.EncodeToString(digest[:16]),
		Entries:   encoded, PayloadHash: hex.EncodeToString(digest[:]), CreatedAt: time.Now().UTC(),
	}
	if err := l.db.WithContext(ctx).Create(request).Error; err != nil {
		return nil, fmt.Errorf("bedrock: create pending request: %w", err)
	}
	return request, nil
}

// CommitPending verifies a response against the one durable request, appends
// its entries through Import, then removes the request. Import is idempotent,
// so a crash between those two operations is safe to retry.
func (l *Log) CommitPending(ctx context.Context, accountID string, signatures map[uint64][]Signature) error {
	request, err := l.Pending(ctx, accountID)
	if err != nil {
		return err
	}
	if request == nil {
		return errors.New("bedrock: no pending signing request")
	}
	entries, err := DecodeLog(request.Entries)
	if err != nil {
		return fmt.Errorf("bedrock: decode pending request: %w", err)
	}
	for i := range entries {
		entries[i].Sigs = signatures[entries[i].Seq]
		if len(entries[i].Sigs) == 0 {
			return fmt.Errorf("bedrock: response has no signature for entry %d", entries[i].Seq)
		}
	}
	for seq := range signatures {
		found := false
		for _, entry := range entries {
			if entry.Seq == seq {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("bedrock: response signs unrequested entry %d", seq)
		}
	}
	if err := l.Import(ctx, accountID, entries); err != nil {
		return err
	}
	if err := l.db.WithContext(ctx).Where("account_id = ?", accountID).Delete(&PendingSigningRequest{}).Error; err != nil {
		return fmt.Errorf("bedrock: remove committed request: %w", err)
	}
	return nil
}

// Log is the server's copy of one account's Bedrock chain.
type Log struct{ db *gorm.DB }

// NewLog returns a log over db, migrating the table.
func NewLog(db *gorm.DB) (*Log, error) {
	if err := MigrateLog(db); err != nil {
		return nil, err
	}
	return &Log{db: db}, nil
}

// Entries returns stored entries strictly after sinceSeq, in order, capped at
// limit.
func (l *Log) Entries(ctx context.Context, accountID string, sinceSeq uint64, limit int) ([]Entry, error) {
	if limit <= 0 || limit > MaxEntriesPerResponse {
		limit = MaxEntriesPerResponse
	}
	var rows []LogEntry
	if err := l.db.WithContext(ctx).
		Where("account_id = ? AND seq > ?", accountID, sinceSeq).
		Order("seq ASC").Limit(limit).Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("bedrock: read log: %w", err)
	}
	return decodeRows(rows)
}

// All returns the whole stored log for an account.
func (l *Log) All(ctx context.Context, accountID string) ([]Entry, error) {
	var rows []LogEntry
	if err := l.db.WithContext(ctx).
		Where("account_id = ?", accountID).Order("seq ASC").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("bedrock: read log: %w", err)
	}
	return decodeRows(rows)
}

// Head returns the stored tip's hash and sequence.
//
// Returns ErrNoLog when the account has none, which is a normal state and not
// an error condition: most accounts never turn Bedrock on.
func (l *Log) Head(ctx context.Context, accountID string) ([]byte, uint64, error) {
	var row LogEntry
	if err := l.db.WithContext(ctx).
		Where("account_id = ?", accountID).Order("seq DESC").First(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, 0, ErrNoLog
		}
		return nil, 0, fmt.Errorf("bedrock: head: %w", err)
	}
	return row.Hash, row.Seq, nil
}

// State verifies the stored log and returns the state it establishes.
//
// Verified on every call rather than cached. The log is small by construction —
// one entry per enrolment plus revocations — and a cached State is a thing that
// can be stale at exactly the moment a revocation matters.
func (l *Log) State(ctx context.Context, accountID string) (*State, error) {
	entries, err := l.All(ctx, accountID)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, ErrNoLog
	}
	return VerifyLog(entries)
}

// Import appends entries to an account's log.
//
// The entries must extend what is stored: the combined chain is verified in
// full before anything is written, and a set that would fork or rewrite history
// is refused. This is the only write path, and it is deliberately the slow one.
func (l *Log) Import(ctx context.Context, accountID string, entries []Entry) error {
	if len(entries) == 0 {
		return errors.New("bedrock: nothing to import")
	}
	return l.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var stored []LogEntry
		if err := tx.Where("account_id = ?", accountID).Order("seq ASC").Find(&stored).Error; err != nil {
			return fmt.Errorf("read stored log: %w", err)
		}
		existing, err := decodeRows(stored)
		if err != nil {
			return err
		}

		// Entries at or below the stored head must be byte-identical to what is
		// already there. An import that "corrects" history is a rewrite, and a
		// rewrite is exactly what the chain exists to make impossible.
		combined := make([]Entry, len(existing))
		copy(combined, existing)
		for _, e := range entries {
			switch {
			case e.Seq <= uint64(len(existing)):
				have := existing[e.Seq-1]
				if !equalEntry(have, e) {
					return fmt.Errorf("%w: entry %d differs from the stored one", ErrNotExtension, e.Seq)
				}
			case e.Seq == uint64(len(combined))+1:
				combined = append(combined, e)
			default:
				return fmt.Errorf("%w: entry %d leaves a gap after %d", ErrNotExtension, e.Seq, len(combined))
			}
		}

		// The whole chain, every time. Verifying only the new tail would accept
		// a valid extension of a stored log that had itself been corrupted.
		// VerifyLog also fills in each entry's Hash, which is what gets indexed.
		if _, err := VerifyLog(combined); err != nil {
			return err
		}

		for i := len(existing); i < len(combined); i++ {
			e := combined[i]
			row := LogEntry{
				AccountID: accountID,
				Seq:       e.Seq,
				Encoded:   e.Encode(),
				Op:        string(e.Op),
				Hash:      e.Hash,
				EntryTime: e.Time,
				CreatedAt: time.Now().UTC(),
			}
			if err := tx.Create(&row).Error; err != nil {
				return fmt.Errorf("store entry %d: %w", e.Seq, err)
			}
		}
		return nil
	})
}

func decodeRows(rows []LogEntry) ([]Entry, error) {
	out := make([]Entry, 0, len(rows))
	for _, row := range rows {
		e, err := decodeEntry(row.Encoded)
		if err != nil {
			return nil, fmt.Errorf("bedrock: stored entry %d: %w", row.Seq, err)
		}
		out = append(out, e)
	}
	return out, nil
}

// equalEntry compares by encoding, which is the only comparison that matters:
// two entries are the same entry when the bytes the signatures cover are the
// same bytes.
func equalEntry(a, b Entry) bool {
	return string(a.Encode()) == string(b.Encode())
}
