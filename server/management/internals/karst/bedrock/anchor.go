// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// Anchoring the audit log into the Bedrock chain — spec/bedrock-v1.md §3.1,
// plan item 10.14.
//
// # What this fixes
//
// audit.go says it plainly: a hash chain "does not detect truncation of the
// tail. Delete the last k entries and the remaining chain still verifies
// perfectly, because nothing in it commits to how long it is meant to be."
// The stated mitigation is an external anchor, and "Bedrock's quorum signing is
// the intended home for that".
//
// An `anchor` entry carries an audit head — a sequence and its hash — into a
// log the server cannot rewrite. Truncation past that point then fails
// audit.Log.VerifyFrom, which already existed and had nothing authoritative to
// be pointed at.
//
// # The server cannot sign one, and that is not an oversight
//
// The plan asks for anchors "on a schedule". Only the *preparation* can be
// scheduled here. An anchor is an authority-signed entry, the server holds no
// authority key, and giving it one would hand it the ability to countersign
// nodes — which is the single thing Bedrock exists to deny it. There is no
// arrangement in which a compromised server both anchors automatically and
// cannot admit rogue nodes.
//
// So the server computes what should be anchored and prepares the entry; an
// authority signs it offline with `karst-bedrock sign`, exactly as for a
// node-sign. The cadence is therefore how often an admin runs the ceremony,
// and the honest framing is that anchoring is a periodic *operation* rather
// than a background task.
//
// A capability-scoped authority — one permitted to sign `anchor` and nothing
// else — would allow real automation, and would be a change to the
// authority-list body in §3.4. It is worth considering and is deliberately not
// done here; see FINDINGS 56.
package bedrock

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"
)

// AuditHead is the slice of audit.Log anchoring needs.
//
// An interface for the same reason the control package's dependencies are:
// bedrock must not acquire ownership of audit storage to read two fields from
// it.
type AuditHead interface {
	Head(ctx context.Context) (uint64, string, error)
	VerifyFrom(ctx context.Context, anchorSeq uint64, anchorHash string) (uint64, error)
}

// ErrNothingToAnchor is returned when the audit log has not moved since the
// last anchor, so a new one would commit to the same point.
var ErrNothingToAnchor = errors.New("bedrock: the audit log has not advanced since the last anchor")

// ErrNotAnchored is returned when a chain carries no anchor at all.
var ErrNotAnchored = errors.New("bedrock: the chain contains no audit anchor")

// PrepareAnchor builds the next anchor entry for an account and returns it with
// the hash an authority must sign.
//
// Nothing is written. The entry is committed only when a signature comes back,
// through the same import path as any other entry — so a prepared anchor that
// is never signed costs nothing and leaves no trace.
//
// The audit head's hash is carried as the bytes of its base64 presentation,
// which is what audit.Log.Head returns and what VerifyFrom compares. Converting
// it to raw digest bytes here would mean two representations of one value and a
// conversion on the verification path, which is where they would eventually
// disagree.
func (l *Log) PrepareAnchor(ctx context.Context, accountID string, audit AuditHead, at time.Time) (*Entry, []byte, error) {
	seq, hash, err := audit.Head(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("bedrock: audit head: %w", err)
	}

	entries, err := l.All(ctx, accountID)
	if err != nil {
		return nil, nil, err
	}
	if len(entries) == 0 {
		return nil, nil, ErrNoLog
	}
	state, err := VerifyLog(entries)
	if err != nil {
		return nil, nil, err
	}
	// Re-anchoring the same point adds an entry that says nothing new, and the
	// log is replicated to every node in the network — so "nothing changed" is
	// worth an error rather than a silent write.
	if state.Anchor != nil && state.Anchor.AuditSeq >= seq {
		return nil, nil, fmt.Errorf("%w: audit is at %d, already anchored at %d",
			ErrNothingToAnchor, seq, state.Anchor.AuditSeq)
	}

	builder, err := FromEntries(entries)
	if err != nil {
		return nil, nil, err
	}
	entry, input := builder.Prepare(at.UTC().Unix(), OpAnchor, AnchorBody([]byte(hash), seq))
	return entry, input, nil
}

// AnchorDue reports whether an account's audit log has advanced far enough, or
// long enough ago, to be worth anchoring again.
//
// Two conditions rather than one. A pure time interval anchors a quiet log
// repeatedly at the same point; a pure entry count never anchors a log that
// moves slowly, which is exactly the log whose truncation would be least
// noticed.
func AnchorDue(state *State, auditSeq uint64, lastAnchoredAt time.Time, now time.Time, minEntries uint64, maxAge time.Duration) bool {
	if state == nil {
		return false
	}
	if state.Anchor == nil {
		// Never anchored. Anything at all is worth committing to.
		return auditSeq > 0
	}
	advanced := auditSeq - state.Anchor.AuditSeq
	if auditSeq < state.Anchor.AuditSeq {
		// The audit log is *behind* the anchor, which means it has been
		// truncated. Anchoring again would paper over it; the caller wants
		// VerifyAnchored, which reports it.
		return false
	}
	if advanced == 0 {
		return false
	}
	return advanced >= minEntries || now.Sub(lastAnchoredAt) >= maxAge
}

// VerifyAnchored checks an audit log against the newest anchor in a verified
// chain.
//
// This is the payoff: audit.Log.VerifyFrom has always been able to prove the
// log has not been rewound past a given point, and until now there was nowhere
// trustworthy to keep that point. A server that truncates its own audit log now
// contradicts an entry signed by a key it does not hold.
//
// Returns the sequence of the first broken entry, or 0 when the log is intact
// and still contains the anchored entry.
func VerifyAnchored(ctx context.Context, state *State, audit AuditHead) (uint64, error) {
	if state == nil || state.Anchor == nil {
		return 0, ErrNotAnchored
	}
	broken, err := audit.VerifyFrom(ctx, state.Anchor.AuditSeq, string(state.Anchor.AuditHead))
	if err != nil {
		return broken, fmt.Errorf("bedrock: audit log does not match its anchor: %w", err)
	}
	return 0, nil
}

// LastAnchoredAt finds when the log's current anchor was written, by scanning
// for the `anchor` entry matching state.Anchor.
//
// Returns the zero Time and false when state has no anchor at all — the
// scheduler and the audit-status endpoint both handle that case earlier,
// through AnchorDue's own nil-anchor branch and the console's
// last_anchored_at == nil respectively, so neither needed a distinguishable
// zero value from this function specifically.
func LastAnchoredAt(entries []Entry, state *State) (time.Time, bool) {
	if state == nil || state.Anchor == nil {
		return time.Time{}, false
	}
	for _, e := range entries {
		if e.Op != OpAnchor {
			continue
		}
		a, err := ParseAnchor(e.Body)
		if err == nil && a.AuditSeq == state.Anchor.AuditSeq {
			return time.Unix(e.Time, 0).UTC(), true
		}
	}
	return time.Time{}, false
}

// AnchorMatches reports whether an anchor commits to exactly this audit head.
//
// Used by the console to show whether the anchor is current, which is a
// different question from whether the log verifies against it: an old anchor
// over an intact log is fine, and an anchor over a log that has since been
// truncated is not.
func AnchorMatches(state *State, seq uint64, hash string) bool {
	if state == nil || state.Anchor == nil {
		return false
	}
	return state.Anchor.AuditSeq == seq && bytes.Equal(state.Anchor.AuditHead, []byte(hash))
}
