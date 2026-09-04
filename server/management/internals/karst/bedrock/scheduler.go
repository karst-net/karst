// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// The anchor scheduler — ADR-0016, and spec/bedrock-v1.md §9's "automatic
// anchoring policy" bullet, which this closes.
//
// # AnchorDue's first production caller
//
// anchor.go's package comment explains why the server could not anchor on a
// schedule before this ADR: the authority list was flat, and a key able to
// sign `anchor` on a timer could also countersign nodes. The anchor tier —
// scoped by context string to `anchor` and nothing else — is what makes
// holding a key here safe. This file is the job that uses it.
//
// # What this cannot do
//
// A key loaded here is only ever an AnchorKey. There is no path from this
// file to a RootKey or an AuthorityKey, and PrepareAnchor still recomputes
// the entry from the verified chain rather than trusting anything cached —
// the same discipline the offline signer applies to a bundle it did not build
// itself. A compromised process running this scheduler can commit to a
// history it fabricated after the last anchor and nothing more; see
// ADR-0016's "why this is safe to automate".
package bedrock

import (
	"bytes"
	"context"
	"errors"
	"time"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel"
	otelcodes "go.opentelemetry.io/otel/codes"
	oteltrace "go.opentelemetry.io/otel/trace"

	"github.com/netbirdio/netbird/management/server/telemetry"
)

// tracer names every span this package creates — plans/phase-6
// /08-observability.md §3.4 item 2. See control/service.go's own tracer var
// for why this reads from the global TracerProvider rather than a field on
// Scheduler.
var tracer = otel.Tracer("github.com/netbirdio/netbird/management/internals/karst/bedrock")

// endSpan closes span, marking it as failed when err is non-nil. Duplicated
// from control/service.go's identical helper rather than shared: two
// three-line copies in two packages that otherwise have nothing to do with
// each other is cheaper than a new package built to hold one function.
func endSpan(span oteltrace.Span, err error) {
	if err != nil {
		span.RecordError(err)
		span.SetStatus(otelcodes.Error, err.Error())
	}
	span.End()
}

// Scheduler periodically anchors one account's audit log with a locally held
// AnchorKey, when AnchorDue says it is time.
//
// One account, not every account with Bedrock enabled: Karst's server-side
// account model is single-tenant per deployment in the intended use (PLAN.md
// §0), and a scheduler wired to a specific accountID is the honest shape of
// that rather than a multi-account loop nothing self-hosted needs yet.
type Scheduler struct {
	Log       *Log
	Audit     AuditHead
	AccountID string
	Key       *AnchorKey

	// MinEntries and MaxAge are AnchorDue's two thresholds — see its doc
	// comment for why anchoring needs both rather than either alone.
	MinEntries uint64
	MaxAge     time.Duration

	// Metrics is optional (nil is a valid, no-op value) and drives
	// management.karst.bedrock.anchor.age.seconds. Set from the same
	// *telemetry.KarstMetrics instance as Log.Metrics — see main.go's
	// startBedrockAnchorScheduler.
	Metrics *telemetry.KarstMetrics

	// loggedNotEnabled suppresses repeating the same informational line every
	// tick while an operator's key waits for the root ceremony that adds it
	// to the chain's anchor list — an expected steady state, not a fault.
	loggedNotEnabled bool
}

// Run ticks until ctx is canceled, anchoring when due. It makes one immediate
// pass at startup for the same reason audit.Log.StartDeliveryWorker does: a
// restart should not wait a full interval to notice a log that is already
// overdue.
func (s *Scheduler) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	tick := func() {
		if err := s.Tick(ctx, time.Now().UTC()); err != nil && ctx.Err() == nil {
			log.WithContext(ctx).Errorf("karst: bedrock anchor scheduler: %v", err)
		}
	}
	tick()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			tick()
		}
	}
}

// Tick runs one pass: verify the chain, decide whether an anchor is due, and
// if so prepare, sign, and commit one.
//
// No Bedrock chain yet, a key not yet in the account's anchor list, and an
// anchor that is not due are all expected, quiet outcomes — this returns nil
// for each, the same way a cron job that finds nothing to do is not a
// failure. The audit log erroring (most commonly: no entries have ever been
// written) is logged and swallowed rather than returned, for the same
// reason: there is nothing this scheduler can do about it besides wait for
// the next tick, and it is the ordinary state of a brand new deployment.
func (s *Scheduler) Tick(ctx context.Context, now time.Time) error {
	ctx, cycleSpan := tracer.Start(ctx, "karst.bedrock.anchor_cycle")
	var tickErr error
	defer func() { endSpan(cycleSpan, tickErr) }()

	entries, err := s.Log.All(ctx, s.AccountID)
	if err != nil {
		tickErr = err
		return err
	}
	if len(entries) == 0 {
		return nil
	}
	state, err := VerifyLog(entries)
	if err != nil {
		tickErr = err
		return err
	}

	signerIndex, enabled := anchorSignerIndex(state, s.Key.Public())
	if !enabled {
		if !s.loggedNotEnabled {
			log.WithContext(ctx).Infof("karst: bedrock anchor scheduler: this key is not in %s's "+
				"anchor list yet; waiting for a root ceremony to enable it", s.AccountID)
			s.loggedNotEnabled = true
		}
		return nil
	}
	s.loggedNotEnabled = false

	auditSeq, _, err := s.Audit.Head(ctx)
	if err != nil {
		log.WithContext(ctx).Debugf("karst: bedrock anchor scheduler: audit head: %v", err)
		return nil
	}
	lastAnchoredAt, hasAnchored := LastAnchoredAt(entries, state)
	if hasAnchored {
		s.Metrics.SetBedrockLastAnchoredAt(s.AccountID, lastAnchoredAt)
	}
	_, dueSpan := tracer.Start(ctx, "karst.bedrock.anchor_cycle.anchor_due")
	due := AnchorDue(state, auditSeq, lastAnchoredAt, now, s.MinEntries, s.MaxAge)
	dueSpan.End()
	if !due {
		return nil
	}

	prepareCtx, prepareSpan := tracer.Start(ctx, "karst.bedrock.anchor_cycle.prepare_anchor")
	entry, input, err := s.Log.PrepareAnchor(prepareCtx, s.AccountID, s.Audit, now)
	if err != nil && !errors.Is(err, ErrNothingToAnchor) {
		tickErr = err
	}
	endSpan(prepareSpan, tickErr)
	if err != nil {
		if errors.Is(err, ErrNothingToAnchor) {
			// Something else anchored between the AnchorDue check above and
			// here — a race with a manual offline ceremony, not a failure.
			return nil
		}
		return err
	}

	_, signSpan := tracer.Start(ctx, "karst.bedrock.anchor_cycle.sign")
	sig, err := s.Key.Sign(input)
	signSpan.End()
	if err != nil {
		tickErr = err
		return err
	}
	entry.Sigs = []Signature{{SignerIndex: signerIndex, Sig: sig}}

	extended := append(append([]Entry(nil), entries...), *entry)
	importCtx, importSpan := tracer.Start(ctx, "karst.bedrock.anchor_cycle.import")
	err = s.Log.Import(importCtx, s.AccountID, extended)
	endSpan(importSpan, err)
	if err != nil {
		tickErr = err
		return err
	}
	log.WithContext(ctx).Infof("karst: bedrock anchor scheduler: anchored %s's audit log at seq %d",
		s.AccountID, auditSeq)
	return nil
}

// anchorSignerIndex finds this key's index in the concatenated signer space
// spec §3.5 defines for `anchor`: the authority list first, then the anchor
// list at an offset of len(state.Authorities) — the same arithmetic
// verifySignatures applies on the reading side.
func anchorSignerIndex(state *State, public []byte) (uint32, bool) {
	for i, k := range state.AnchorKeys {
		if bytes.Equal(k, public) {
			// len(state.Authorities)+i never exceeds maxSigners (64): both
			// lists are bounded there at verification (validateAnchorKeys).
			return uint32(len(state.Authorities) + i), true
		}
	}
	return 0, false
}
