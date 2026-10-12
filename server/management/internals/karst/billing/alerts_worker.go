// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package billing

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/netbirdio/netbird/management/internals/karst/relayusage"
)

const relayAlertAccountPageSize = 128

type relayUsageReporter interface {
	Report(context.Context, string, time.Time, time.Time) (relayusage.Report, error)
}

// EvaluateCurrentRelayAlerts evaluates all explicitly scheduled accounts for
// the current UTC month. Missing schedules never create billing or alerts.
func (s *Store) EvaluateCurrentRelayAlerts(ctx context.Context, reporter relayUsageReporter, now time.Time) error {
	if reporter == nil || now.IsZero() {
		return ErrInvalidPeriod
	}
	now = now.UTC().Truncate(time.Microsecond)
	start := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	end := now.Truncate(time.Minute)
	if !start.Before(end) {
		return nil
	}
	periodEnd := start.AddDate(0, 1, 0)
	if end.After(periodEnd) {
		end = periodEnd
	}
	var failures []error
	after := ""
	for {
		accounts, err := s.AssignedAccountPage(ctx, start, periodEnd, after, relayAlertAccountPageSize)
		if err != nil {
			return errors.Join(append(failures, fmt.Errorf("billing: list accounts for relay alerts: %w", err))...)
		}
		if len(accounts) == 0 {
			break
		}
		for _, accountID := range accounts {
			accountCtx := WithAccount(ctx, accountID)
			var capMinor *int64
			cap, err := s.RelaySpendingCap(accountCtx, start, periodEnd)
			if err == nil {
				minor := cap.OverageMinor
				capMinor = &minor
			} else if !errors.Is(err, ErrRelayCapNotConfigured) {
				failures = append(failures, fmt.Errorf("billing: read relay cap for account %q: %w", accountID, err))
				continue
			}
			report, err := reporter.Report(ctx, accountID, start, end)
			if err != nil {
				failures = append(failures, fmt.Errorf("billing: read relay usage for account %q: %w", accountID, err))
				continue
			}
			if _, err := s.EvaluateAndRecordRelayAlerts(accountCtx, report, capMinor); err != nil {
				failures = append(failures, fmt.Errorf("billing: evaluate relay alerts for account %q: %w", accountID, err))
			}
		}
		after = accounts[len(accounts)-1]
		if len(accounts) < relayAlertAccountPageSize {
			break
		}
	}
	return errors.Join(failures...)
}

// RunRelayAlertWorker periodically refreshes persisted in-app threshold
// events. It does no work for accounts without an explicit schedule and never
// sends an email or puts alert processing on the networking path.
func RunRelayAlertWorker(ctx context.Context, store *Store, reporter relayUsageReporter, interval time.Duration, onError func(error)) {
	if ctx == nil || store == nil || reporter == nil || interval <= 0 {
		return
	}
	run := func() {
		workCtx, cancel := context.WithTimeout(ctx, interval)
		defer cancel()
		if err := store.EvaluateCurrentRelayAlerts(workCtx, reporter, time.Now().UTC()); err != nil && onError != nil {
			onError(err)
		}
	}
	run()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			run()
		}
	}
}
