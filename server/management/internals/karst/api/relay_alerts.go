// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/management/internals/karst/billing"
	"github.com/netbirdio/netbird/management/internals/karst/relayusage"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

type relayAlertBillingStore interface {
	EvaluateAndRecordRelayAlerts(context.Context, relayusage.Report, *int64) ([]billing.RelayAlertCandidate, error)
	RelayAlerts(context.Context, time.Time, time.Time) ([]billing.RelayAlertCandidate, error)
	RelaySpendingCap(context.Context, time.Time, time.Time) (billing.RelaySpendingCap, error)
}

type relayAlertUsageReporter interface {
	Report(context.Context, string, time.Time, time.Time) (relayusage.Report, error)
}

type relayAlertFeed struct {
	PeriodStart      time.Time                     `json:"period_start"`
	PeriodEnd        time.Time                     `json:"period_end"`
	AsOf             time.Time                     `json:"as_of"`
	CoverageComplete bool                          `json:"coverage_complete"`
	CoverageWarning  string                        `json:"coverage_warning,omitempty"`
	Alerts           []billing.RelayAlertCandidate `json:"alerts"`
}

// RegisterRelayAlertEndpoints exposes the persisted in-app alert feed to
// account owners and administrators. Reading the
// current period reevaluates authorized usage and records any new threshold
// crossings before returning the account-scoped feed.
func RegisterRelayAlertEndpoints(router *mux.Router, manager permissions.Manager, usageStore relayAlertUsageReporter, billingStore relayAlertBillingStore, log auditReader) {
	routes := router.PathPrefix("/karst/v1/usage/relay-alerts").Subrouter()
	routes.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			if manager == nil {
				util.WriteError(r.Context(), status.Errorf(status.PermissionDenied, "billing alert authorization is not configured"), w)
				return
			}
			karstAuthorization(manager)(next).ServeHTTP(w, r)
		})
	})
	routes.HandleFunc("", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "method must be GET"), w)
			return
		}
		user, err := nbcontext.GetUserAuthFromContext(r.Context())
		if err != nil {
			util.WriteError(r.Context(), err, w)
			return
		}
		role, ok := nbcontext.RoleFromContext(r.Context())
		if !ok || (types.UserRole(role) != types.UserRoleOwner && types.UserRole(role) != types.UserRoleAdmin) {
			util.WriteError(r.Context(), status.Errorf(status.PermissionDenied, "billing alerts require an account owner or administrator"), w)
			return
		}
		if usageStore == nil || billingStore == nil || log == nil {
			util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "billing alerts or audit storage are not configured"), w)
			return
		}
		query := r.URL.Query()
		periods := query["period"]
		if len(periods) != 1 || query.Encode() != "period="+periods[0] {
			util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "period must be one YYYY-MM UTC calendar month"), w)
			return
		}
		start, err := time.Parse("2006-01", periods[0])
		if err != nil || start.Format("2006-01") != periods[0] {
			util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "period must be one YYYY-MM UTC calendar month"), w)
			return
		}
		start = start.UTC()
		end := start.AddDate(0, 1, 0)
		now := time.Now().UTC().Truncate(time.Microsecond)
		currentMonth := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
		if start.After(currentMonth) {
			util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "period must be a past or current UTC calendar month"), w)
			return
		}
		if end.After(now) {
			end = now.Truncate(time.Minute)
		}
		feed := relayAlertFeed{PeriodStart: start, PeriodEnd: start.AddDate(0, 1, 0), AsOf: now, Alerts: []billing.RelayAlertCandidate{}}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		accountCtx := billing.WithAccount(ctx, user.AccountId)
		if end.After(start) {
			var capMinor *int64
			cap, capErr := billingStore.RelaySpendingCap(accountCtx, start, start.AddDate(0, 1, 0))
			if capErr == nil {
				minor := cap.OverageMinor
				capMinor = &minor
			} else if !errors.Is(capErr, billing.ErrRelayCapNotConfigured) {
				util.WriteError(ctx, status.Errorf(status.Internal, "could not read relay spending cap"), w)
				return
			}
			report, err := usageStore.Report(ctx, user.AccountId, start, end)
			if err != nil {
				switch {
				case errors.Is(err, relayusage.ErrInvalidReport):
					err = status.Errorf(status.InvalidArgument, "period must be a past or current UTC calendar month")
				case errors.Is(err, relayusage.ErrReportLimit):
					err = status.Errorf(status.InvalidArgument, "relay usage report exceeds the supported window")
				default:
					err = status.Errorf(status.Internal, "could not read relay usage report")
				}
				util.WriteError(ctx, err, w)
				return
			}
			feed.AsOf = report.AsOf
			feed.CoverageComplete = report.Complete && report.Coverage == "authorized_producers"
			if !feed.CoverageComplete {
				feed.CoverageWarning = "Relay usage coverage is incomplete; threshold amounts are lower bounds."
			}
			if _, err := billingStore.EvaluateAndRecordRelayAlerts(accountCtx, report, capMinor); err != nil {
				if errors.Is(err, billing.ErrScheduleUnassigned) {
					err = status.Errorf(status.PreconditionFailed, "no billing schedule is assigned for this period")
				} else {
					err = status.Errorf(status.Internal, "could not evaluate relay billing alerts")
				}
				util.WriteError(ctx, err, w)
				return
			}
			alerts, err := billingStore.RelayAlerts(accountCtx, start, start.AddDate(0, 1, 0))
			if err != nil {
				util.WriteError(ctx, status.Errorf(status.Internal, "could not read relay billing alerts"), w)
				return
			}
			feed.Alerts = alerts
		} else {
			feed.CoverageWarning = "Relay usage coverage is not yet available."
		}
		if _, err := log.Append(ctx, user.UserId, "karst.billing.relay_alerts.view", "billing/relay-alerts", periods[0]); err != nil {
			util.WriteError(ctx, status.Errorf(status.Internal, "could not audit relay billing alert access"), w)
			return
		}
		util.WriteJSONObject(ctx, w, feed)
	}).Methods(http.MethodGet, http.MethodOptions)
}
