// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"time"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/management/internals/karst/billing"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/auth"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

type estavelleCapBillingStore interface {
	SetEstavelleSpendingCap(context.Context, time.Time, time.Time, int64, bool, string) (billing.EstavelleSpendingCap, error)
	EstavelleSpendingCap(context.Context, time.Time, time.Time) (billing.EstavelleSpendingCap, error)
}

type estavelleCapRequest struct {
	Period                  string `json:"period"`
	OverageLimitMinor       int64  `json:"overage_limit_minor"`
	AcknowledgeInterruption bool   `json:"acknowledge_interruption"`
}

type estavelleCapResponse struct {
	Enabled           bool       `json:"enabled"`
	PeriodStart       time.Time  `json:"period_start"`
	PeriodEnd         time.Time  `json:"period_end"`
	Currency          string     `json:"currency"`
	OverageLimitMinor *int64     `json:"overage_limit_minor,omitempty"`
	Acknowledged      bool       `json:"acknowledged_interruption"`
	EffectiveAt       *time.Time `json:"effective_at,omitempty"`
}

// RegisterEstavelleCapEndpoints exposes optional organization-wide managed estavelle
// caps to account owners and administrators. The estavelle identity endpoint stays
// separate and does not use customer session auth.
func RegisterEstavelleCapEndpoints(router *mux.Router, manager permissions.Manager, billingStore estavelleCapBillingStore, log auditReader) {
	routes := router.PathPrefix("/karst/v1/billing/estavelle-cap").Subrouter()
	routes.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			if manager == nil {
				util.WriteError(r.Context(), status.Errorf(status.PermissionDenied, "billing cap authorization is not configured"), w)
				return
			}
			karstAuthorization(manager)(next).ServeHTTP(w, r)
		})
	})
	routes.HandleFunc("", func(w http.ResponseWriter, r *http.Request) {
		user, err := estavelleCapUser(r)
		if err != nil {
			util.WriteError(r.Context(), err, w)
			return
		}
		if billingStore == nil || log == nil {
			util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "billing cap or audit storage is not configured"), w)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		accountCtx := billing.WithAccount(ctx, user.AccountId)

		switch r.Method {
		case http.MethodGet:
			periods := r.URL.Query()["period"]
			if len(periods) != 1 || r.URL.Query().Encode() != "period="+periods[0] {
				util.WriteError(ctx, status.Errorf(status.InvalidArgument, "period must be one YYYY-MM UTC calendar month"), w)
				return
			}
			start, end, ok := estavelleCapPeriod(periods[0])
			if !ok {
				util.WriteError(ctx, status.Errorf(status.InvalidArgument, "period must be one YYYY-MM UTC calendar month"), w)
				return
			}
			cap, err := billingStore.EstavelleSpendingCap(accountCtx, start, end)
			if errors.Is(err, billing.ErrEstavelleCapNotConfigured) {
				if _, auditErr := log.Append(ctx, user.UserId, "karst.billing.estavelle_cap.view", "billing/estavelle-cap", periods[0]); auditErr != nil {
					util.WriteError(ctx, status.Errorf(status.Internal, "could not audit estavelle cap access"), w)
					return
				}
				util.WriteJSONObject(ctx, w, estavelleCapResponse{PeriodStart: start, PeriodEnd: end, Currency: "USD"})
				return
			}
			if err != nil {
				util.WriteError(ctx, status.Errorf(status.Internal, "could not read estavelle cap"), w)
				return
			}
			if _, err := log.Append(ctx, user.UserId, "karst.billing.estavelle_cap.view", "billing/estavelle-cap", periods[0]); err != nil {
				util.WriteError(ctx, status.Errorf(status.Internal, "could not audit estavelle cap access"), w)
				return
			}
			minor := cap.OverageMinor
			effective := cap.EffectiveAt
			util.WriteJSONObject(ctx, w, estavelleCapResponse{Enabled: true, PeriodStart: start, PeriodEnd: end,
				Currency: cap.Currency, OverageLimitMinor: &minor, Acknowledged: cap.Acknowledged, EffectiveAt: &effective})
		case http.MethodPut:
			if r.URL.RawQuery != "" {
				util.WriteError(ctx, status.Errorf(status.InvalidArgument, "cap settings do not accept query parameters"), w)
				return
			}
			request, err := parseEstavelleCapRequest(w, r)
			if err != nil {
				util.WriteError(ctx, status.Errorf(status.InvalidArgument, "invalid estavelle cap request"), w)
				return
			}
			start, end, ok := estavelleCapPeriod(request.Period)
			if !ok || start.Before(currentEstavelleCapMonth(time.Now().UTC())) || request.OverageLimitMinor < 0 {
				util.WriteError(ctx, status.Errorf(status.InvalidArgument, "period must be a current or future UTC month and limit must be nonnegative"), w)
				return
			}
			if !request.AcknowledgeInterruption {
				util.WriteError(ctx, status.Errorf(status.InvalidArgument, "acknowledge_interruption must be true"), w)
				return
			}
			cap, err := billingStore.SetEstavelleSpendingCap(accountCtx, start, end,
				request.OverageLimitMinor, request.AcknowledgeInterruption, user.UserId)
			if err != nil {
				switch {
				case errors.Is(err, billing.ErrScheduleUnassigned):
					err = status.Errorf(status.PreconditionFailed, "no billing schedule is assigned for this period")
				case errors.Is(err, billing.ErrEstavelleCapDecrease):
					err = status.Errorf(status.PreconditionFailed, "a current-period decrease is blocked while estavelle credits remain reserved; it may be unavailable until the next period")
				case errors.Is(err, billing.ErrInvalidPeriod), errors.Is(err, billing.ErrInvalidRateSchedule):
					err = status.Errorf(status.InvalidArgument, "estavelle cap settings are invalid for this billing schedule")
				default:
					err = status.Errorf(status.Internal, "could not save estavelle cap")
				}
				util.WriteError(ctx, err, w)
				return
			}
			if _, err := log.Append(ctx, user.UserId, "karst.billing.estavelle_cap.set", "billing/estavelle-cap", request.Period); err != nil {
				util.WriteError(ctx, status.Errorf(status.Internal, "could not audit estavelle cap update"), w)
				return
			}
			minor := cap.OverageMinor
			effective := cap.EffectiveAt
			util.WriteJSONObject(ctx, w, estavelleCapResponse{Enabled: true, PeriodStart: start, PeriodEnd: end,
				Currency: cap.Currency, OverageLimitMinor: &minor, Acknowledged: cap.Acknowledged, EffectiveAt: &effective})
		default:
			w.Header().Set("Allow", "GET, PUT")
			util.WriteError(ctx, status.Errorf(status.InvalidArgument, "method must be GET or PUT"), w)
		}
	}).Methods(http.MethodGet, http.MethodPut, http.MethodOptions)
}

func estavelleCapUser(r *http.Request) (auth.UserAuth, error) {
	user, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		return auth.UserAuth{}, err
	}
	role, ok := nbcontext.RoleFromContext(r.Context())
	if !ok || (types.UserRole(role) != types.UserRoleOwner && types.UserRole(role) != types.UserRoleAdmin) {
		return auth.UserAuth{}, status.Errorf(status.PermissionDenied, "estavelle spending caps require an account owner or administrator")
	}
	return user, nil
}

func parseEstavelleCapRequest(w http.ResponseWriter, r *http.Request) (estavelleCapRequest, error) {
	var request estavelleCapRequest
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return request, errors.New("content type must be application/json")
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return request, err
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return request, errors.New("request must contain one JSON object")
	}
	return request, nil
}

func estavelleCapPeriod(value string) (time.Time, time.Time, bool) {
	start, err := time.Parse("2006-01", value)
	if err != nil || start.Format("2006-01") != value {
		return time.Time{}, time.Time{}, false
	}
	start = start.UTC()
	return start, start.AddDate(0, 1, 0), true
}

func currentEstavelleCapMonth(now time.Time) time.Time {
	return time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
}
