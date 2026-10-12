// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/management/internals/karst/relayusage"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

type relayUsageReporter interface {
	Report(context.Context, string, time.Time, time.Time) (relayusage.Report, error)
}

// RegisterRelayUsageEndpoints mounts the customer relay report before the
// broad /karst/v1 router. Scope always comes from the authenticated account.
func RegisterRelayUsageEndpoints(router *mux.Router, manager permissions.Manager, reporter relayUsageReporter, log auditReader) {
	routes := router.PathPrefix("/karst/v1/usage").Subrouter()
	routes.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			if manager == nil {
				util.WriteError(r.Context(), status.Errorf(status.PermissionDenied, "usage authorization is not configured"), w)
				return
			}
			karstAuthorization(manager)(next).ServeHTTP(w, r)
		})
	})
	routes.HandleFunc("/relays", func(w http.ResponseWriter, r *http.Request) {
		user, err := nbcontext.GetUserAuthFromContext(r.Context())
		if err != nil {
			util.WriteError(r.Context(), err, w)
			return
		}
		role, ok := nbcontext.RoleFromContext(r.Context())
		if !ok || (types.UserRole(role) != types.UserRoleOwner && types.UserRole(role) != types.UserRoleAdmin) {
			util.WriteError(r.Context(), status.Errorf(status.PermissionDenied, "usage reports require an account owner or administrator"), w)
			return
		}
		if reporter == nil || log == nil {
			util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "relay usage reporting or audit storage is not configured"), w)
			return
		}
		query := r.URL.Query()
		start, startErr := time.Parse(time.RFC3339Nano, query.Get("start"))
		end, endErr := time.Parse(time.RFC3339Nano, query.Get("end"))
		if startErr != nil || endErr != nil || len(query["start"]) != 1 || len(query["end"]) != 1 {
			util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "start and end must each be one RFC3339 timestamp"), w)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		report, err := reporter.Report(ctx, user.AccountId, start, end)
		if err != nil {
			switch {
			case errors.Is(err, relayusage.ErrInvalidReport):
				err = status.Errorf(status.InvalidArgument, "request a past, nonempty window of at most 93 days aligned to whole minutes")
			case errors.Is(err, relayusage.ErrReportLimit):
				err = status.Errorf(status.InvalidArgument, "too many relay usage records; request a shorter window")
			default:
				err = status.Errorf(status.Internal, "could not read relay usage report")
			}
			util.WriteError(ctx, err, w)
			return
		}
		if _, err := log.Append(ctx, user.UserId, "karst.usage.relays.view", "usage/relays", ""); err != nil {
			util.WriteError(ctx, status.Errorf(status.Internal, "could not audit relay usage report"), w)
			return
		}
		util.WriteJSONObject(ctx, w, report)
	}).Methods(http.MethodGet, http.MethodOptions)
}
