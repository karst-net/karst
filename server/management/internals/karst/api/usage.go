// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/management/internals/karst/usage"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

type deviceUsageReporter interface {
	Devices(context.Context, string, time.Time, time.Time) (usage.DeviceReport, error)
}

// RegisterUsageEndpoints must precede RegisterEndpoints' broad /karst/v1 route.
// The outer router supplies session authentication and account-override checks.
// Account ID always comes from that authenticated context, never query input.
func RegisterUsageEndpoints(router *mux.Router, manager permissions.Manager, reporter deviceUsageReporter, log auditReader) {
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
	routes.HandleFunc("/devices", func(w http.ResponseWriter, r *http.Request) {
		user, err := nbcontext.GetUserAuthFromContext(r.Context())
		if err != nil {
			util.WriteError(r.Context(), err, w)
			return
		}
		// NOC/network roles can read operational telemetry; financial usage
		// is initially restricted to account owners and administrators.
		role, ok := nbcontext.RoleFromContext(r.Context())
		if !ok || (types.UserRole(role) != types.UserRoleOwner && types.UserRole(role) != types.UserRoleAdmin) {
			util.WriteError(r.Context(), status.Errorf(status.PermissionDenied, "usage reports require an account owner or administrator"), w)
			return
		}
		if reporter == nil || log == nil {
			util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "usage reporting or audit storage is not configured"), w)
			return
		}
		start, startErr := time.Parse(time.RFC3339Nano, r.URL.Query().Get("start"))
		end, endErr := time.Parse(time.RFC3339Nano, r.URL.Query().Get("end"))
		if startErr != nil || endErr != nil || len(r.URL.Query()["start"]) != 1 || len(r.URL.Query()["end"]) != 1 {
			util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "start and end must each be one RFC3339 timestamp"), w)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		report, err := reporter.Devices(ctx, user.AccountId, start, end)
		if err != nil {
			if errors.Is(err, usage.ErrInvalid) {
				err = status.Errorf(status.InvalidArgument, "request a past, nonempty window of at most 93 days with microsecond timestamp precision")
			} else if errors.Is(err, usage.ErrReportLimit) {
				err = status.Errorf(status.InvalidArgument, "too many usage changes; request a shorter window")
			} else {
				err = status.Errorf(status.Internal, "could not read usage report")
			}
			util.WriteError(ctx, err, w)
			return
		}
		// Auditing every read also covers operator-granted cross-account views.
		if _, err := log.Append(ctx, user.UserId, "karst.usage.devices.view", "usage/devices", ""); err != nil {
			util.WriteError(ctx, status.Errorf(status.Internal, "could not audit usage report"), w)
			return
		}
		util.WriteJSONObject(ctx, w, report)
	}).Methods(http.MethodGet, http.MethodOptions)
}
