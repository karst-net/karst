// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"gorm.io/gorm"

	"github.com/netbirdio/netbird/management/internals/karst/audit"
	"github.com/netbirdio/netbird/management/internals/karst/billing"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

type customerPaymentStore interface {
	WithDB(*gorm.DB) *billing.Store
	PaddleAccount(context.Context) (billing.PaddleAccount, error)
	QueuePayment(context.Context, time.Time, time.Time) (billing.PaymentIntent, error)
	Payment(context.Context, time.Time, time.Time) (billing.PaymentIntent, error)
	PaymentFailureNotices(context.Context, time.Time, time.Time) ([]billing.PaymentFailureNotice, error)
	Invoice(context.Context, time.Time, time.Time) (billing.FinalInvoice, error)
}

type customerPaymentView struct {
	PeriodStart time.Time `json:"period_start"`
	PeriodEnd   time.Time `json:"period_end"`
	Currency    string    `json:"currency"`
	DeviceMinor int64     `json:"device_minor"`
	RelayMinor  int64     `json:"relay_minor"`
	TotalMinor  int64     `json:"total_minor"`
	State       string    `json:"state"`
	CheckoutURL string    `json:"checkout_url,omitempty"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// RegisterPaymentEndpoints lets an account owner or admin explicitly queue
// collection for a finalized invoice and read payment state.
// The queue mutation and audit record share one SQL transaction; the provider
// request runs later in the outbox worker.
func RegisterPaymentEndpoints(router *mux.Router, manager permissions.Manager, db *gorm.DB, payments customerPaymentStore, log *audit.Log, collectionEnabled bool) {
	notices := router.PathPrefix("/karst/v1/billing/payment-notices").Subrouter()
	notices.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			if manager == nil {
				util.WriteError(r.Context(), status.Errorf(status.PermissionDenied, "billing authorization is not configured"), w)
				return
			}
			karstAuthorization(manager)(next).ServeHTTP(w, r)
		})
	})
	notices.HandleFunc("", func(w http.ResponseWriter, r *http.Request) {
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
		if !ok || !isBillingRole(types.UserRole(role)) {
			util.WriteError(r.Context(), status.Errorf(status.PermissionDenied, "billing notices require an account owner or administrator"), w)
			return
		}
		period, err := parsePaymentPeriod(r)
		if err != nil {
			util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "period must be one YYYY-MM UTC calendar month"), w)
			return
		}
		if payments == nil || log == nil {
			util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "billing notice or audit storage is not configured"), w)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		accountCtx := billing.WithAccount(ctx, user.AccountId)
		periodEnd := period.AddDate(0, 1, 0)
		items, err := payments.PaymentFailureNotices(accountCtx, period, periodEnd)
		if err != nil {
			paymentAPIError(ctx, w, err)
			return
		}
		if _, err := log.Append(ctx, user.UserId, "karst.billing.payment_notices.view", "billing/payment-notices/"+period.Format("2006-01"), ""); err != nil {
			util.WriteError(ctx, status.Errorf(status.Internal, "could not audit billing notice access"), w)
			return
		}
		util.WriteJSONObject(ctx, w, map[string]any{"notices": items})
	}).Methods(http.MethodGet, http.MethodOptions)

	routes := router.PathPrefix("/karst/v1/billing/payments").Subrouter()
	routes.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			if manager == nil {
				util.WriteError(r.Context(), status.Errorf(status.PermissionDenied, "billing authorization is not configured"), w)
				return
			}
			karstAuthorization(manager)(next).ServeHTTP(w, r)
		})
	})
	routes.HandleFunc("", func(w http.ResponseWriter, r *http.Request) {
		user, err := nbcontext.GetUserAuthFromContext(r.Context())
		if err != nil {
			util.WriteError(r.Context(), err, w)
			return
		}
		role, ok := nbcontext.RoleFromContext(r.Context())
		if !ok || !isBillingRole(types.UserRole(role)) {
			util.WriteError(r.Context(), status.Errorf(status.PermissionDenied, "billing requires an account owner or administrator"), w)
			return
		}
		period, err := parsePaymentPeriod(r)
		if err != nil {
			util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "period must be one YYYY-MM UTC calendar month"), w)
			return
		}
		if payments == nil || db == nil || log == nil || !collectionEnabled {
			util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "Paddle collection or billing storage is not configured"), w)
			return
		}
		start := period
		end := start.AddDate(0, 1, 0)
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		accountCtx := billing.WithAccount(ctx, user.AccountId)
		if _, err := payments.PaddleAccount(accountCtx); err != nil {
			util.WriteError(ctx, status.Errorf(status.PreconditionFailed, "Paddle billing is not enabled for this account"), w)
			return
		}
		switch r.Method {
		case http.MethodGet:
			invoice, err := payments.Invoice(accountCtx, start, end)
			if err != nil {
				paymentAPIError(ctx, w, err)
				return
			}
			intent, err := payments.Payment(accountCtx, start, end)
			if errors.Is(err, billing.ErrPaymentNotFound) {
				intent = billing.PaymentIntent{State: "not_queued", UpdatedAt: invoice.FinalizedAt}
			} else if err != nil {
				paymentAPIError(ctx, w, err)
				return
			}
			if _, err := log.Append(ctx, user.UserId, "karst.billing.payment.view", "billing/payments/"+start.Format("2006-01"), ""); err != nil {
				util.WriteError(ctx, status.Errorf(status.Internal, "could not audit payment view"), w)
				return
			}
			writePaymentView(w, http.StatusOK, paymentView(invoice, intent))
		case http.MethodPost:
			var intent billing.PaymentIntent
			var invoice billing.FinalInvoice
			err := db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
				transactionalStore := payments.WithDB(tx)
				if _, err := transactionalStore.PaddleAccount(accountCtx); err != nil {
					return err
				}
				var invoiceErr error
				invoice, invoiceErr = transactionalStore.Invoice(accountCtx, start, end)
				if invoiceErr != nil {
					return invoiceErr
				}
				var queueErr error
				intent, queueErr = transactionalStore.QueuePayment(accountCtx, start, end)
				if queueErr != nil {
					return queueErr
				}
				_, auditErr := log.AppendInTransaction(audit.WithAccount(accountCtx, user.AccountId), tx, user.UserId, "karst.billing.payment.queue", "billing/payments/"+start.Format("2006-01"), fmt.Sprintf("invoice_reference=%s", intent.InvoiceReference))
				return auditErr
			})
			if err != nil {
				paymentAPIError(ctx, w, err)
				return
			}
			writePaymentView(w, http.StatusAccepted, paymentView(invoice, intent))
		default:
			w.Header().Set("Allow", "GET, POST, OPTIONS")
			util.WriteError(ctx, status.Errorf(status.InvalidArgument, "method must be GET or POST"), w)
		}
	}).Methods(http.MethodGet, http.MethodPost)
}

func isBillingRole(role types.UserRole) bool {
	return role == types.UserRoleOwner || role == types.UserRoleAdmin
}

func parsePaymentPeriod(r *http.Request) (time.Time, error) {
	query := r.URL.Query()
	values := query["period"]
	if len(values) != 1 || query.Encode() != "period="+values[0] {
		return time.Time{}, errors.New("invalid period")
	}
	start, err := time.Parse("2006-01", values[0])
	if err != nil || start.Format("2006-01") != values[0] {
		return time.Time{}, errors.New("invalid period")
	}
	return start.UTC(), nil
}

func paymentView(invoice billing.FinalInvoice, intent billing.PaymentIntent) customerPaymentView {
	return customerPaymentView{PeriodStart: invoice.PeriodStart, PeriodEnd: invoice.PeriodEnd, Currency: invoice.Currency,
		DeviceMinor: invoice.DeviceMinor, RelayMinor: invoice.RelayMinor, TotalMinor: invoice.TotalMinor,
		State: intent.State, CheckoutURL: intent.CheckoutURL, UpdatedAt: intent.UpdatedAt}
}

func writePaymentView(w http.ResponseWriter, responseStatus int, view customerPaymentView) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(responseStatus)
	_ = json.NewEncoder(w).Encode(view)
}

func paymentAPIError(ctx context.Context, w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, billing.ErrPaddleAccountNotConfigured):
		err = status.Errorf(status.PreconditionFailed, "Paddle billing is not enabled for this account")
	case errors.Is(err, billing.ErrInvoiceNotFound):
		err = status.Errorf(status.PreconditionFailed, "no finalized invoice exists for this period")
	case errors.Is(err, billing.ErrNoBillingAccount):
		err = status.Errorf(status.PermissionDenied, "billing account scope is unavailable")
	case errors.Is(err, billing.ErrNoPaddleCharge), errors.Is(err, billing.ErrInvalidPaddleInvoice):
		err = status.Errorf(status.PreconditionFailed, "invoice cannot be collected through Paddle")
	default:
		err = status.Errorf(status.Internal, "could not process billing payment request")
	}
	util.WriteError(ctx, err, w)
}
