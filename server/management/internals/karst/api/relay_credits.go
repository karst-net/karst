// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package api

import (
	"context"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/management/internals/karst/billing"
	"github.com/netbirdio/netbird/management/internals/karst/relayusage"
	"github.com/netbirdio/netbird/shared/management/http/util"
)

// RegisterRelayCreditEndpoint mounts the relay-only, ML-DSA-authenticated
// credit reservation endpoint. It does not use customer session auth because
// the managed relay identity and signed mapping request are its authority.
func RegisterRelayCreditEndpoint(router *mux.Router, relayStore *relayusage.Store, billingStore *billing.Store) {
	router.Handle(relayusage.CreditRequestPath, &relayCreditHandler{relays: relayStore, billing: billingStore}).Methods(http.MethodPost)
}

type relayCreditHandler struct {
	relays  *relayusage.Store
	billing *billing.Store
}

func (h *relayCreditHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost || r.URL.RawQuery != "" || r.URL.EscapedPath() != relayusage.CreditRequestPath {
		http.Error(w, "invalid relay cap credit request", http.StatusBadRequest)
		return
	}
	if h.relays == nil || h.billing == nil {
		http.Error(w, "relay cap credits are not configured", http.StatusServiceUnavailable)
		return
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		http.Error(w, "unsupported relay cap content type", http.StatusUnsupportedMediaType)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8192))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			http.Error(w, "relay cap request too large", http.StatusRequestEntityTooLarge)
		} else {
			http.Error(w, "could not read relay cap request", http.StatusBadRequest)
		}
		return
	}
	request, err := relayusage.ParseCreditRequest(body)
	if err != nil {
		http.Error(w, "invalid relay cap request", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	now := time.Now().UTC()
	start := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	end := start.AddDate(0, 1, 0)
	grant, err := h.billing.ReserveAuthorizedRelayCredits(ctx, h.relays, start, end, request)
	if errors.Is(err, billing.ErrRelayCapNotConfigured) {
		until, leaseErr := h.billing.IssueAuthorizedRelayUncappedLease(ctx, h.relays, start, end, request)
		if errors.Is(leaseErr, billing.ErrRelayCapAlreadyActive) {
			grant, err = h.billing.ReserveAuthorizedRelayCredits(ctx, h.relays, start, end, request)
		} else if leaseErr == nil {
			w.Header().Set("X-Karst-Relay-Cap-Mode", "uncapped")
			w.Header().Set("X-Karst-Relay-Cap-Lease-Millis", strconv.FormatInt(billing.RelayUncappedLeaseMillis, 10))
			w.Header().Set("X-Karst-Relay-Cap-Until", strconv.FormatInt(until.UnixMicro(), 10))
			w.WriteHeader(http.StatusNoContent)
			return
		} else {
			err = leaseErr
		}
	}
	if err != nil {
		switch {
		case errors.Is(err, relayusage.ErrInvalidCreditRequest):
			http.Error(w, "invalid relay cap request", http.StatusBadRequest)
		case errors.Is(err, relayusage.ErrUnauthorized), errors.Is(err, relayusage.ErrProducerMissing), errors.Is(err, relayusage.ErrMappingNotAllowed):
			http.Error(w, "relay cap request rejected", http.StatusForbidden)
		case errors.Is(err, billing.ErrRelayCapPending):
			w.Header().Set("Retry-After", "1")
			http.Error(w, "relay cap activation is pending uncapped forwarding leases", http.StatusTooEarly)
		case errors.Is(err, billing.ErrRelayCapNotConfigured):
			http.Error(w, "relay cap state could not be leased", http.StatusServiceUnavailable)
		case errors.Is(err, billing.ErrRelayCapExhausted):
			http.Error(w, "relay spending cap exhausted", http.StatusTooManyRequests)
		case errors.Is(err, billing.ErrCreditRequestConflict):
			http.Error(w, "relay cap request ID conflicts with prior request", http.StatusConflict)
		default:
			http.Error(w, "could not reserve relay cap credits", http.StatusInternalServerError)
		}
		return
	}
	util.WriteJSONObject(ctx, w, grant)
}

var _ http.Handler = (*relayCreditHandler)(nil)
