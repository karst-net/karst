// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package shortlink

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/gorilla/mux"
)

// Handler serves both the unauthenticated redirect surface and the
// bearer-token-gated CRUD API described in ADR-0042.
type Handler struct {
	store      *Store
	adminToken string
	mux        *mux.Router
}

// NewHandler builds the HTTP handler. adminToken gates every /api/links
// request; a request presenting no token, or the wrong one, gets 401. An
// empty adminToken disables the CRUD API entirely (every /api/links request
// gets 403) rather than leaving it open — there is no "admin API with no
// auth" mode.
func NewHandler(store *Store, adminToken string) *Handler {
	h := &Handler{store: store, adminToken: adminToken}
	r := mux.NewRouter()
	r.HandleFunc("/healthz", h.healthz).Methods(http.MethodGet)
	api := r.PathPrefix("/api/links").Subrouter()
	api.Use(h.requireAdmin)
	api.HandleFunc("", h.listLinks).Methods(http.MethodGet)
	api.HandleFunc("", h.createLink).Methods(http.MethodPost)
	api.HandleFunc("/{keyword}", h.updateLink).Methods(http.MethodPut)
	api.HandleFunc("/{keyword}", h.deleteLink).Methods(http.MethodDelete)
	r.HandleFunc("/{keyword}", h.redirect).Methods(http.MethodGet)
	h.mux = r
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

func (h *Handler) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.adminToken == "" {
			http.Error(w, "admin API disabled: no admin token configured", http.StatusForbidden)
			return
		}
		const prefix = "Bearer "
		auth := r.Header.Get("Authorization")
		if len(auth) <= len(prefix) || auth[:len(prefix)] != prefix ||
			subtle.ConstantTimeCompare([]byte(auth[len(prefix):]), []byte(h.adminToken)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (h *Handler) healthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}

// redirect is the unauthenticated, mesh-reachable front door: GET /<keyword>
// -> 302 to the stored target, or 404 if the keyword is not mapped. This
// route never matches a reserved keyword (mux routes /healthz and
// /api/links before falling through to {keyword}), so an attempt to map
// "api" or "healthz" is rejected at write time in the store instead.
func (h *Handler) redirect(w http.ResponseWriter, r *http.Request) {
	keyword := mux.Vars(r)["keyword"]
	link, err := h.store.Get(r.Context(), keyword)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, link.TargetURL, http.StatusFound)
}

type linkRequest struct {
	Keyword   string `json:"keyword"`
	TargetURL string `json:"target_url"`
}

func (h *Handler) listLinks(w http.ResponseWriter, r *http.Request) {
	links, err := h.store.List(r.Context())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, links)
}

func (h *Handler) createLink(w http.ResponseWriter, r *http.Request) {
	var req linkRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	link, err := h.store.Create(r.Context(), req.Keyword, req.TargetURL)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, link)
}

func (h *Handler) updateLink(w http.ResponseWriter, r *http.Request) {
	keyword := mux.Vars(r)["keyword"]
	var req linkRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	link, err := h.store.Update(r.Context(), keyword, req.TargetURL)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, link)
}

func (h *Handler) deleteLink(w http.ResponseWriter, r *http.Request) {
	keyword := mux.Vars(r)["keyword"]
	if err := h.store.Delete(r.Context(), keyword); err != nil {
		writeStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func writeStoreError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		http.Error(w, err.Error(), http.StatusNotFound)
	case errors.Is(err, ErrExists):
		http.Error(w, err.Error(), http.StatusConflict)
	case errors.Is(err, ErrInvalidKeyword), errors.Is(err, ErrInvalidTargetURL):
		http.Error(w, err.Error(), http.StatusBadRequest)
	default:
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
