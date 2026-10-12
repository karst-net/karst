// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package relayusage

import (
	"errors"
	"io"
	"mime"
	"net/http"
	"time"

	"github.com/gorilla/mux"
)

// RegisterUploadEndpoint mounts the relay-only endpoint on the outer router,
// beside relay telemetry. It intentionally bypasses user-session middleware;
// the handler requires a managed producer's fresh ML-DSA request signature.
func RegisterUploadEndpoint(router *mux.Router, store *Store) {
	router.Handle(UploadPath, &uploadHandler{store: store, now: time.Now}).Methods(http.MethodPost)
}

type uploadHandler struct {
	store *Store
	now   func() time.Time
}

func (h *uploadHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost || r.URL.RawQuery != "" || r.URL.EscapedPath() != UploadPath {
		http.Error(w, "invalid relay usage request", http.StatusBadRequest)
		return
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/octet-stream" {
		http.Error(w, "unsupported relay usage content type", http.StatusUnsupportedMediaType)
		return
	}
	auth, err := ParseUploadAuthorization(r.Header.Get("Authorization"))
	if err != nil {
		http.Error(w, "relay usage upload rejected", http.StatusForbidden)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxEncodedSize))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			http.Error(w, "relay usage batch too large", http.StatusRequestEntityTooLarge)
		} else {
			http.Error(w, "could not read relay usage batch", http.StatusBadRequest)
		}
		return
	}
	_, err = h.store.Ingest(r.Context(), r.Method, UploadPath, auth, body, h.now())
	switch {
	case err == nil:
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, ErrInvalidBatch), errors.Is(err, ErrInvalidUploadAuth):
		http.Error(w, "invalid relay usage batch", http.StatusBadRequest)
	case errors.Is(err, ErrUnauthorized), errors.Is(err, ErrProducerMissing), errors.Is(err, ErrMappingNotAllowed):
		http.Error(w, "relay usage upload rejected", http.StatusForbidden)
	case errors.Is(err, ErrRequestReplay), errors.Is(err, ErrBatchConflict):
		http.Error(w, "relay usage batch conflict", http.StatusConflict)
	default:
		http.Error(w, "could not persist relay usage batch", http.StatusInternalServerError)
	}
}
