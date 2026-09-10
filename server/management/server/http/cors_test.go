package http

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCORSMiddleware(t *testing.T) {
	handler := newCORSMiddleware([]string{"https://console.example.test"}).Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	t.Run("allows a configured origin", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/nodes", nil)
		req.Header.Set("Origin", "https://console.example.test")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.Equal(t, "https://console.example.test", rec.Header().Get("Access-Control-Allow-Origin"))
		assert.Empty(t, rec.Header().Get("Access-Control-Allow-Credentials"))
	})

	t.Run("does not allow an unconfigured origin", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/nodes", nil)
		req.Header.Set("Origin", "https://attacker.example.test")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.Empty(t, rec.Header().Get("Access-Control-Allow-Origin"))
	})

	t.Run("allows authenticated API preflight for a configured origin", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodOptions, "/api/nodes", nil)
		req.Header.Set("Origin", "https://console.example.test")
		req.Header.Set("Access-Control-Request-Method", http.MethodDelete)
		req.Header.Set("Access-Control-Request-Headers", "Authorization, Content-Type")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusNoContent, rec.Code)
		assert.Equal(t, "https://console.example.test", rec.Header().Get("Access-Control-Allow-Origin"))
		assert.Contains(t, rec.Header().Get("Access-Control-Allow-Methods"), http.MethodDelete)
		assert.Contains(t, rec.Header().Get("Access-Control-Allow-Headers"), "Authorization")
	})

	t.Run("defaults to same-origin only", func(t *testing.T) {
		defaultHandler := newCORSMiddleware(nil).Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		req := httptest.NewRequest(http.MethodGet, "/api/nodes", nil)
		req.Header.Set("Origin", "https://console.example.test")
		rec := httptest.NewRecorder()

		defaultHandler.ServeHTTP(rec, req)

		assert.Empty(t, rec.Header().Get("Access-Control-Allow-Origin"))
	})

	t.Run("does not treat a wildcard setting as an allowed origin", func(t *testing.T) {
		wildcardHandler := newCORSMiddleware([]string{"*"}).Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		req := httptest.NewRequest(http.MethodGet, "/api/nodes", nil)
		req.Header.Set("Origin", "https://attacker.example.test")
		rec := httptest.NewRecorder()

		wildcardHandler.ServeHTTP(rec, req)

		assert.Empty(t, rec.Header().Get("Access-Control-Allow-Origin"))
	})
}
