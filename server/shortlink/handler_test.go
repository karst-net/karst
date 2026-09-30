// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package shortlink

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newTestHandler(t *testing.T, adminToken string) *Handler {
	t.Helper()
	return NewHandler(newTestStore(t), adminToken)
}

func TestRedirectFoundAndNotFound(t *testing.T) {
	h := newTestHandler(t, "secret")
	if _, err := h.store.Create(context.Background(), "wiki", "https://wiki.example.internal"); err != nil {
		t.Fatalf("seed: %v", err)
	}

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/wiki", nil))
	if rr.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rr.Code)
	}
	if loc := rr.Header().Get("Location"); loc != "https://wiki.example.internal" {
		t.Fatalf("unexpected Location: %s", loc)
	}

	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/nope", nil))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rr.Code)
	}
}

func TestHealthz(t *testing.T) {
	h := newTestHandler(t, "")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestAdminAPIDisabledWithoutToken(t *testing.T) {
	h := newTestHandler(t, "")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/links", nil))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}
}

func TestAdminAPIRequiresBearerToken(t *testing.T) {
	h := newTestHandler(t, "secret")

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/links", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 with no header, got %d", rr.Code)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/links", nil)
	req.Header.Set("Authorization", "Bearer wrong")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 with wrong token, got %d", rr.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/links", nil)
	req.Header.Set("Authorization", "Bearer secret")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 with correct token, got %d", rr.Code)
	}
}

func TestCRUDLifecycle(t *testing.T) {
	h := newTestHandler(t, "secret")

	body, _ := json.Marshal(linkRequest{Keyword: "wiki", TargetURL: "https://wiki.example.internal"})
	req := httptest.NewRequest(http.MethodPost, "/api/links", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer secret")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rr.Code, rr.Body.String())
	}

	// Redirect now resolves.
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/wiki", nil))
	if rr.Code != http.StatusFound {
		t.Fatalf("expected 302 after create, got %d", rr.Code)
	}

	// List includes it.
	req = httptest.NewRequest(http.MethodGet, "/api/links", nil)
	req.Header.Set("Authorization", "Bearer secret")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	var links []Link
	if err := json.Unmarshal(rr.Body.Bytes(), &links); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(links) != 1 || links[0].Keyword != "wiki" {
		t.Fatalf("unexpected list: %v", links)
	}

	// Update.
	body, _ = json.Marshal(linkRequest{TargetURL: "https://new.example.internal"})
	req = httptest.NewRequest(http.MethodPut, "/api/links/wiki", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer secret")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 on update, got %d: %s", rr.Code, rr.Body.String())
	}

	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/wiki", nil))
	if loc := rr.Header().Get("Location"); loc != "https://new.example.internal" {
		t.Fatalf("unexpected Location after update: %s", loc)
	}

	// Delete.
	req = httptest.NewRequest(http.MethodDelete, "/api/links/wiki", nil)
	req.Header.Set("Authorization", "Bearer secret")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204 on delete, got %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/wiki", nil))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404 after delete, got %d", rr.Code)
	}
}

func TestCreateReservedKeywordRejected(t *testing.T) {
	h := newTestHandler(t, "secret")
	body, _ := json.Marshal(linkRequest{Keyword: "api", TargetURL: "https://example.internal"})
	req := httptest.NewRequest(http.MethodPost, "/api/links", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer secret")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestCreateDuplicateConflict(t *testing.T) {
	h := newTestHandler(t, "secret")
	body, _ := json.Marshal(linkRequest{Keyword: "wiki", TargetURL: "https://example.internal"})

	req := httptest.NewRequest(http.MethodPost, "/api/links", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer secret")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", rr.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/links", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer secret")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d", rr.Code)
	}
}
