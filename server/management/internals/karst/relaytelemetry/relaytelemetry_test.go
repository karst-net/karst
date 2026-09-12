// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package relaytelemetry

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/management/internals/karst/identity"
	"github.com/netbirdio/netbird/management/internals/karst/relayreg"
)

// fakeStore is an in-memory stand-in for relayreg.Store's two methods this
// package needs, so these tests exercise the handler's own logic (parsing,
// signature verification, freshness) without a database.
type fakeStore struct {
	byID      map[string][]relayreg.StoredRelay
	recorded  []recordedCall
	failList  bool
	failWrite bool
}

type recordedCall struct {
	accountID, id string
	t             relayreg.Telemetry
}

func (f *fakeStore) FindByID(_ context.Context, id string) ([]relayreg.StoredRelay, error) {
	if f.failList {
		return nil, errFake
	}
	return f.byID[id], nil
}

func (f *fakeStore) RecordTelemetry(_ context.Context, accountID, id string, t relayreg.Telemetry) error {
	if f.failWrite {
		return errFake
	}
	f.recorded = append(f.recorded, recordedCall{accountID, id, t})
	return nil
}

var errFake = &fakeError{}

type fakeError struct{}

func (*fakeError) Error() string { return "fake store error" }

// testRelay is one relay identity plus the registry row a store would hold
// for it, so a test can sign a report the same way a real karst-relay would.
type testRelay struct {
	key       *identity.Key
	accountID string
	id        string // base64.RawURLEncoding, matching relayreg.StoredRelay.ID
}

func newTestRelay(t *testing.T, accountID string) testRelay {
	t.Helper()
	key, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	rawID := relayreg.RelayID(key.Public())
	return testRelay{
		key:       key,
		accountID: accountID,
		id:        base64.RawURLEncoding.EncodeToString(rawID),
	}
}

func (r testRelay) storedRelay() relayreg.StoredRelay {
	return relayreg.StoredRelay{
		AccountID:   r.accountID,
		ID:          r.id,
		IdentityKey: base64.StdEncoding.EncodeToString(r.key.Public()),
	}
}

// validRequest signs a report exactly the way ADR-0021 specifies, so these
// tests exercise the real wire contract rather than a shortcut through it.
func (r testRelay) validRequest(t *testing.T, at time.Time, tel relayreg.Telemetry) report {
	t.Helper()
	rawID, err := base64.RawURLEncoding.DecodeString(r.id)
	if err != nil {
		t.Fatalf("decode id: %v", err)
	}
	req := report{
		RelayID:       r.id,
		Timestamp:     at.Unix(),
		LocalClients:  tel.LocalClients,
		MeshPeers:     tel.MeshPeers,
		RemoteClients: tel.RemoteClients,
		BytesTotal:    tel.BytesTotal,
		UptimeSecs:    tel.UptimeSecs,
	}
	sig, err := r.key.Sign([]byte(identity.RelayTelemetryContext), signingInput(rawID, req))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	req.Signature = base64.StdEncoding.EncodeToString(sig)
	return req
}

func post(t *testing.T, h http.Handler, relayID string, req report) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	r := httptest.NewRequest(http.MethodPost, "/karst/v1/relays/"+relayID+"/telemetry", bytes.NewReader(body))
	r = mux.SetURLVars(r, map[string]string{"relayId": relayID})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func newHandler(store *fakeStore) http.Handler {
	router := mux.NewRouter()
	RegisterEndpoints(router, store)
	return router
}

func TestAValidReportIsAcceptedAndRecorded(t *testing.T) {
	relay := newTestRelay(t, "acct-a")
	store := &fakeStore{byID: map[string][]relayreg.StoredRelay{relay.id: {relay.storedRelay()}}}
	tel := relayreg.Telemetry{LocalClients: 3, MeshPeers: 1, RemoteClients: 7, BytesTotal: 1000, UptimeSecs: 60}
	req := relay.validRequest(t, time.Now(), tel)

	w := post(t, newHandler(store), relay.id, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	if len(store.recorded) != 1 {
		t.Fatalf("got %d recorded calls, want 1", len(store.recorded))
	}
	got := store.recorded[0]
	if got.accountID != "acct-a" || got.id != relay.id || got.t != tel {
		t.Fatalf("recorded %+v, want account=acct-a id=%s telemetry=%+v", got, relay.id, tel)
	}
}

func TestAWrongSignatureIsRejected(t *testing.T) {
	relay := newTestRelay(t, "acct-a")
	impostor := newTestRelay(t, "acct-a") // a different key entirely
	store := &fakeStore{byID: map[string][]relayreg.StoredRelay{relay.id: {relay.storedRelay()}}}

	// Signed by the impostor's key, but claiming to be `relay`.
	req := impostor.validRequest(t, time.Now(), relayreg.Telemetry{})
	req.RelayID = relay.id

	w := post(t, newHandler(store), relay.id, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body = %s", w.Code, w.Body.String())
	}
	if len(store.recorded) != 0 {
		t.Fatalf("got %d recorded calls, want 0 — an unverified report must never be stored", len(store.recorded))
	}
}

func TestAStaleTimestampIsRejected(t *testing.T) {
	relay := newTestRelay(t, "acct-a")
	store := &fakeStore{byID: map[string][]relayreg.StoredRelay{relay.id: {relay.storedRelay()}}}
	req := relay.validRequest(t, time.Now().Add(-2*freshnessWindow), relayreg.Telemetry{})

	w := post(t, newHandler(store), relay.id, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body = %s", w.Code, w.Body.String())
	}
	if len(store.recorded) != 0 {
		t.Fatalf("got %d recorded calls, want 0", len(store.recorded))
	}
}

func TestAFutureTimestampIsRejected(t *testing.T) {
	relay := newTestRelay(t, "acct-a")
	store := &fakeStore{byID: map[string][]relayreg.StoredRelay{relay.id: {relay.storedRelay()}}}
	req := relay.validRequest(t, time.Now().Add(2*freshnessWindow), relayreg.Telemetry{})

	w := post(t, newHandler(store), relay.id, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 — a report from the future is exactly as suspicious as a stale one; body = %s", w.Code, w.Body.String())
	}
}

func TestAnUnregisteredRelayIDIsRejected(t *testing.T) {
	relay := newTestRelay(t, "acct-a")
	store := &fakeStore{} // empty registry
	req := relay.validRequest(t, time.Now(), relayreg.Telemetry{})

	w := post(t, newHandler(store), relay.id, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 — unknown id and bad signature must look identical; body = %s", w.Code, w.Body.String())
	}
}

func TestABodyRelayIDThatDoesNotMatchTheURLIsRejected(t *testing.T) {
	relay := newTestRelay(t, "acct-a")
	other := newTestRelay(t, "acct-a")
	store := &fakeStore{byID: map[string][]relayreg.StoredRelay{relay.id: {relay.storedRelay()}}}
	req := relay.validRequest(t, time.Now(), relayreg.Telemetry{})

	// Posted to a different relay's URL than the body claims.
	w := post(t, newHandler(store), other.id, req)

	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422; body = %s", w.Code, w.Body.String())
	}
	if len(store.recorded) != 0 {
		t.Fatalf("got %d recorded calls, want 0", len(store.recorded))
	}
}

func TestAReportIsRecordedUnderEveryAccountThatRegisteredTheSameKey(t *testing.T) {
	relay := newTestRelay(t, "acct-a")
	sameKeyOtherAccount := relay
	sameKeyOtherAccount.accountID = "acct-b"
	store := &fakeStore{byID: map[string][]relayreg.StoredRelay{
		relay.id: {relay.storedRelay(), sameKeyOtherAccount.storedRelay()},
	}}
	req := relay.validRequest(t, time.Now(), relayreg.Telemetry{LocalClients: 1})

	w := post(t, newHandler(store), relay.id, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	if len(store.recorded) != 2 {
		t.Fatalf("got %d recorded calls, want 2 (one per account holding this key)", len(store.recorded))
	}
}

func TestMalformedJSONIsRejected(t *testing.T) {
	store := &fakeStore{}
	r := httptest.NewRequest(http.MethodPost, "/karst/v1/relays/x/telemetry", bytes.NewReader([]byte("not json")))
	r = mux.SetURLVars(r, map[string]string{"relayId": "x"})
	w := httptest.NewRecorder()
	newHandler(store).ServeHTTP(w, r)

	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422; body = %s", w.Code, w.Body.String())
	}
}
