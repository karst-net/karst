// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// Package relaytelemetry serves the one endpoint a relay itself calls —
// ADR-0021.
//
// Deliberately its own package, not part of api: that package's own doc
// comment says it "deliberately consumes the router's existing
// authentication middleware; this package never parses credentials itself".
// A relay has no user session to present, so authenticating it belongs
// somewhere that owns doing so — the same reason `channel` exists beside
// `api` for the node control channel's own ML-DSA verification, rather than
// that verification living in api too.
package relaytelemetry

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/management/internals/karst/identity"
	"github.com/netbirdio/netbird/management/internals/karst/relayreg"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

// maxBodyBytes bounds a report's size before anything is parsed — this
// endpoint has no session and no rate limiting beyond it, so an oversized
// body has to be refused before decoding rather than after. An ML-DSA-87
// signature is 4627 raw bytes, ~6172 base64-encoded, so the bound has to
// clear that plus the rest of the envelope with real headroom, not just fit
// a typical small-signature scheme.
const maxBodyBytes = 8192

// freshnessWindow bounds how far a report's own timestamp may be from the
// server's clock, in either direction, before it is rejected as a replay or
// a badly-skewed clock — ADR-0021. Generous relative to the relay's own
// default report interval (60s) to tolerate clock skew and a missed tick;
// tight enough that a captured report is useless within minutes.
const freshnessWindow = 5 * time.Minute

// signedFieldCount matches the fixed layout ADR-0021 specifies: relay_id (32
// bytes) plus six 8-byte big-endian fields.
const signedMessageLen = 32 + 8*6

// store is the narrow slice of relayreg.Store this package needs. Unlike
// api.relayReader, FindByID is not account-scoped — a relay proves itself by
// a signature over its own id, not by presenting an account context.
type store interface {
	FindByID(ctx context.Context, id string) ([]relayreg.StoredRelay, error)
	RecordTelemetry(ctx context.Context, accountID, id string, t relayreg.Telemetry) error
}

// RegisterEndpoints wires the relay-telemetry POST route directly on the
// server's outer router, bypassing the `/karst/v1` subrouter's blanket user
// authorization — ADR-0021. Call this beside api.RegisterEndpoints, on the
// same router, with the same relayreg.Store.
func RegisterEndpoints(router *mux.Router, relays store) {
	h := &handler{relays: relays}
	router.HandleFunc("/karst/v1/relays/{relayId}/telemetry", h.report).Methods(http.MethodPost)
}

type handler struct {
	relays store
}

// report is the request body's shape — the transport envelope. See
// ADR-0021 for why the signed message is a separate, fixed binary layout
// rather than these JSON bytes.
type report struct {
	RelayID       string `json:"relay_id"`
	Timestamp     int64  `json:"timestamp"`
	LocalClients  int    `json:"local_clients"`
	MeshPeers     int    `json:"mesh_peers"`
	RemoteClients int    `json:"remote_clients"`
	BytesTotal    int64  `json:"bytes_total"`
	UptimeSecs    int64  `json:"uptime_secs"`
	Signature     string `json:"signature"`
}

func (h *handler) report(w http.ResponseWriter, r *http.Request) {
	urlRelayID := mux.Vars(r)["relayId"]

	var req report
	if err := json.NewDecoder(io.LimitReader(r.Body, maxBodyBytes)).Decode(&req); err != nil {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "malformed telemetry report"), w)
		return
	}
	if req.RelayID != urlRelayID {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "relay_id does not match the URL"), w)
		return
	}
	relayID, err := base64.RawURLEncoding.DecodeString(req.RelayID)
	if err != nil || len(relayID) != 32 {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "relay_id is not a 32-byte id"), w)
		return
	}
	if age := time.Since(time.Unix(req.Timestamp, 0)); age > freshnessWindow || age < -freshnessWindow {
		// Uniform with the signature-rejection path below: a caller probing
		// for "is this id registered" or "is this timestamp stale" learns
		// nothing more from one failure mode than the other.
		util.WriteError(r.Context(), status.Errorf(status.PermissionDenied, "telemetry report rejected"), w)
		return
	}
	sig, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "signature is not base64"), w)
		return
	}

	candidates, err := h.relays.FindByID(r.Context(), req.RelayID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	msg := signingInput(relayID, req)
	t := relayreg.Telemetry{
		LocalClients:  req.LocalClients,
		MeshPeers:     req.MeshPeers,
		RemoteClients: req.RemoteClients,
		BytesTotal:    req.BytesTotal,
		UptimeSecs:    req.UptimeSecs,
	}
	recorded := false
	for _, candidate := range candidates {
		key, err := base64.StdEncoding.DecodeString(candidate.IdentityKey)
		if err != nil {
			continue
		}
		if !identity.Verify(key, []byte(identity.RelayTelemetryContext), msg, sig) {
			continue
		}
		if err := h.relays.RecordTelemetry(r.Context(), candidate.AccountID, candidate.ID, t); err != nil {
			util.WriteError(r.Context(), err, w)
			return
		}
		recorded = true
	}
	if !recorded {
		// Whether the id is unknown or the signature is simply wrong looks
		// identical here, for the same reason ponor-v1.md §10 keeps its own
		// handshake rejections uniform: distinguishing the two would hand an
		// unauthenticated caller a way to probe which relay ids exist.
		util.WriteError(r.Context(), status.Errorf(status.PermissionDenied, "telemetry report rejected"), w)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// signingInput builds ADR-0021's fixed 80-byte signed message: relay_id
// followed by six big-endian 8-byte fields. Never the JSON body — JSON has
// no canonical encoding, and a signature must cover bytes both sides
// construct identically without needing to agree on field order or
// whitespace.
func signingInput(relayID []byte, req report) []byte {
	buf := make([]byte, 0, signedMessageLen)
	buf = append(buf, relayID...)
	buf = binary.BigEndian.AppendUint64(buf, uint64(req.Timestamp))
	buf = binary.BigEndian.AppendUint64(buf, uint64(req.LocalClients))
	buf = binary.BigEndian.AppendUint64(buf, uint64(req.MeshPeers))
	buf = binary.BigEndian.AppendUint64(buf, uint64(req.RemoteClients))
	buf = binary.BigEndian.AppendUint64(buf, uint64(req.BytesTotal))
	buf = binary.BigEndian.AppendUint64(buf, uint64(req.UptimeSecs))
	return buf
}
