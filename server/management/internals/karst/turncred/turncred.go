// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// Package turncred mints the ephemeral TURN (RFC 8656) credentials a node
// receives in its netmap — ADR-0008 §4.
//
// # Ephemeral, not pinned
//
// Unlike the Ponor relay registry (package relayreg), a TURN server is not
// authenticated by a pinned identity key — RFC 8656 authenticates the client
// to the server via a shared credential, not the other way around. So the
// registry here is deliberately simpler: an operator-configured list of
// server URIs, and a shared secret this package never puts on the wire.
// What travels in the netmap is a minted, time-limited username/password
// pair, generated fresh per response by the standard TURN-REST scheme
// (username = a unix expiry timestamp, password =
// base64(HMAC(secret, username))) — never the secret itself. ADR-0008 is
// explicit: "Static TURN credentials must never be placed in a netmap."
//
// # These are secrets that travel
//
// Like a PSK (package psk), a minted credential's password is a real secret
// carried to the node in the netmap. [Credential] follows the same
// unprintable-by-construction discipline PSKs use, for the same reason:
// Phase 3's exit criterion is an automated scan for secret bytes in logs,
// traces and bugreports, and that only reliably holds if the type refuses to
// render rather than every call site remembering to redact it.
package turncred

import (
	"bytes"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/netbirdio/netbird/shared/management/proto"
	hmac "github.com/netbirdio/netbird/shared/relay/auth/hmac"
)

// Entry is one TURN server as an operator writes it.
type Entry struct {
	// URI is a turn: or turns: URI (RFC 8656 §3.1 / RFC 7065), e.g.
	// "turn:turn.example.com:3478" or "turns:turn.example.com:5349".
	URI string `json:"uri"`

	// Region this server serves. Empty means DefaultRegion, matching
	// relayreg's convention.
	Region string `json:"region"`
}

// DefaultRegion mirrors relayreg.DefaultRegion: both empty-region defaults
// agreeing is what lets a single-region deployment work without an operator
// ever having to learn what a region is.
const DefaultRegion = "default"

type document struct {
	Turn []Entry `json:"turn"`
}

// Load reads and validates a TURN registry file.
func Load(path string) ([]Entry, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("turn registry: %w", err)
	}
	entries, err := Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("turn registry %s: %w", path, err)
	}
	return entries, nil
}

// Parse validates a registry document and returns the configured entries.
func Parse(raw []byte) ([]Entry, error) {
	var doc document
	dec := json.NewDecoder(bytes.NewReader(raw))
	// A misspelled field would otherwise be dropped in silence, leaving a
	// server entry that is valid, wrong, and pinned to nothing an operator
	// wrote — relayreg.Parse makes the same call for the same reason.
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}

	if len(doc.Turn) == 0 {
		// An operator who configured a registry meant to publish a server.
		// Starting with none would hand every node an empty registry, which
		// looks identical to not having configured one at all.
		return nil, fmt.Errorf("no turn servers; a registry that publishes nothing leaves every node without a TURN fallback")
	}

	out := make([]Entry, 0, len(doc.Turn))
	for i := range doc.Turn {
		entry, err := doc.Turn[i].validate()
		if err != nil {
			return nil, fmt.Errorf("turn server %d: %w", i, err)
		}
		out = append(out, entry)
	}
	return out, nil
}

func (e Entry) validate() (Entry, error) {
	// Not net/url.Parse: RFC 7065's turnURI grammar is
	// "turn:" host [ ":" port ] [ "?transport=..." ], with no "//" — Go's
	// net/url treats that as an opaque URI and leaves Host empty, which
	// would make every well-formed turn: URI fail a Host check that was
	// actually testing net/url's parsing convention rather than this
	// package's own rule.
	scheme, rest, ok := strings.Cut(e.URI, ":")
	if !ok {
		return Entry{}, fmt.Errorf("uri %q has no scheme", e.URI)
	}
	// Named rather than a generic "invalid scheme": ADR-0008 rejects DERP
	// wire compatibility outright, and the same discipline applies to any
	// other scheme here, including one this package does not yet know
	// about — a TURN registry must not become a way to configure an
	// arbitrary relay.
	switch scheme {
	case "turn", "turns":
	default:
		return Entry{}, fmt.Errorf("uri %q has scheme %q, want turn: or turns:", e.URI, scheme)
	}
	rest = strings.TrimPrefix(rest, "//") // tolerate turn://host:port too
	if rest == "" {
		return Entry{}, fmt.Errorf("uri %q has no host", e.URI)
	}

	region := e.Region
	if region == "" {
		region = DefaultRegion
	}
	return Entry{URI: e.URI, Region: region}, nil
}

// Credential is a minted TURN-REST username/password pair. It deliberately
// does not print — see the package doc.
type Credential struct {
	Username  string
	Password  string
	ExpiresAt time.Time
}

const redacted = "turn-credential(redacted)"

func (Credential) String() string               { return redacted }
func (Credential) GoString() string             { return redacted }
func (Credential) MarshalText() ([]byte, error) { return []byte(redacted), nil }
func (Credential) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }
func (Credential) Format(f fmt.State, _ rune)   { _, _ = f.Write([]byte(redacted)) }

// Minter mints time-limited TURN-REST credentials from a shared secret.
//
// One Minter serves every configured server: the standard TURN-REST
// deployment shape is one static-auth-secret shared across every coturn
// instance in a deployment, each minting and validating independently
// against it, so one minted credential is valid on all of them.
type Minter struct {
	hmac *hmac.TimedHMAC
}

// NewMinter builds a Minter from a shared secret and credential lifetime.
func NewMinter(secret string, ttl time.Duration) (*Minter, error) {
	if secret == "" {
		return nil, fmt.Errorf("turncred: empty shared secret")
	}
	if ttl <= 0 {
		return nil, fmt.Errorf("turncred: non-positive ttl %s", ttl)
	}
	return &Minter{hmac: hmac.NewTimedHMAC(secret, ttl)}, nil
}

// Mint generates a fresh credential. sha1.New is the coturn/TURN-REST
// default hash — the same one NetBird's own inherited credential minting
// (server/management/internals/shared/grpc/token_mgr.go) already uses.
func (m *Minter) Mint() (Credential, error) {
	tok, err := m.hmac.GenerateToken(sha1.New)
	if err != nil {
		return Credential{}, fmt.Errorf("turncred: mint: %w", err)
	}
	expiry, err := strconv.ParseInt(tok.Payload, 10, 64)
	if err != nil {
		// GenerateToken's own payload is always a unix timestamp it just
		// formatted; a parse failure here would mean the two disagree about
		// their own wire format, not a caller mistake.
		return Credential{}, fmt.Errorf("turncred: mint: unparseable expiry %q: %w", tok.Payload, err)
	}
	return Credential{
		Username:  tok.Payload,
		Password:  tok.Signature,
		ExpiresAt: time.Unix(expiry, 0),
	}, nil
}

// NetmapEntries mints one credential and stamps it onto every configured
// server, producing the netmap wire entries. Returns (nil, nil) — not an
// error — when servers is empty or m is nil, so a deployment that has not
// configured TURN produces a netmap with no turn_servers field: this
// feature is opt-in the same way the anchor tier and the netmap-cache suite
// mechanism are.
func NetmapEntries(servers []Entry, m *Minter) ([]*proto.KarstTurnServer, error) {
	if len(servers) == 0 || m == nil {
		return nil, nil
	}
	cred, err := m.Mint()
	if err != nil {
		return nil, err
	}
	out := make([]*proto.KarstTurnServer, 0, len(servers))
	for _, s := range servers {
		out = append(out, &proto.KarstTurnServer{
			Uri:       s.URI,
			Region:    s.Region,
			Username:  cred.Username,
			Password:  cred.Password,
			ExpiresAt: uint64(cred.ExpiresAt.Unix()),
		})
	}
	return out, nil
}
