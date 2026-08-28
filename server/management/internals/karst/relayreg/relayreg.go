// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// Package relayreg loads the authenticated relay registry a node receives in
// its netmap — spec/ponor-v1.md §4.2, §5.2.
//
// # Why this exists
//
// A node learns which relays exist, and which key authenticates each one, from
// exactly one place: the `relays` field of its signed netmap. There is
// deliberately no local relay list in `karstd` — §4.2 declines to trust TLS for
// relay identity, so a relay a node was told about out of band would be a relay
// it could not authenticate.
//
// The consequence, unwritten until FINDINGS.md 43, is that
// `control.NetmapHandler.Relays` is the *only* supply of relays in the entire
// system — and until this package the only code that ever populated it was
// `karst/testserver`, which exists to serve the Rust test suite. A production
// coordination server handed every node an empty registry, so a relay could be
// running, correctly configured, with a current roster, and no node would ever
// dial it. Nothing failed; relaying simply never happened, and a pair of nodes
// that could not reach each other directly could not reach each other at all.
//
// # Why a file, and why validated here
//
// The registry is operator-supplied configuration rather than discovered state
// because a relay's identity key is a *pin*: §4.2 has the node trust the key
// the coordination server vouches for and nothing else, which is only
// meaningful if a human decided what that key is.
//
// Validation is fatal at startup, and that is not caution — it is the only
// place the error can be reported usefully. `karstd` decodes the registry with
// `collect::<Result<_, _>>()?` (bins/karstd/src/netmap.rs), so **one malformed
// entry fails the entire netmap for every node**, not merely that one relay.
// A typo here is a total outage whose symptom is every node failing to parse a
// netmap it just authenticated. Refusing to start converts that into a message
// naming the field, at the moment the operator changed it.
package relayreg

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/netbirdio/netbird/shared/management/proto"
)

// IdentityKeySize is an ML-DSA-87 public key. `karstd` refuses any other
// length while decoding the netmap, so accepting one here would move a
// startup-visible mistake into every node's netmap.
const IdentityKeySize = 2592

// DefaultRegion matches the default in a relay's own configuration
// (bins/karst-relay/src/config.rs).
//
// Both ends defaulting to the same name is what lets a single-region
// deployment work without anyone learning what a region is — and §8 refuses to
// mesh across regions, so a registry that defaulted differently from the relay
// would produce a mesh that silently never forms.
const DefaultRegion = "default"

// idLabel domain-separates a relay identifier from a node handle — §5.2.
//
// The disjointness is load-bearing rather than tidy: it is what makes §8's
// role separation structural, so a node id can never be found in the mesh
// directory.
var idLabel = []byte("karst-relay-id-v1")

// RelayID is SHA-256("karst-relay-id-v1" ‖ identity_pk) — §5.2.
//
// Derived rather than configured, for the reason the roster derives node ids:
// an operator-written id would make a silent mismatch a typo away, and
// `karstd` recomputes this and rejects the netmap when the two disagree.
func RelayID(identityPK []byte) []byte {
	h := sha256.New()
	h.Write(idLabel)
	h.Write(identityPK)
	return h.Sum(nil)
}

// Entry is one relay as an operator writes it.
//
// There is no `relay_id` field, deliberately: see [RelayID].
type Entry struct {
	// Address is where to dial, as IP:port.
	//
	// An address literal, not a DNS name — `karstd` parses this with Rust's
	// `SocketAddr`, which does not resolve names. `TLSServerName` is the
	// separate field that carries the name, which is why the two exist.
	Address string `json:"address"`

	// TLSServerName is the SNI name and the name the certificate must match.
	//
	// It is not what authenticates the relay. §4.2 pins `IdentityKey` for
	// that; this only has to get the TLS session established.
	TLSServerName string `json:"tls_server_name"`

	// IdentityKey is the relay's ML-DSA-87 public key, base64.
	//
	// `karst-relay pubkey` prints exactly this.
	IdentityKey string `json:"identity_key"`

	// Region this relay serves — §8, §9. Empty means [DefaultRegion].
	Region string `json:"region"`
}

type document struct {
	Relays []Entry `json:"relays"`
}

// Compile validates one API-supplied relay entry through the exact same path
// the startup registry uses. The derived relay ID is never caller supplied.
func Compile(entry Entry) (*proto.KarstRelay, error) { return entry.compile() }

// Load reads and validates a registry file.
func Load(path string) ([]*proto.KarstRelay, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("relay registry: %w", err)
	}
	relays, err := Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("relay registry %s: %w", path, err)
	}
	return relays, nil
}

// Parse validates a registry document and returns the netmap entries.
//
// Every check here mirrors one in `karstd`'s `Relay::from_wire`, so a file
// this accepts is one every node accepts. Where the two could drift they are
// pinned together by a shared vector — see `TestRelayRegistryVector`.
func Parse(raw []byte) ([]*proto.KarstRelay, error) {
	var doc document
	dec := json.NewDecoder(bytes.NewReader(raw))
	// A misspelled field would otherwise be dropped in silence, leaving a
	// relay entry that is valid, wrong, and pinned to nothing an operator
	// wrote. `deny_unknown_fields` on the Rust configuration types makes the
	// same call for the same reason.
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}

	if len(doc.Relays) == 0 {
		// An operator who configured a registry meant to publish a relay.
		// Starting with none would hand every node an empty registry, which is
		// precisely the failure this package exists to end — and it would look
		// identical to not having configured one at all.
		return nil, fmt.Errorf("no relays; a registry that publishes nothing leaves every node unable to relay")
	}

	seen := make(map[string]int, len(doc.Relays))
	out := make([]*proto.KarstRelay, 0, len(doc.Relays))
	for i := range doc.Relays {
		relay, err := doc.Relays[i].compile()
		if err != nil {
			return nil, fmt.Errorf("relay %d: %w", i, err)
		}
		// Two entries with one key are two names for one relay: they derive
		// the same relay_id, so a node choosing between them would be choosing
		// between duplicates of a single destination while believing it had a
		// fallback.
		if first, dup := seen[string(relay.RelayId)]; dup {
			return nil, fmt.Errorf("relay %d repeats the identity key of relay %d", i, first)
		}
		seen[string(relay.RelayId)] = i
		out = append(out, relay)
	}
	return out, nil
}

func (e Entry) compile() (*proto.KarstRelay, error) {
	if _, err := netip.ParseAddrPort(e.Address); err != nil {
		// Named rather than paraphrased: the usual mistake is a DNS name, and
		// an operator who wrote one needs to be told that this field cannot
		// hold one rather than that it is "invalid".
		return nil, fmt.Errorf("address %q is not IP:port (a DNS name belongs in tls_server_name)", e.Address)
	}
	if err := checkServerName(e.TLSServerName); err != nil {
		return nil, err
	}

	key, err := base64.StdEncoding.DecodeString(e.IdentityKey)
	if err != nil {
		return nil, fmt.Errorf("identity_key is not base64: %w", err)
	}
	if len(key) != IdentityKeySize {
		return nil, fmt.Errorf("identity_key is %d bytes, want %d (an ML-DSA-87 public key, as `karst-relay pubkey` prints)",
			len(key), IdentityKeySize)
	}

	region := e.Region
	if region == "" {
		region = DefaultRegion
	}

	return &proto.KarstRelay{
		Address:       e.Address,
		TlsServerName: e.TLSServerName,
		RelayId:       RelayID(key),
		IdentityKey:   key,
		Region:        region,
	}, nil
}

// checkServerName mirrors the check in bins/karstd/src/netmap.rs.
func checkServerName(name string) error {
	if name == "" {
		return fmt.Errorf("tls_server_name is empty")
	}
	for _, r := range name {
		if r > 127 {
			return fmt.Errorf("tls_server_name %q is not ASCII", name)
		}
	}
	if strings.ContainsAny(name, " \t\r\n\v\f") {
		return fmt.Errorf("tls_server_name %q contains whitespace", name)
	}
	return nil
}
