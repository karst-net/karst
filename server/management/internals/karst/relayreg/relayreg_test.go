// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package relayreg

import (
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func key(seed byte) []byte {
	out := make([]byte, IdentityKeySize)
	for i := range out {
		out[i] = seed + byte(i%251)
	}
	return out
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// doc builds a one-relay registry with the given entry body spliced in.
func doc(body string) []byte {
	return []byte(`{"relays":[{` + body + `}]}`)
}

func goodEntry() string {
	return `"address":"203.0.113.7:443","tls_server_name":"relay.example.com","identity_key":"` +
		b64(key(1)) + `"`
}

func TestAValidRegistryCompilesToNetmapEntries(t *testing.T) {
	relays, err := Parse(doc(goodEntry()))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(relays) != 1 {
		t.Fatalf("want one relay, got %d", len(relays))
	}
	r := relays[0]
	if r.GetAddress() != "203.0.113.7:443" {
		t.Fatalf("address %q", r.GetAddress())
	}
	if r.GetTlsServerName() != "relay.example.com" {
		t.Fatalf("tls_server_name %q", r.GetTlsServerName())
	}
	if len(r.GetIdentityKey()) != IdentityKeySize {
		t.Fatalf("identity key is %d bytes", len(r.GetIdentityKey()))
	}
}

func TestTheRelayIDIsDerivedAndNotConfigurable(t *testing.T) {
	// §5.2 defines relay_id as a digest of the pinned identity key, and karstd
	// recomputes it while decoding the netmap. An operator-written id would
	// make a silent mismatch a typo away — and that mismatch fails the whole
	// netmap, not just the relay.
	relays, err := Parse(doc(goodEntry()))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := RelayID(key(1))
	if hex.EncodeToString(relays[0].GetRelayId()) != hex.EncodeToString(want) {
		t.Fatalf("relay_id is not the digest of the identity key")
	}

	// And the field cannot be supplied: an operator who writes one is told,
	// rather than having it quietly ignored while they believe it is in force.
	if _, err := Parse(doc(goodEntry() + `,"relay_id":"00"`)); err == nil {
		t.Fatal("a hand-written relay_id was accepted")
	}
}

func TestTheDerivationMatchesTheSpecDigest(t *testing.T) {
	// Pinned to the literal construction in ponor-v1.md §5.2 rather than to
	// this package's own helper, so a changed label is caught here and not by
	// every node in a deployment failing to parse its netmap.
	got := hex.EncodeToString(RelayID(key(1)))
	if len(got) != 64 {
		t.Fatalf("relay id is %d hex chars, want 64", len(got))
	}
	// SHA-256("karst-relay-id-v1" ‖ key(1)), computed outside this codebase.
	// A constant rather than a second call to the same helper: recomputing it
	// here with crypto/sha256 would agree with a changed domain label, which is
	// the mistake most worth catching.
	const want = "1afc82c36fd8902bb0eddd09fddd346465c2de4577ff827c3dfc96c89ae92335"
	if got != want {
		t.Fatalf("relay id %s, want %s — the domain label or the digest changed, "+
			"and karstd derives this independently", got, want)
	}
}

func TestAnEmptiregistryIsRefused(t *testing.T) {
	// This is the failure the package exists to end: a server that publishes
	// no relay hands every node an empty registry, and relaying silently never
	// happens. An operator who wrote a registry file meant to publish one.
	if _, err := Parse([]byte(`{"relays":[]}`)); err == nil {
		t.Fatal("an empty registry was accepted")
	}
	if _, err := Parse([]byte(`{}`)); err == nil {
		t.Fatal("a registry with no relays key was accepted")
	}
}

func TestADNSNameInAddressIsRefusedWithTheReason(t *testing.T) {
	// karstd parses `address` with Rust's SocketAddr, which does not resolve
	// names. Accepting one here would produce a netmap every node rejects —
	// and the whole netmap, not just this entry.
	_, err := Parse(doc(`"address":"relay.example.com:443","tls_server_name":"relay.example.com","identity_key":"` +
		b64(key(1)) + `"`))
	if err == nil {
		t.Fatal("a DNS name was accepted as an address")
	}
	if !strings.Contains(err.Error(), "tls_server_name") {
		t.Fatalf("the error does not say where a name belongs: %v", err)
	}
}

func TestAnIdentityKeyOfTheWrongLengthIsRefused(t *testing.T) {
	// karstd requires exactly an ML-DSA-65 public key. The likely mistake is
	// pasting a node's key or a truncated line, both of which are valid base64.
	for _, size := range []int{0, 32, IdentityKeySize - 1, IdentityKeySize + 1} {
		body := `"address":"203.0.113.7:443","tls_server_name":"r","identity_key":"` +
			b64(make([]byte, size)) + `"`
		if _, err := Parse(doc(body)); err == nil {
			t.Fatalf("a %d-byte identity key was accepted", size)
		}
	}
	if _, err := Parse(doc(`"address":"203.0.113.7:443","tls_server_name":"r","identity_key":"not base64!"`)); err == nil {
		t.Fatal("a non-base64 identity key was accepted")
	}
}

func TestAnUnusableServerNameIsRefused(t *testing.T) {
	// Mirrors bins/karstd/src/netmap.rs: empty, non-ASCII, or containing
	// whitespace. A name karstd rejects is a netmap no node can apply.
	for _, name := range []string{"", "relay example.com", "relay\t.com", "relay\n", "rëlay.example.com"} {
		body := `"address":"203.0.113.7:443","tls_server_name":` +
			mustQuote(name) + `,"identity_key":"` + b64(key(1)) + `"`
		if _, err := Parse(doc(body)); err == nil {
			t.Fatalf("server name %q was accepted", name)
		}
	}
}

func TestTheRegionDefaultsToTheRelaysOwnDefault(t *testing.T) {
	// §8 refuses to mesh across regions, so a registry that defaulted
	// differently from bins/karst-relay/src/config.rs would produce a mesh
	// that silently never forms between two relays nobody configured.
	relays, err := Parse(doc(goodEntry()))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if relays[0].GetRegion() != DefaultRegion {
		t.Fatalf("region %q, want %q", relays[0].GetRegion(), DefaultRegion)
	}
	if DefaultRegion != "default" {
		t.Fatalf("DefaultRegion is %q; bins/karst-relay/src/config.rs defaults to \"default\"",
			DefaultRegion)
	}
}

func TestARepeatedIdentityKeyIsRefused(t *testing.T) {
	// Two entries with one key derive one relay_id: a node choosing between
	// them would be choosing between two names for a single destination while
	// believing it had a fallback.
	raw := []byte(`{"relays":[{` + goodEntry() + `},{"address":"198.51.100.9:443",` +
		`"tls_server_name":"other.example.com","identity_key":"` + b64(key(1)) + `"}]}`)
	if _, err := Parse(raw); err == nil {
		t.Fatal("two entries with the same identity key were accepted")
	}
}

func TestAMisspelledFieldIsRefusedRatherThanDropped(t *testing.T) {
	// Go's JSON decoder ignores unknown fields by default, which would leave a
	// relay pinned to a region nobody configured while the operator reads their
	// own file and sees one. The Rust configuration types make the same call
	// with `deny_unknown_fields`.
	body := goodEntry() + `,"regoin":"eu"`
	if _, err := Parse(doc(body)); err == nil {
		t.Fatal("a misspelled field was silently dropped")
	}
}

func TestLoadNamesTheFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "relays.json")
	if err := os.WriteFile(path, doc(goodEntry()), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	relays, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(relays) != 1 {
		t.Fatalf("want one relay, got %d", len(relays))
	}

	// A bad file names itself: this error is what an operator sees at startup,
	// and "invalid character" with no path is a poor thing to be told.
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte(`{"relays":[{`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := Load(bad); err == nil || !strings.Contains(err.Error(), "bad.json") {
		t.Fatalf("the error does not name the file: %v", err)
	}
}

func mustQuote(s string) string {
	out := `"`
	for _, r := range s {
		switch r {
		case '"':
			out += `\"`
		case '\\':
			out += `\\`
		case '\t':
			out += `\t`
		case '\n':
			out += `\n`
		default:
			out += string(r)
		}
	}
	return out + `"`
}
