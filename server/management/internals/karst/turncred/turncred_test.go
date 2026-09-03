// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package turncred

import (
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	hmac "github.com/netbirdio/netbird/shared/relay/auth/hmac"
)

func doc(body string) []byte {
	return []byte(`{"turn":[{` + body + `}]}`)
}

func TestAValidRegistryParsesAndDefaultsRegion(t *testing.T) {
	entries, err := Parse(doc(`"uri":"turn:turn.example.com:3478"`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("want one entry, got %d", len(entries))
	}
	if entries[0].URI != "turn:turn.example.com:3478" {
		t.Fatalf("uri %q", entries[0].URI)
	}
	if entries[0].Region != DefaultRegion {
		t.Fatalf("region %q, want default", entries[0].Region)
	}
}

func TestTurnsSchemeAlsoParses(t *testing.T) {
	entries, err := Parse(doc(`"uri":"turns:turn.example.com:5349","region":"eu"`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if entries[0].Region != "eu" {
		t.Fatalf("region %q", entries[0].Region)
	}
}

func TestADerpSchemeIsRejected(t *testing.T) {
	// The same discipline ADR-0008 requires of the relay registry — this
	// registry must not become a way to configure an arbitrary relay under a
	// different name.
	_, err := Parse(doc(`"uri":"derp://derp.example.com"`))
	if err == nil {
		t.Fatal("want an error, got nil")
	}
	if !strings.Contains(err.Error(), "turn: or turns:") {
		t.Fatalf("error %q does not name the expected schemes", err)
	}
}

func TestABareHostWithNoSchemeIsRejected(t *testing.T) {
	_, err := Parse(doc(`"uri":"turn.example.com:3478"`))
	if err == nil {
		t.Fatal("want an error, got nil")
	}
}

func TestAnEmptyRegistryIsRejected(t *testing.T) {
	_, err := Parse([]byte(`{"turn":[]}`))
	if err == nil {
		t.Fatal("want an error, got nil")
	}
}

func TestAnUnknownFieldIsRejected(t *testing.T) {
	_, err := Parse(doc(`"uri":"turn:turn.example.com:3478","protocol":"udp"`))
	if err == nil {
		t.Fatal("want an error for the unrecognized protocol field, got nil")
	}
}

func TestMintedCredentialsIndependentlyVerify(t *testing.T) {
	m, err := NewMinter("s3cret", time.Hour)
	if err != nil {
		t.Fatalf("new minter: %v", err)
	}
	cred, err := m.Mint()
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	// Verify against a hand-built TimedHMAC, independent of Minter's own
	// construction, to prove the minted credential is genuinely the standard
	// TURN-REST scheme and not merely internally self-consistent.
	verifier := hmac.NewTimedHMAC("s3cret", time.Hour)
	tok := hmac.Token{Payload: cred.Username, Signature: cred.Password}
	if err := verifier.Validate(sha1.New, tok); err != nil {
		t.Fatalf("credential does not independently verify: %v", err)
	}
}

func TestTwoMintsASecondApartBothVerify(t *testing.T) {
	m, err := NewMinter("s3cret", time.Hour)
	if err != nil {
		t.Fatalf("new minter: %v", err)
	}
	verifier := hmac.NewTimedHMAC("s3cret", time.Hour)

	first, err := m.Mint()
	if err != nil {
		t.Fatalf("mint 1: %v", err)
	}
	time.Sleep(1100 * time.Millisecond)
	second, err := m.Mint()
	if err != nil {
		t.Fatalf("mint 2: %v", err)
	}

	for _, cred := range []Credential{first, second} {
		tok := hmac.Token{Payload: cred.Username, Signature: cred.Password}
		if err := verifier.Validate(sha1.New, tok); err != nil {
			t.Fatalf("credential does not verify: %v", err)
		}
	}
}

func TestExpiresAtMatchesTheConfiguredTTL(t *testing.T) {
	ttl := 30 * time.Minute
	m, err := NewMinter("s3cret", ttl)
	if err != nil {
		t.Fatalf("new minter: %v", err)
	}
	before := time.Now()
	cred, err := m.Mint()
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	after := time.Now()

	// The TURN-REST scheme's payload is a whole-second unix timestamp, so
	// ExpiresAt is second-truncated — compare at that resolution rather than
	// against before/after's own sub-second precision.
	want := before.Add(ttl).Unix()
	max := after.Add(ttl).Unix()
	if got := cred.ExpiresAt.Unix(); got < want || got > max {
		t.Fatalf("expires_at unix %d not within [%d, %d]", got, want, max)
	}
}

func TestACredentialNeverRendersItsPassword(t *testing.T) {
	m, err := NewMinter("s3cret-password-marker", time.Hour)
	if err != nil {
		t.Fatalf("new minter: %v", err)
	}
	cred, err := m.Mint()
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if cred.Password == "" {
		t.Fatal("test is vacuous: minted password is empty")
	}

	renderings := []string{
		cred.String(),
		cred.GoString(),
		fmt.Sprintf("%x", cred),
		fmt.Sprintf("%+v", cred),
	}
	mustMarshalText, err := cred.MarshalText()
	if err != nil {
		t.Fatalf("marshal text: %v", err)
	}
	renderings = append(renderings, string(mustMarshalText))

	jsonBytes, err := json.Marshal(cred)
	if err != nil {
		t.Fatalf("marshal json: %v", err)
	}
	renderings = append(renderings, string(jsonBytes))

	for _, r := range renderings {
		if strings.Contains(r, cred.Password) {
			t.Fatalf("rendering %q leaks the password", r)
		}
	}
}

func TestNetmapEntriesIsNilWhenTurnIsNotConfigured(t *testing.T) {
	entries, err := NetmapEntries(nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if entries != nil {
		t.Fatalf("want nil, got %d entries", len(entries))
	}

	m, err := NewMinter("s3cret", time.Hour)
	if err != nil {
		t.Fatalf("new minter: %v", err)
	}
	entries, err = NetmapEntries(nil, m)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if entries != nil {
		t.Fatalf("want nil for an empty server list even with a minter, got %d entries", len(entries))
	}
}

func TestNetmapEntriesStampsOneCredentialOntoEveryServer(t *testing.T) {
	m, err := NewMinter("s3cret", time.Hour)
	if err != nil {
		t.Fatalf("new minter: %v", err)
	}
	servers := []Entry{
		{URI: "turn:a.example.com:3478", Region: "us"},
		{URI: "turn:b.example.com:3478", Region: "eu"},
	}
	entries, err := NetmapEntries(servers, m)
	if err != nil {
		t.Fatalf("netmap entries: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("want 2 entries, got %d", len(entries))
	}
	if entries[0].Username != entries[1].Username || entries[0].Password != entries[1].Password {
		t.Fatal("every server must share the one minted credential")
	}
	if entries[0].Uri != servers[0].URI || entries[1].Uri != servers[1].URI {
		t.Fatal("uri not carried through")
	}
	if entries[0].Region != "us" || entries[1].Region != "eu" {
		t.Fatal("region not carried through")
	}
}
