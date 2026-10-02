// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

package karst

import (
	"strings"
	"testing"
)

// This wrapper does not reimplement validation — an invitation
// karstd::enrollment itself rejects must still be rejected here, mirroring
// crates/karst-embed-capi's own identically-named test for the C boundary.
func TestEnrollRejectsAMalformedInvitationWithoutEchoingIt(t *testing.T) {
	secret := "SECRET-DO-NOT-ECHO"
	err := Enroll("not-a-real-invitation-"+secret, "/nonexistent/config.toml", "/nonexistent/state")
	if err == nil {
		t.Fatal("a malformed invitation must be refused")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error echoed the credential: %v", err)
	}
}

func TestStartReportsAMissingConfigWithoutPanicking(t *testing.T) {
	_, err := Start("/nonexistent/karst-go-config.toml", "/nonexistent/karst-go.sock")
	if err == nil {
		t.Fatal("a missing config file must be refused")
	}
}
