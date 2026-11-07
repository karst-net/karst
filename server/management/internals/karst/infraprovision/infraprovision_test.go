// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package infraprovision

import "testing"

func TestTLSServerNameForIsDeterministicAndSuffixScoped(t *testing.T) {
	a := TLSServerNameFor("alloc-1", "token-a", "aws.karst.internal")
	b := TLSServerNameFor("alloc-1", "token-a", "aws.karst.internal")
	if a != b {
		t.Fatalf("got %q and %q, want the same input to derive the same label every time", a, b)
	}
	if got := TLSServerNameFor("alloc-1", "token-a", "nomad.karst.internal"); got == a {
		t.Fatalf("got %q for both suffixes, want the suffix to keep the two drivers' labels distinct", got)
	}
	if got := TLSServerNameFor("alloc-1", "token-b", "aws.karst.internal"); got == a {
		t.Fatalf("got %q for both tokens, want a different token to derive a different label", got)
	}
}

// TestTLSServerNameForMatchesTheAWSRustDerivation locks in the exact
// byte-for-byte formula (SHA-256(token), first 6 bytes, lowercase hex)
// bins/karst-scaler-aws's own bundle.rs derives -- both actuators' EC2
// instances are looked up by this same tag value, so a change here that
// silently drifted from the Rust side would break that lookup for every
// AWS-actuated relay, not just newly created ones.
func TestTLSServerNameForMatchesTheAWSRustDerivation(t *testing.T) {
	got := TLSServerNameFor("alloc-xyz", "s3cr3t-token", "aws.karst.internal")
	const want = "alloc-xyz-fb07916a0e7d.aws.karst.internal"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}
