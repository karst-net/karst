// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package compliance_test

import (
	"reflect"
	"testing"
	"time"

	"github.com/netbirdio/netbird/management/internals/karst/compliance"
)

var now = time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
var subject = compliance.Subject{TenantID: "tenant-a", DeviceID: "device-a"}

func clientRequirement() compliance.Requirement {
	return compliance.Requirement{ID: "client", Kind: compliance.MinimumClientVersion, MinimumVersion: "v0.1.0", Provenance: compliance.SelfReported}
}
func evidence() compliance.Evidence {
	return compliance.Evidence{Subject: subject, ReceivedAt: now.Add(-time.Minute), Provenance: compliance.SelfReported, Platform: compliance.MacOS,
		ClientVersion: compliance.Observation{Status: compliance.Collected, Version: "v0.1.0"},
		OSVersion:     compliance.Observation{Status: compliance.Collected, Version: "15.1"}}
}

func TestEvidenceStates(t *testing.T) {
	tests := []struct {
		name   string
		change func(*compliance.Evidence)
		state  compliance.State
		reason compliance.Reason
	}{
		{"passes", func(*compliance.Evidence) {}, compliance.Compliant, compliance.Passed},
		{"below minimum", func(e *compliance.Evidence) { e.ClientVersion.Version = "0.0.9" }, compliance.Noncompliant, compliance.BelowMinimum},
		{"absent observation", func(e *compliance.Evidence) { e.ClientVersion = compliance.Observation{} }, compliance.Unknown, compliance.MissingValue},
		{"missing collected value", func(e *compliance.Evidence) { e.ClientVersion.Version = "" }, compliance.Unknown, compliance.MissingValue},
		{"collector unsupported", func(e *compliance.Evidence) {
			e.ClientVersion = compliance.Observation{Status: compliance.NotSupported}
		}, compliance.Unsupported, compliance.UnsupportedObservation},
		{"collector failed", func(e *compliance.Evidence) {
			e.ClientVersion = compliance.Observation{Status: compliance.CollectionError}
		}, compliance.EvaluationError, compliance.CollectionFailed},
		{"bad version", func(e *compliance.Evidence) { e.ClientVersion.Version = "dev" }, compliance.EvaluationError, compliance.InvalidVersion},
		{"unknown status", func(e *compliance.Evidence) { e.ClientVersion = compliance.Observation{Status: "future-status"} }, compliance.EvaluationError, compliance.MalformedObservation},
		{"value without collected status", func(e *compliance.Evidence) { e.ClientVersion.Status = "" }, compliance.EvaluationError, compliance.MalformedObservation},
		{"error with cached value", func(e *compliance.Evidence) { e.ClientVersion.Status = compliance.CollectionError }, compliance.EvaluationError, compliance.MalformedObservation},
		{"different tenant", func(e *compliance.Evidence) { e.Subject.TenantID = "tenant-b" }, compliance.EvaluationError, compliance.IdentityMismatch},
		{"different device", func(e *compliance.Evidence) { e.Subject.DeviceID = "device-b" }, compliance.EvaluationError, compliance.IdentityMismatch},
		{"empty identity", func(e *compliance.Evidence) { e.Subject = compliance.Subject{} }, compliance.EvaluationError, compliance.IdentityMismatch},
		{"missing receipt", func(e *compliance.Evidence) { e.ReceivedAt = time.Time{} }, compliance.EvaluationError, compliance.InvalidTime},
		{"future receipt", func(e *compliance.Evidence) { e.ReceivedAt = now.Add(time.Nanosecond) }, compliance.EvaluationError, compliance.InvalidTime},
		{"wrong provenance", func(e *compliance.Evidence) { e.Provenance = "provider-verified" }, compliance.Unsupported, compliance.ProvenanceMismatch},
		{"missing provenance", func(e *compliance.Evidence) { e.Provenance = "" }, compliance.Unsupported, compliance.ProvenanceMismatch},
		{"unsupported platform", func(e *compliance.Evidence) { e.Platform = "ios" }, compliance.Unsupported, compliance.UnsupportedPlatform},
		{"expiry boundary", func(e *compliance.Evidence) { e.ReceivedAt = now.Add(-compliance.EvidenceLifetime) }, compliance.Stale, compliance.EvidenceExpired},
		{"after expiry", func(e *compliance.Evidence) { e.ReceivedAt = now.Add(-compliance.EvidenceLifetime - time.Nanosecond) }, compliance.Stale, compliance.EvidenceExpired},
		{"before expiry", func(e *compliance.Evidence) { e.ReceivedAt = now.Add(-compliance.EvidenceLifetime + time.Nanosecond) }, compliance.Compliant, compliance.Passed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := evidence()
			tt.change(&e)
			got, err := compliance.Evaluate([]compliance.Requirement{clientRequirement()}, subject, &e, now)
			if err != nil {
				t.Fatal(err)
			}
			if len(got.Results) != 1 || got.Results[0].State != tt.state || got.Results[0].Reason != tt.reason {
				t.Fatalf("result: %+v", got)
			}
			if got.Satisfied() != (tt.state == compliance.Compliant) {
				t.Fatalf("satisfied: %+v", got)
			}
			if got.Satisfied() {
				if !got.ValidUntil.Equal(e.ReceivedAt.Add(compliance.EvidenceLifetime)) {
					t.Fatalf("deadline: %s", got.ValidUntil)
				}
			} else if !got.ValidUntil.IsZero() {
				t.Fatalf("failure must not carry passing deadline: %+v", got)
			}
		})
	}
	got, err := compliance.Evaluate([]compliance.Requirement{clientRequirement()}, subject, nil, now)
	if err != nil || got.Satisfied() || got.Results[0].State != compliance.Unknown || got.Results[0].Reason != compliance.MissingEvidence {
		t.Fatalf("nil evidence: %+v %v", got, err)
	}
}

func TestRequirementValidationFailsClosed(t *testing.T) {
	tests := []struct {
		name   string
		change func(*compliance.Requirement)
	}{
		{"missing ID", func(r *compliance.Requirement) { r.ID = "" }},
		{"unknown check", func(r *compliance.Requirement) { r.Kind = "disk-encryption" }},
		{"unknown trust", func(r *compliance.Requirement) { r.Provenance = "verified-mdm" }},
		{"missing trust", func(r *compliance.Requirement) { r.Provenance = "" }},
		{"malformed minimum", func(r *compliance.Requirement) { r.MinimumVersion = "latest" }},
		{"client scoped to OS", func(r *compliance.Requirement) { r.Platform = compliance.MacOS }},
		{"client scoped to distribution", func(r *compliance.Requirement) { r.Distribution = "ubuntu" }},
		{"OS missing platform", func(r *compliance.Requirement) { r.Kind = compliance.MinimumOSVersion }},
		{"unknown distribution", func(r *compliance.Requirement) {
			r.Kind = compliance.MinimumOSVersion
			r.Platform = compliance.Linux
			r.Distribution = "custom"
		}},
		{"distribution on macOS", func(r *compliance.Requirement) {
			r.Kind = compliance.MinimumOSVersion
			r.Platform = compliance.MacOS
			r.Distribution = "ubuntu"
		}},
		{"invalid OS release", func(r *compliance.Requirement) {
			r.Kind = compliance.MinimumOSVersion
			r.Platform = compliance.Windows
			r.MinimumVersion = "Windows 11"
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := clientRequirement()
			tt.change(&r)
			if r.Validate() == nil {
				t.Fatal("invalid requirement accepted")
			}
			e := evidence()
			got, err := compliance.Evaluate([]compliance.Requirement{r}, subject, &e, now)
			if err == nil || got.Satisfied() || !got.ValidUntil.IsZero() {
				t.Fatalf("invalid configuration: %+v %v", got, err)
			}
		})
	}
	e := evidence()
	for _, rs := range [][]compliance.Requirement{nil, {}, {clientRequirement(), clientRequirement()}} {
		got, err := compliance.Evaluate(rs, subject, &e, now)
		if err == nil || got.Satisfied() {
			t.Fatalf("empty/duplicate accepted: %+v %v", got, err)
		}
	}
	for _, s := range []compliance.Subject{{}, {TenantID: subject.TenantID}, {DeviceID: subject.DeviceID}} {
		if _, err := compliance.Evaluate([]compliance.Requirement{clientRequirement()}, s, &e, now); err == nil {
			t.Fatal("incomplete identity accepted")
		}
	}
	if _, err := compliance.Evaluate([]compliance.Requirement{clientRequirement()}, subject, &e, time.Time{}); err == nil {
		t.Fatal("zero evaluation time accepted")
	}
	if (compliance.Evaluation{}).Satisfied() {
		t.Fatal("zero evaluation satisfied")
	}
}

func TestConjunctionRecoveryAndIsolation(t *testing.T) {
	rs := []compliance.Requirement{clientRequirement(), {ID: "os", Kind: compliance.MinimumOSVersion, MinimumVersion: "15.1", Platform: compliance.MacOS, Provenance: compliance.SelfReported}}
	a := evidence()
	original := a
	b := a
	b.Subject.DeviceID = "device-b"
	b.OSVersion.Version = "14.7"
	evaluate := func(e *compliance.Evidence, at time.Time) compliance.Evaluation {
		t.Helper()
		got, err := compliance.Evaluate(rs, e.Subject, e, at)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	good := evaluate(&a, now)
	bad := evaluate(&b, now)
	if !good.Satisfied() || bad.Satisfied() || len(bad.Results) != 2 || bad.Results[0].State != compliance.Compliant || bad.Results[1].State != compliance.Noncompliant {
		t.Fatalf("device isolation/conjunction: %+v %+v", good, bad)
	}
	if !reflect.DeepEqual(good, evaluate(&a, now)) || a != original {
		t.Fatal("evaluation is nondeterministic or mutated evidence")
	}
	expired := evaluate(&a, a.ReceivedAt.Add(compliance.EvidenceLifetime))
	if expired.Satisfied() || expired.Results[0].State != compliance.Stale || expired.Results[1].State != compliance.Stale {
		t.Fatalf("expiry: %+v", expired)
	}
	a.ReceivedAt = now
	a.OSVersion = compliance.Observation{Status: compliance.CollectionError}
	if evaluate(&a, now).Satisfied() {
		t.Fatal("new failed collection reused previous pass")
	}
	a.OSVersion = compliance.Observation{Status: compliance.Collected, Version: "15.2"}
	if !evaluate(&a, now).Satisfied() {
		t.Fatal("fresh passing evidence failed to recover")
	}
	for _, change := range []func(*compliance.Evidence){
		func(e *compliance.Evidence) { e.Platform = compliance.Windows },
		func(e *compliance.Evidence) { e.Distribution = "ubuntu" },
	} {
		e := evidence()
		change(&e)
		got := evaluate(&e, now)
		if got.Results[1].State != compliance.Unsupported || got.Satisfied() {
			t.Fatalf("OS mismatch: %+v", got)
		}
	}
}
