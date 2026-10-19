// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// Package compliance evaluates typed device evidence against requirements.
// It does not authenticate reports, issue permissions, or enforce traffic.
// Callers must obtain evidence identity, provenance and receipt time from a
// trusted ingestion path, never from fields asserted by the reporting client.
package compliance

import (
	"fmt"
	"time"
)

// EvidenceLifetime is measured from server receipt, never a client timestamp.
const EvidenceLifetime = 180 * time.Second

type State string

const (
	Compliant       State = "compliant"
	Noncompliant    State = "noncompliant"
	Unknown         State = "unknown"
	Unsupported     State = "unsupported"
	Stale           State = "stale"
	EvaluationError State = "evaluation-error"
)

type Kind string

const (
	MinimumClientVersion Kind = "minimum-client-version"
	MinimumOSVersion     Kind = "minimum-os-version"
)

type Platform string

const (
	Linux   Platform = "linux"
	MacOS   Platform = "darwin"
	Windows Platform = "windows"
)

type Provenance string

const SelfReported Provenance = "self-reported"

// Subject comes from the authenticated enrollment, not report payload IDs.
type Subject struct {
	TenantID string
	DeviceID string
}

// Requirement describes one mandatory comparison. OS requirements apply only
// to the named platform/distribution; a different platform does not satisfy it.
// Only SelfReported is implemented; verified provider evidence is not supported.
type Requirement struct {
	ID             string
	Kind           Kind
	MinimumVersion string
	Provenance     Provenance
	Platform       Platform
	Distribution   string // Linux distribution ID (ubuntu or debian); otherwise empty.
}

func (r Requirement) Validate() error {
	if r.ID == "" {
		return fmt.Errorf("compliance: requirement ID is required")
	}
	if r.Provenance != SelfReported {
		return fmt.Errorf("compliance: requirement %q has unsupported provenance", r.ID)
	}
	switch r.Kind {
	case MinimumClientVersion:
		if r.Platform != "" || r.Distribution != "" {
			return fmt.Errorf("compliance: client version requirement %q must not specify an OS", r.ID)
		}
		if _, err := clientVersion(r.MinimumVersion); err != nil {
			return fmt.Errorf("compliance: requirement %q: %w", r.ID, err)
		}
	case MinimumOSVersion:
		if !supportedOS(r.Platform, r.Distribution) {
			return fmt.Errorf("compliance: requirement %q has unsupported OS", r.ID)
		}
		if _, err := osVersion(r.Platform, r.Distribution, r.MinimumVersion); err != nil {
			return fmt.Errorf("compliance: requirement %q: %w", r.ID, err)
		}
	default:
		return fmt.Errorf("compliance: requirement %q has unsupported check", r.ID)
	}
	return nil
}

type ObservationStatus string

const (
	Collected       ObservationStatus = "collected"
	NotSupported    ObservationStatus = "unsupported"
	CollectionError ObservationStatus = "collection-error"
)

// Observation has a version only when Collected. A zero observation is missing.
// Error details are deliberately not returned in evaluation reasons.
type Observation struct {
	Status  ObservationStatus
	Version string
}

// Evidence is trusted ingestion output, not a wire report. ReceivedAt and
// Provenance must be assigned by ingestion after authentication/verification.
// A newer error report must replace previous evidence rather than preserving a
// passing observation. Replay protection and persistence belong to ingestion.
type Evidence struct {
	Subject       Subject
	ReceivedAt    time.Time
	Provenance    Provenance
	Platform      Platform
	Distribution  string
	ClientVersion Observation
	OSVersion     Observation
}

type Reason string

const (
	Passed                 Reason = "minimum-satisfied"
	BelowMinimum           Reason = "below-minimum"
	MissingEvidence        Reason = "missing-evidence"
	MissingValue           Reason = "missing-value"
	IdentityMismatch       Reason = "identity-mismatch"
	InvalidTime            Reason = "invalid-server-time"
	EvidenceExpired        Reason = "evidence-expired"
	ProvenanceMismatch     Reason = "provenance-mismatch"
	UnsupportedPlatform    Reason = "unsupported-platform"
	UnsupportedObservation Reason = "unsupported-observation"
	CollectionFailed       Reason = "collection-failed"
	MalformedObservation   Reason = "malformed-observation"
	InvalidVersion         Reason = "invalid-version"
)

type Result struct {
	RequirementID string
	State         State
	Reason        Reason
}

// Evaluation retains every requirement's result; no failure is hidden by a
// passing check. ValidUntil is set only when all checks pass. It is an evidence
// deadline, not a permission lease or an authorization decision.
type Evaluation struct {
	Results    []Result
	ValidUntil time.Time
}

func (e Evaluation) Satisfied() bool {
	if len(e.Results) == 0 {
		return false
	}
	for _, r := range e.Results {
		if r.State != Compliant {
			return false
		}
	}
	return true
}

// Evaluate is deterministic in now. Invalid requirements/subjects/time are
// errors; callers must deny rather than reuse a previous passing evaluation.
// Requirements must be a nonempty, fully resolved set with unique IDs.
func Evaluate(requirements []Requirement, subject Subject, evidence *Evidence, now time.Time) (Evaluation, error) {
	if subject.TenantID == "" || subject.DeviceID == "" {
		return Evaluation{}, fmt.Errorf("compliance: authenticated tenant and device are required")
	}
	if now.IsZero() {
		return Evaluation{}, fmt.Errorf("compliance: evaluation time is required")
	}
	if len(requirements) == 0 {
		return Evaluation{}, fmt.Errorf("compliance: requirements must not be empty")
	}
	ids := make(map[string]struct{}, len(requirements))
	for _, r := range requirements {
		if err := r.Validate(); err != nil {
			return Evaluation{}, err
		}
		if _, ok := ids[r.ID]; ok {
			return Evaluation{}, fmt.Errorf("compliance: duplicate requirement %q", r.ID)
		}
		ids[r.ID] = struct{}{}
	}
	evaluation := Evaluation{Results: make([]Result, 0, len(requirements))}
	for _, r := range requirements {
		state, reason := evaluate(r, subject, evidence, now)
		evaluation.Results = append(evaluation.Results, Result{RequirementID: r.ID, State: state, Reason: reason})
	}
	if evaluation.Satisfied() {
		evaluation.ValidUntil = evidence.ReceivedAt.Add(EvidenceLifetime)
	}
	return evaluation, nil
}

func evaluate(r Requirement, subject Subject, e *Evidence, now time.Time) (State, Reason) {
	if e == nil {
		return Unknown, MissingEvidence
	}
	if e.Subject != subject {
		return EvaluationError, IdentityMismatch
	}
	if e.ReceivedAt.IsZero() || e.ReceivedAt.After(now) {
		return EvaluationError, InvalidTime
	}
	if !now.Before(e.ReceivedAt.Add(EvidenceLifetime)) {
		return Stale, EvidenceExpired
	}
	if e.Provenance != r.Provenance {
		return Unsupported, ProvenanceMismatch
	}
	if !supportedPlatform(e.Platform) {
		return Unsupported, UnsupportedPlatform
	}
	o := e.ClientVersion
	if r.Kind == MinimumOSVersion {
		if e.Platform != r.Platform || e.Distribution != r.Distribution {
			return Unsupported, UnsupportedPlatform
		}
		o = e.OSVersion
	}
	if o.Status != Collected && o.Version != "" {
		return EvaluationError, MalformedObservation
	}
	switch o.Status {
	case "":
		return Unknown, MissingValue
	case NotSupported:
		return Unsupported, UnsupportedObservation
	case CollectionError:
		return EvaluationError, CollectionFailed
	case Collected:
		if o.Version == "" {
			return Unknown, MissingValue
		}
	default:
		return EvaluationError, MalformedObservation
	}
	comparison, err := compare(r, o.Version)
	if err != nil {
		return EvaluationError, InvalidVersion
	}
	if comparison < 0 {
		return Noncompliant, BelowMinimum
	}
	return Compliant, Passed
}

func supportedPlatform(p Platform) bool { return p == Linux || p == MacOS || p == Windows }
func supportedOS(p Platform, distribution string) bool {
	if p == Linux {
		return distribution == "ubuntu" || distribution == "debian"
	}
	return (p == MacOS || p == Windows) && distribution == ""
}
