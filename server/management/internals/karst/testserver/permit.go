// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sync"

	"github.com/netbirdio/netbird/management/internals/karst/compliance"
	"github.com/netbirdio/netbird/management/internals/karst/control"
	"github.com/netbirdio/netbird/management/internals/karst/policy"
)

// Opt-in wire-test fixture for #363's permit protocol, mirroring
// complianceFixture's own shape and reusing its Store rather than a second
// one over the same table -- `--compliance-permit` requires `--compliance`
// already enabled, since a permit over no ingested evidence is nothing to
// test. Uses the production PermitHandler; the dynamic draft/revision this
// exposes over the admin control surface is a test fixture only, deliberately
// kept separate from the real persisted admin policy-write API
// (policy.ComplianceDraftStore, PUT /karst/v1/compliance/draft -- #363 PR5).
// This binary's account manager is a stub (no real database, no
// authentication middleware, no permissions.Manager -- see this file's
// surrounding doc comments), so it cannot host that real, authenticated API;
// this fixture exists to drive the control-channel timing test
// (bins/karstd/tests/control.rs's compliance_permit_issuance_enforcement_and_
// revocation_bound_are_real_end_to_end), which the real API already has its
// own, separate handler-level tests for.
type permitFixture struct {
	mu       sync.Mutex
	draft    policy.ComplianceDraft
	revision string
	handler  *control.PermitHandler
}

func installPermitFixture(r *router) error {
	enabled := false
	for _, arg := range os.Args[1:] {
		if arg == "--compliance-permit" {
			enabled = true
		}
	}
	if !enabled {
		return nil
	}
	if r.compliance == nil {
		return errors.New("--compliance-permit requires --compliance")
	}
	f := &permitFixture{revision: control.UnconfiguredComplianceRevision}
	f.handler = &control.PermitHandler{
		Store: r.compliance.store,
		Peers: r.account,
		Draft: f.currentDraft,
	}
	r.permit = f
	r.netmap.CompliancePermit = true
	r.netmap.CompliancePolicyRevision = f.currentRevision
	return nil
}

func (f *permitFixture) currentDraft(_ context.Context, _ string) (policy.ComplianceDraft, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.draft.TenantID == "" {
		// Nothing configured yet -- PermitHandler's own nil-vs-empty-TenantID
		// convention (see its Draft field doc comment) means this is read as
		// "unconfigured," not an error.
		return policy.ComplianceDraft{}, "", nil
	}
	return f.draft, f.revision, nil
}

func (f *permitFixture) currentRevision(_ context.Context, _ string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.revision, nil
}

// permitDraftRequest is the admin wire shape for POST /permit-draft. Kept
// deliberately narrow -- only what the end-to-end test needs to construct:
// client-version requirements (always "collected" cross-platform, unlike OS
// version collection, which keeps the fixture's behavior identical on every
// CI runner) and plain selector/protocol/port-range resources.
type permitDraftRequest struct {
	TenantID        string                         `json:"tenant_id"`
	Revision        string                         `json:"revision"`
	RequirementSets map[string][]permitRequirement `json:"requirement_sets"`
	Guardrails      []permitGuardrail              `json:"guardrails"`
	Remediation     []permitResource               `json:"remediation"`
}
type permitRequirement struct {
	ID             string `json:"id"`
	MinimumVersion string `json:"minimum_version"`
}
type permitResource struct {
	Selector string `json:"selector"`
	Protocol string `json:"protocol"`
	First    uint16 `json:"first"`
	Last     uint16 `json:"last"`
}
type permitGuardrail struct {
	ID              string         `json:"id"`
	Resource        permitResource `json:"resource"`
	RequirementSets []string       `json:"requirement_sets"`
}

// serveDraft handles POST /permit-draft. Explicitly enabled fixture control
// listener only, never a production API -- same disclaimer `serveControl`'s
// other admin routes already carry.
func (f *permitFixture) serveDraft(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var body permitDraftRequest
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		http.Error(w, fmt.Sprintf("decode: %v", err), http.StatusBadRequest)
		return
	}
	sets := make(map[string][]compliance.Requirement, len(body.RequirementSets))
	for id, reqs := range body.RequirementSets {
		set := make([]compliance.Requirement, 0, len(reqs))
		for _, r := range reqs {
			set = append(set, compliance.Requirement{
				ID:             r.ID,
				Kind:           compliance.MinimumClientVersion,
				MinimumVersion: r.MinimumVersion,
				Provenance:     compliance.SelfReported,
			})
		}
		sets[id] = set
	}
	guardrails := make([]policy.ComplianceGuardrail, 0, len(body.Guardrails))
	for _, g := range body.Guardrails {
		guardrails = append(guardrails, policy.ComplianceGuardrail{
			ID: g.ID,
			Resource: policy.ComplianceResource{
				Selector: g.Resource.Selector,
				Protocol: g.Resource.Protocol,
				Ports:    policy.PortRange{First: g.Resource.First, Last: g.Resource.Last},
			},
			RequirementSets: g.RequirementSets,
		})
	}
	remediation := make([]policy.ComplianceResource, 0, len(body.Remediation))
	for _, r := range body.Remediation {
		remediation = append(remediation, policy.ComplianceResource{
			Selector: r.Selector,
			Protocol: r.Protocol,
			Ports:    policy.PortRange{First: r.First, Last: r.Last},
		})
	}
	draft := policy.ComplianceDraft{
		TenantID:        body.TenantID,
		RequirementSets: sets,
		Guardrails:      guardrails,
		Remediation:     remediation,
	}
	f.mu.Lock()
	f.draft, f.revision = draft, body.Revision
	f.mu.Unlock()
	fmt.Fprintln(w, "ok")
}
