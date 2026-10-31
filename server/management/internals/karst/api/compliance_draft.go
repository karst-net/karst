// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/netbirdio/netbird/management/internals/karst/compliance"
	karstpolicy "github.com/netbirdio/netbird/management/internals/karst/policy"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"

	"github.com/gorilla/mux"
)

func (h *handler) requireComplianceDraft(w http.ResponseWriter, r *http.Request) bool {
	if h.complianceDraft != nil {
		return true
	}
	util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "compliance draft store is not configured"), w)
	return false
}

// complianceRequirementDTO mirrors compliance.Requirement with a stable JSON
// shape -- the core type deliberately carries no json tags of its own (it is
// not a wire type), the same reason testserver/permit.go defines its own
// request DTOs rather than tagging policy.ComplianceDraft directly.
type complianceRequirementDTO struct {
	ID             string `json:"id"`
	Kind           string `json:"kind"`
	MinimumVersion string `json:"minimum_version"`
	Platform       string `json:"platform,omitempty"`
	Distribution   string `json:"distribution,omitempty"`
}

func (dto complianceRequirementDTO) toRequirement() compliance.Requirement {
	return compliance.Requirement{
		ID:             dto.ID,
		Kind:           compliance.Kind(dto.Kind),
		MinimumVersion: dto.MinimumVersion,
		Provenance:     compliance.SelfReported,
		Platform:       compliance.Platform(dto.Platform),
		Distribution:   dto.Distribution,
	}
}

func requirementDTO(r compliance.Requirement) complianceRequirementDTO {
	return complianceRequirementDTO{ID: r.ID, Kind: string(r.Kind), MinimumVersion: r.MinimumVersion, Platform: string(r.Platform), Distribution: r.Distribution}
}

type complianceResourceDTO struct {
	Selector string `json:"selector"`
	Protocol string `json:"protocol"`
	First    uint16 `json:"first"`
	Last     uint16 `json:"last"`
}

func (dto complianceResourceDTO) toResource() karstpolicy.ComplianceResource {
	return karstpolicy.ComplianceResource{Selector: dto.Selector, Protocol: dto.Protocol, Ports: karstpolicy.PortRange{First: dto.First, Last: dto.Last}}
}

func resourceDTO(r karstpolicy.ComplianceResource) complianceResourceDTO {
	return complianceResourceDTO{Selector: r.Selector, Protocol: r.Protocol, First: r.Ports.First, Last: r.Ports.Last}
}

type complianceGuardrailDTO struct {
	ID              string                `json:"id"`
	Resource        complianceResourceDTO `json:"resource"`
	RequirementSets []string              `json:"requirement_sets"`
}

func (dto complianceGuardrailDTO) toGuardrail() karstpolicy.ComplianceGuardrail {
	return karstpolicy.ComplianceGuardrail{ID: dto.ID, Resource: dto.Resource.toResource(), RequirementSets: dto.RequirementSets}
}

func guardrailDTO(g karstpolicy.ComplianceGuardrail) complianceGuardrailDTO {
	return complianceGuardrailDTO{ID: g.ID, Resource: resourceDTO(g.Resource), RequirementSets: g.RequirementSets}
}

// complianceDraftDTO is the wire shape for both the write request body and
// the read/preview/test responses. Tenant and revision are never part of the
// body: tenant comes from the authenticated user exactly as policyWrite never
// accepts an account ID, and revision is the If-Match version, not an
// admin-chosen string.
type complianceDraftDTO struct {
	RequirementSets map[string][]complianceRequirementDTO `json:"requirement_sets"`
	Guardrails      []complianceGuardrailDTO              `json:"guardrails"`
	Remediation     []complianceResourceDTO               `json:"remediation"`
}

func (dto complianceDraftDTO) toDraft(tenantID string) karstpolicy.ComplianceDraft {
	draft := karstpolicy.ComplianceDraft{TenantID: tenantID}
	if len(dto.RequirementSets) > 0 {
		draft.RequirementSets = make(map[string][]compliance.Requirement, len(dto.RequirementSets))
		for id, reqs := range dto.RequirementSets {
			converted := make([]compliance.Requirement, 0, len(reqs))
			for _, r := range reqs {
				converted = append(converted, r.toRequirement())
			}
			draft.RequirementSets[id] = converted
		}
	}
	for _, g := range dto.Guardrails {
		draft.Guardrails = append(draft.Guardrails, g.toGuardrail())
	}
	for _, r := range dto.Remediation {
		draft.Remediation = append(draft.Remediation, r.toResource())
	}
	return draft
}

func draftDTO(draft karstpolicy.ComplianceDraft) complianceDraftDTO {
	dto := complianceDraftDTO{}
	if len(draft.RequirementSets) > 0 {
		dto.RequirementSets = make(map[string][]complianceRequirementDTO, len(draft.RequirementSets))
		for id, reqs := range draft.RequirementSets {
			converted := make([]complianceRequirementDTO, 0, len(reqs))
			for _, r := range reqs {
				converted = append(converted, requirementDTO(r))
			}
			dto.RequirementSets[id] = converted
		}
	}
	for _, g := range draft.Guardrails {
		dto.Guardrails = append(dto.Guardrails, guardrailDTO(g))
	}
	for _, r := range draft.Remediation {
		dto.Remediation = append(dto.Remediation, resourceDTO(r))
	}
	return dto
}

// complianceDraftVersionResponse separates the public draft from its
// account-scoped storage record, the same reason policyVersionResponse does.
func complianceDraftVersionResponse(version *karstpolicy.ComplianceDraftVersion) (map[string]any, error) {
	draft, err := version.Draft()
	if err != nil {
		return nil, err
	}
	dto := draftDTO(draft)
	return map[string]any{
		"version":          version.Version,
		"requirement_sets": orEmptyMap(dto.RequirementSets),
		"guardrails":       orEmptySlice(dto.Guardrails),
		"remediation":      orEmptySlice(dto.Remediation),
		"author":           version.Author,
		"created_at":       version.CreatedAt,
	}, nil
}

func orEmptyMap(m map[string][]complianceRequirementDTO) map[string][]complianceRequirementDTO {
	if m == nil {
		return map[string][]complianceRequirementDTO{}
	}
	return m
}

func orEmptySlice[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

func (h *handler) complianceDraftCurrent(w http.ResponseWriter, r *http.Request) {
	if !h.requireComplianceDraft(w, r) {
		return
	}
	if _, err := nbcontext.GetUserAuthFromContext(r.Context()); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	version, err := h.complianceDraft.Current(r.Context())
	if errors.Is(err, karstpolicy.ErrNoVersion) {
		util.WriteError(r.Context(), status.Errorf(status.NotFound, "no compliance draft version"), w)
		return
	}
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	response, err := complianceDraftVersionResponse(version)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, response)
}

func (h *handler) complianceDraftVersions(w http.ResponseWriter, r *http.Request) {
	if !h.requireComplianceDraft(w, r) {
		return
	}
	if _, err := nbcontext.GetUserAuthFromContext(r.Context()); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	offset, limit, err := pageArguments(r)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	versions, err := h.complianceDraft.List(r.Context(), offset, limit+1)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	var next any
	if len(versions) > limit {
		versions = versions[:limit]
		next = strconv.Itoa(offset + limit)
	}
	items := make([]map[string]any, 0, len(versions))
	for index := range versions {
		response, err := complianceDraftVersionResponse(&versions[index])
		if err != nil {
			util.WriteError(r.Context(), err, w)
			return
		}
		items = append(items, response)
	}
	util.WriteJSONObject(r.Context(), w, map[string]any{"items": items, "next_cursor": next})
}

func (h *handler) complianceDraftVersion(w http.ResponseWriter, r *http.Request) {
	if !h.requireComplianceDraft(w, r) {
		return
	}
	if _, err := nbcontext.GetUserAuthFromContext(r.Context()); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	number, err := strconv.ParseUint(mux.Vars(r)["version"], 10, 64)
	if err != nil {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid compliance draft version"), w)
		return
	}
	version, err := h.complianceDraft.Get(r.Context(), number)
	if errors.Is(err, karstpolicy.ErrNoVersion) {
		util.WriteError(r.Context(), status.Errorf(status.NotFound, "compliance draft version not found"), w)
		return
	}
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	response, err := complianceDraftVersionResponse(version)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, response)
}

// complianceDraftInventory builds the device inventory ValidateComplianceDraft
// and CompileCompliance need: the admin's full managed fleet (GetAdminPeers,
// the same "never a member's own devices only" roster adminNodes uses), each
// device's owned addresses (needed because ComplianceResource.Selector can be
// a CIDR matched against them, unlike policyPreview's handle/tag-only
// network), and its latest accepted evidence where a compliance store is
// configured.
func (h *handler) complianceDraftInventory(ctx context.Context, accountID, userID string) ([]karstpolicy.ComplianceDevice, []karstpolicy.Node, error) {
	peers, err := h.peers.GetAdminPeers(ctx, accountID, userID, "", "")
	if err != nil {
		return nil, nil, err
	}
	now := time.Now().UTC()
	devices := make([]karstpolicy.ComplianceDevice, 0, len(peers))
	inventory := make([]karstpolicy.Node, 0, len(peers))
	for _, p := range peers {
		if p.ID == "" || p.Key == "" {
			continue
		}
		node := karstpolicy.Node{Handle: p.Key, User: p.UserID, Addresses: complianceAllowedIPsOf(p)}
		if len(node.Addresses) == 0 {
			continue
		}
		subject := compliance.Subject{TenantID: accountID, DeviceID: p.ID}
		var evidence *compliance.Evidence
		if h.compliance != nil {
			accepted, err := h.compliance.Latest(ctx, subject, p.Key, now)
			if err == nil {
				e := accepted.Evidence
				evidence = &e
			}
		}
		inventory = append(inventory, node)
		devices = append(devices, karstpolicy.ComplianceDevice{Node: node, Subject: subject, Evidence: evidence})
	}
	return devices, inventory, nil
}

// complianceAllowedIPsOf is control.allowedIPsOf's own logic, duplicated
// rather than imported: this package does not otherwise depend on package
// control, and the two packages' own peer.Peer views of "what this peer is
// permitted to source traffic from" would otherwise need a shared helper
// package for ten lines of code.
func complianceAllowedIPsOf(p *peer.Peer) []string {
	var out []string
	if p.IP.IsValid() {
		out = append(out, p.IP.String()+"/32")
	}
	if p.IPv6.IsValid() {
		out = append(out, p.IPv6.String()+"/128")
	}
	return out
}

// complianceDraftIdentityDocument loads the account's real identity Document,
// needed so a guardrail's group: selector resolves against real groups
// (compliance.go's validateComplianceResource) instead of always failing to
// match against an empty one. Mirrors policyPreview's own current-document
// load, falling back to an empty Document when none has been written yet.
func (h *handler) complianceDraftIdentityDocument(ctx context.Context) (*karstpolicy.Document, error) {
	if h.policy == nil {
		return &karstpolicy.Document{}, nil
	}
	version, err := h.policy.Current(ctx)
	if errors.Is(err, karstpolicy.ErrNoVersion) {
		return &karstpolicy.Document{}, nil
	}
	if err != nil {
		return nil, err
	}
	return karstpolicy.Parse([]byte(version.Document))
}

func (h *handler) complianceDraftValidate(w http.ResponseWriter, r *http.Request) {
	user, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	var request complianceDraftDTO
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}
	doc, err := h.complianceDraftIdentityDocument(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	_, inventory, err := h.complianceDraftInventory(r.Context(), user.AccountId, user.UserId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	candidate := request.toDraft(user.AccountId)
	if err := doc.ValidateComplianceDraft(candidate, inventory); err != nil {
		util.WriteJSONObject(r.Context(), w, map[string]any{"valid": false, "diagnostics": []map[string]any{{"severity": "error", "message": err.Error()}}})
		return
	}
	util.WriteJSONObject(r.Context(), w, map[string]any{"valid": true, "diagnostics": []any{}})
}

// complianceDraftPreview reports, per managed device, the mandatory gates a
// candidate draft would compile to -- the compliance analog of policyPreview,
// grounded in the same compiled output control.PermitHandler issues
// (policy.CompileCompliance), not a reimplementation of it. ADR-0055 requires
// preview to "explain wildcard and CIDR overlaps"; a ValidateComplianceDraft
// failure (which already explains an overlap) is reported as a diagnostic
// rather than an HTTP error, the same shape policyPreview uses for a parse
// error.
func (h *handler) complianceDraftPreview(w http.ResponseWriter, r *http.Request) {
	user, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	var request complianceDraftDTO
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}
	candidate := request.toDraft(user.AccountId)
	doc, err := h.complianceDraftIdentityDocument(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	devices, inventory, err := h.complianceDraftInventory(r.Context(), user.AccountId, user.UserId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if err := doc.ValidateComplianceDraft(candidate, inventory); err != nil {
		util.WriteJSONObject(r.Context(), w, map[string]any{"devices": []any{}, "diagnostics": []map[string]any{{"severity": "error", "message": err.Error()}}})
		return
	}
	now := time.Now().UTC()
	results := make([]map[string]any, 0, len(devices))
	for _, device := range devices {
		compiled, err := doc.CompileCompliance(candidate, devices, device.Node.Handle, nil, now)
		if err != nil {
			util.WriteError(r.Context(), err, w)
			return
		}
		results = append(results, map[string]any{
			"handle":  device.Node.Handle,
			"ingress": compliancePreviewGates(compiled.Ingress),
			"egress":  compliancePreviewGates(compiled.Egress),
		})
	}
	util.WriteJSONObject(r.Context(), w, map[string]any{"devices": results, "diagnostics": []any{}})
}

func compliancePreviewGates(gates []karstpolicy.ComplianceGate) []map[string]any {
	out := make([]map[string]any, 0, len(gates))
	for _, gate := range gates {
		cidrs := make([]string, 0, len(gate.Destinations))
		for _, prefix := range gate.Destinations {
			cidrs = append(cidrs, prefix.String())
		}
		sources := make([]map[string]any, 0, len(gate.Sources))
		for _, source := range gate.Sources {
			sources = append(sources, map[string]any{"handle": source.Handle, "valid_until": source.ValidUntil})
		}
		out = append(out, map[string]any{
			"guardrail_id": gate.GuardrailID,
			"destinations": cidrs,
			"protocol":     gate.Protocol,
			"ports":        map[string]any{"first": gate.Ports.First, "last": gate.Ports.Last},
			"sources":      sources,
		})
	}
	return out
}

// complianceDraftTest mirrors policyTest's own placeholder precedent
// (structural validation only, explicitly designed to grow): a synthetic-flow
// "would this be allowed" test is a reasonable follow-up, not a blocker for
// landing a persisted write API.
func (h *handler) complianceDraftTest(w http.ResponseWriter, r *http.Request) {
	user, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	var request complianceDraftDTO
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}
	doc, err := h.complianceDraftIdentityDocument(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	_, inventory, err := h.complianceDraftInventory(r.Context(), user.AccountId, user.UserId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	candidate := request.toDraft(user.AccountId)
	if err := doc.ValidateComplianceDraft(candidate, inventory); err != nil {
		util.WriteJSONObject(r.Context(), w, map[string]any{"passed": false, "results": []map[string]any{{"name": "draft-valid", "passed": false, "message": err.Error()}}})
		return
	}
	util.WriteJSONObject(r.Context(), w, map[string]any{"passed": true, "results": []map[string]any{{"name": "draft-valid", "passed": true}}})
}

func (h *handler) complianceDraftWrite(w http.ResponseWriter, r *http.Request) {
	if !h.requireComplianceDraft(w, r) {
		return
	}
	user, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	expected, err := strconv.ParseUint(strings.Trim(r.Header.Get("If-Match"), "\""), 10, 64)
	if err != nil {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "If-Match must be a compliance draft version"), w)
		return
	}
	var request complianceDraftDTO
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}
	candidate := request.toDraft(user.AccountId)
	doc, err := h.complianceDraftIdentityDocument(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	_, inventory, err := h.complianceDraftInventory(r.Context(), user.AccountId, user.UserId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if err := doc.ValidateComplianceDraft(candidate, inventory); err != nil {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "%s", err), w)
		return
	}
	version, err := h.complianceDraft.Write(r.Context(), candidate, user.UserId, expected)
	if errors.Is(err, karstpolicy.ErrVersionConflict) {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "compliance draft version changed"), w)
		return
	}
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	h.pushComplianceDraftUpdate(r.Context(), user.AccountId)
	response, err := complianceDraftVersionResponse(version)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	w.Header().Set("ETag", strconv.FormatUint(version.Version, 10))
	util.WriteJSONObject(r.Context(), w, response)
}

func (h *handler) complianceDraftRollback(w http.ResponseWriter, r *http.Request) {
	if !h.requireComplianceDraft(w, r) {
		return
	}
	user, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	number, err := strconv.ParseUint(mux.Vars(r)["version"], 10, 64)
	if err != nil {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid compliance draft version"), w)
		return
	}
	expected, err := strconv.ParseUint(strings.Trim(r.Header.Get("If-Match"), "\""), 10, 64)
	if err != nil {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "If-Match must be a compliance draft version"), w)
		return
	}
	previous, err := h.complianceDraft.Get(r.Context(), number)
	if errors.Is(err, karstpolicy.ErrNoVersion) {
		util.WriteError(r.Context(), status.Errorf(status.NotFound, "compliance draft version not found"), w)
		return
	}
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	previousDraft, err := previous.Draft()
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	// Restoring history must obey the same current validation as a new
	// write -- the account's groups/inventory may have changed since this
	// version was written, the same reasoning policyRollback's own comment
	// gives for validateRegistryGrants.
	doc, err := h.complianceDraftIdentityDocument(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	_, inventory, err := h.complianceDraftInventory(r.Context(), user.AccountId, user.UserId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if err := doc.ValidateComplianceDraft(previousDraft, inventory); err != nil {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "%s", err), w)
		return
	}
	written, err := h.complianceDraft.Write(r.Context(), previousDraft, user.UserId, expected)
	if errors.Is(err, karstpolicy.ErrVersionConflict) {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "compliance draft version changed"), w)
		return
	}
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	h.pushComplianceDraftUpdate(r.Context(), user.AccountId)
	response, err := complianceDraftVersionResponse(written)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	w.Header().Set("ETag", strconv.FormatUint(written.Version, 10))
	util.WriteJSONObject(r.Context(), w, response)
}

// pushComplianceDraftUpdate mirrors pushPolicyUpdate exactly: account-wide,
// synchronous UpdateAccountPeers, for the identical reason -- a guardrail can
// name any node via group:/CIDR/wildcard selectors, so there is no fixed
// affected-peer set to diff, and a compliance draft write is an infrequent,
// deliberate admin action, not a hot path. karstd's control client already
// polls KindCompliancePermit every 30s regardless of netmap pushes (PR2), so
// this does not lower the worst-case bound below that poll interval; it gives
// an already-connected session the same "re-fetch promptly" benefit
// pushPolicyUpdate already gives ACL writes.
func (h *handler) pushComplianceDraftUpdate(ctx context.Context, accountID string) {
	if h.accounts == nil {
		return
	}
	h.accounts.UpdateAccountPeers(ctx, accountID, types.UpdateReason{
		Resource:  types.UpdateResourceCompliancePolicy,
		Operation: types.UpdateOperationUpdate,
	})
}
