// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package policy

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/netbirdio/netbird/management/internals/karst/compliance"
)

// ComplianceDraft is a tenant-scoped preview model, not an enabled policy or
// wire permission. It is deliberately absent from Document's JSON schema:
// accepting policy writes must wait for mandatory packet-path enforcement.
type ComplianceDraft struct {
	TenantID        string
	RequirementSets map[string][]compliance.Requirement
	Guardrails      []ComplianceGuardrail
	Remediation     []ComplianceResource
}

type ComplianceGuardrail struct {
	ID              string
	Resource        ComplianceResource
	RequirementSets []string
}

// ComplianceResource matches a destination node selector or an explicit CIDR,
// an inclusive port range, and TCP/UDP ("*" means either). CIDRs match the real
// destination address, never the gateway identity. A wildcard protects both
// node and routed destinations.
type ComplianceResource struct {
	Selector string
	Protocol string
	Ports    PortRange
}

// ComplianceFlow contains trusted preview inputs. IdentityAllowed and SSHAllowed
// are decisions from the independent identity and SSH gates, never client claims.
// DestinationHandle is empty for routed traffic; it must not name the gateway.
// Address is the actual packet destination. Nodes and evidence must be resolved
// by a tenant-scoped caller; this model does not perform enrollment lookups.
type ComplianceFlow struct {
	Subject           compliance.Subject
	DestinationHandle string
	Address           netip.Addr
	Protocol          string
	Port              uint16
	IdentityAllowed   bool
	SSHAllowed        bool
}

type ComplianceSetPreview struct {
	ID         string
	Evaluation compliance.Evaluation
}

type CompliancePreview struct {
	Allowed         bool
	IdentityAllowed bool
	SSHAllowed      bool
	Guardrails      []string
	RequirementSets []ComplianceSetPreview
	ValidUntil      time.Time // Evidence deadline only; not a permission lease.
}

// ValidateComplianceDraft rejects unresolved requirements and remediation
// intersections before previewing. Inventory must be the current tenant roster;
// revalidate after identity, address, tag or group changes. Unresolved selectors
// remain meaningful for future nodes and do not silently become unconditional.
func (d *Document) ValidateComplianceDraft(draft ComplianceDraft, inventory []Node) error {
	if d == nil {
		return fmt.Errorf("compliance: identity policy is required")
	}
	if err := d.Validate(); err != nil {
		return err
	}
	if draft.TenantID == "" {
		return fmt.Errorf("compliance: tenant is required")
	}
	for id, requirements := range draft.RequirementSets {
		if strings.TrimSpace(id) == "" || len(requirements) == 0 {
			return fmt.Errorf("compliance: requirement set %q is empty", id)
		}
		seen := map[string]bool{}
		for _, r := range requirements {
			if err := r.Validate(); err != nil {
				return err
			}
			if seen[r.ID] {
				return fmt.Errorf("compliance: duplicate requirement %q in set %q", r.ID, id)
			}
			seen[r.ID] = true
		}
	}
	seen := map[string]bool{}
	for _, g := range draft.Guardrails {
		if strings.TrimSpace(g.ID) == "" || seen[g.ID] {
			return fmt.Errorf("compliance: empty or duplicate guardrail ID %q", g.ID)
		}
		seen[g.ID] = true
		if err := d.validateComplianceResource(g.Resource); err != nil {
			return fmt.Errorf("guardrail %q: %w", g.ID, err)
		}
		if len(g.RequirementSets) == 0 {
			return fmt.Errorf("compliance: guardrail %q has no requirements", g.ID)
		}
		refs := map[string]bool{}
		for _, id := range g.RequirementSets {
			if _, ok := draft.RequirementSets[id]; !ok {
				return fmt.Errorf("compliance: guardrail %q references missing set %q", g.ID, id)
			}
			if refs[id] {
				return fmt.Errorf("compliance: guardrail %q repeats set %q", g.ID, id)
			}
			refs[id] = true
		}
	}
	for _, r := range draft.Remediation {
		if err := d.validateComplianceResource(r); err != nil {
			return err
		}
		for _, g := range draft.Guardrails {
			if d.complianceResourcesOverlap(r, g.Resource, inventory) {
				return fmt.Errorf("compliance: remediation overlaps guardrail %q", g.ID)
			}
		}
	}
	return nil
}

func (d *Document) validateComplianceResource(r ComplianceResource) error {
	if r.Protocol != "tcp" && r.Protocol != "udp" && r.Protocol != Wildcard {
		return fmt.Errorf("compliance: unsupported protocol %q", r.Protocol)
	}
	if r.Ports.First > r.Ports.Last {
		return fmt.Errorf("compliance: reversed port range")
	}
	if strings.TrimSpace(r.Selector) == "" || strings.TrimSpace(r.Selector) != r.Selector {
		return fmt.Errorf("compliance: invalid destination selector")
	}
	if strings.Contains(r.Selector, "/") {
		if prefix, err := netip.ParsePrefix(r.Selector); err != nil || prefix.Addr().Is4In6() {
			return fmt.Errorf("compliance: invalid destination CIDR %q", r.Selector)
		}
	}
	if !strings.Contains(r.Selector, "/") {
		if _, err := netip.ParseAddr(r.Selector); err == nil {
			return fmt.Errorf("compliance: address selectors require an explicit CIDR")
		}
		if err := validateSshDst(r.Selector); err != nil {
			return fmt.Errorf("compliance: resource ports belong in the port range: %w", err)
		}
	}
	if strings.HasPrefix(r.Selector, "group:") {
		if _, ok := d.Groups[r.Selector]; !ok {
			return fmt.Errorf("compliance: undefined group %q", r.Selector)
		}
	}
	return nil
}

func (d *Document) complianceSelectorMatches(selector string, node *Node, address netip.Addr) bool {
	if selector == Wildcard {
		return true
	}
	if prefix, err := netip.ParsePrefix(selector); err == nil {
		return prefix.Contains(address)
	}
	return node != nil && d.matches(selector, *node)
}

func (d *Document) complianceResourcesOverlap(a, b ComplianceResource, nodes []Node) bool {
	if a.Protocol != Wildcard && b.Protocol != Wildcard && a.Protocol != b.Protocol {
		return false
	}
	if a.Ports.Last < b.Ports.First || b.Ports.Last < a.Ports.First {
		return false
	}
	if a.Selector == Wildcard || b.Selector == Wildcard || a.Selector == b.Selector {
		return true
	}
	pa, ea := netip.ParsePrefix(a.Selector)
	pb, eb := netip.ParsePrefix(b.Selector)
	if ea == nil && eb == nil {
		return pa.Overlaps(pb)
	}
	for _, node := range nodes {
		// For node/CIDR intersections, addresses are ranges owned by the node.
		// No gateway route offers belong in this inventory.
		if ea == nil || eb == nil {
			prefix, selector := pa, b.Selector
			if eb == nil {
				prefix, selector = pb, a.Selector
			}
			if !d.matches(selector, node) {
				continue
			}
			for _, address := range node.Addresses {
				owned, err := netip.ParsePrefix(address)
				if err == nil && prefix.Overlaps(owned) {
					return true
				}
			}
		} else if d.matches(a.Selector, node) && d.matches(b.Selector, node) {
			return true
		}
	}
	return false
}

// PreviewCompliance applies all matching guardrails with AND, independently of
// which identity accept rule matched. Errors return a denied zero result. This
// computes a diagnostic snapshot only; it neither issues nor renews permits.
func (d *Document) PreviewCompliance(draft ComplianceDraft, inventory []Node, flow ComplianceFlow, evidence *compliance.Evidence, now time.Time) (CompliancePreview, error) {
	if err := d.ValidateComplianceDraft(draft, inventory); err != nil {
		return CompliancePreview{}, err
	}
	if flow.Subject.TenantID != draft.TenantID || flow.Subject.DeviceID == "" || now.IsZero() {
		return CompliancePreview{}, fmt.Errorf("compliance: authenticated subject/time does not match draft")
	}
	if !flow.Address.IsValid() || flow.Address.Is4In6() || flow.Address.Zone() != "" || (flow.Protocol != "tcp" && flow.Protocol != "udp") {
		return CompliancePreview{}, fmt.Errorf("compliance: invalid flow address or protocol")
	}
	var destination *Node
	if flow.DestinationHandle != "" {
		for i := range inventory {
			if inventory[i].Handle == flow.DestinationHandle {
				if destination != nil {
					return CompliancePreview{}, fmt.Errorf("compliance: ambiguous destination handle")
				}
				destination = &inventory[i]
			}
		}
		if destination == nil {
			return CompliancePreview{}, fmt.Errorf("compliance: destination is not in tenant inventory")
		}
		ownsAddress := false
		for _, address := range destination.Addresses {
			if prefix, err := netip.ParsePrefix(address); err == nil && prefix.Contains(flow.Address) {
				ownsAddress = true
			}
		}
		if !ownsAddress {
			return CompliancePreview{}, fmt.Errorf("compliance: destination address does not belong to node")
		}
	}
	result := CompliancePreview{IdentityAllowed: flow.IdentityAllowed, SSHAllowed: flow.SSHAllowed}
	result.Allowed = flow.IdentityAllowed && (flow.Protocol != "tcp" || flow.Port != 22 || flow.SSHAllowed)
	sets := map[string]bool{}
	for _, g := range draft.Guardrails {
		r := g.Resource
		if r.Protocol != Wildcard && r.Protocol != flow.Protocol {
			continue
		}
		if flow.Port < r.Ports.First || flow.Port > r.Ports.Last || !d.complianceSelectorMatches(r.Selector, destination, flow.Address) {
			continue
		}
		result.Guardrails = append(result.Guardrails, g.ID)
		for _, id := range g.RequirementSets {
			sets[id] = true
		}
	}
	sort.Strings(result.Guardrails)
	ids := make([]string, 0, len(sets))
	for id := range sets {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		evaluation, err := compliance.Evaluate(draft.RequirementSets[id], flow.Subject, evidence, now)
		if err != nil {
			return CompliancePreview{}, err
		}
		result.RequirementSets = append(result.RequirementSets, ComplianceSetPreview{ID: id, Evaluation: evaluation})
		if !evaluation.Satisfied() {
			result.Allowed = false
		}
		if !evaluation.ValidUntil.IsZero() && (result.ValidUntil.IsZero() || evaluation.ValidUntil.Before(result.ValidUntil)) {
			result.ValidUntil = evaluation.ValidUntil
		}
	}
	if !result.Allowed {
		result.ValidUntil = time.Time{}
	}
	return result, nil
}
