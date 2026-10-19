// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package policy

import (
	"fmt"
	"net/netip"
	"sort"
	"time"

	"github.com/netbirdio/netbird/management/internals/karst/compliance"
)

// ComplianceDevice binds an authoritative tenant enrollment to its policy
// identity and latest trusted evidence. A missing report is represented by nil.
// The caller must obtain all three from trusted tenant-scoped readers.
type ComplianceDevice struct {
	Node     Node
	Subject  compliance.Subject
	Evidence *compliance.Evidence
}

// ComplianceSourceDecision is deliberately limited to a concrete identity and
// its evidence deadline. Other devices' raw observations and failure reasons
// are not part of the compiled gate. This is not a wire permission or lease.
type ComplianceSourceDecision struct {
	Handle     string
	ValidUntil time.Time
}

// ComplianceGate is mandatory for every matching packet. Matching gates compose
// with AND; Sources is a list of passing devices, never a wildcard. An empty
// source list denies the protected resource rather than removing the gate.
type ComplianceGate struct {
	GuardrailID  string
	Destinations []netip.Prefix
	Protocol     string
	Ports        PortRange
	Sources      []ComplianceSourceDecision
}

// ComplianceCompilation is an internal diagnostic snapshot. It must not replace
// identity filters or the SSH gate, and is not yet distributed to clients.
// Ingress includes only this node's owned addresses and authoritative gateway
// routes. Egress includes only this node's own source decision.
type ComplianceCompilation struct {
	TenantID   string
	Node       string
	CompiledAt time.Time
	Ingress    []ComplianceGate
	Egress     []ComplianceGate
	valid      bool
}

// CompileCompliance resolves guardrails into device-specific ingress and egress
// gates. routedPrefixes must be the target's current authoritative gateway
// prefixes, not routes it merely receives or routes advertised by other peers.
// Recompile on evidence, policy, enrollment, selector or route ownership changes.
// The snapshot uses evidence expiry only; permit issuance, capability checks and
// suspend-aware datapath expiry remain separate implementation stages.
func (d *Document) CompileCompliance(draft ComplianceDraft, devices []ComplianceDevice, target string, routedPrefixes []string, now time.Time) (*ComplianceCompilation, error) {
	if now.IsZero() {
		return nil, fmt.Errorf("compliance: compilation time is required")
	}
	inventory := make([]Node, 0, len(devices))
	handles, subjects := map[string]bool{}, map[string]bool{}
	owned := map[string][]netip.Prefix{}
	for _, device := range devices {
		handle := device.Node.Handle
		if handle == "" || handle == Wildcard || handles[handle] {
			return nil, fmt.Errorf("compliance: empty, wildcard or duplicate device handle")
		}
		if device.Subject.TenantID != draft.TenantID || device.Subject.DeviceID == "" || subjects[device.Subject.DeviceID] {
			return nil, fmt.Errorf("compliance: invalid or duplicate tenant enrollment")
		}
		if len(device.Node.Addresses) == 0 {
			return nil, fmt.Errorf("compliance: enrolled device has no owned addresses")
		}
		handles[handle], subjects[device.Subject.DeviceID] = true, true
		inventory = append(inventory, device.Node)
		for _, address := range device.Node.Addresses {
			prefix, err := compliancePrefix(address)
			if err != nil {
				return nil, err
			}
			owned[handle] = append(owned[handle], prefix)
		}
	}
	if !handles[target] {
		return nil, fmt.Errorf("compliance: target is not enrolled in tenant inventory")
	}
	if err := d.ValidateComplianceDraft(draft, inventory); err != nil {
		return nil, err
	}
	ingressScope := append([]netip.Prefix{}, owned[target]...)
	for _, route := range routedPrefixes {
		prefix, err := compliancePrefix(route)
		if err != nil {
			return nil, err
		}
		ingressScope = append(ingressScope, prefix)
	}
	result := &ComplianceCompilation{TenantID: draft.TenantID, Node: target, CompiledAt: now}
	// Cache each requirement-set evaluation per device, so overlapping guardrails
	// reuse one explicit-time decision without conflating different devices.
	evaluations := map[string]map[string]compliance.Evaluation{}
	for _, device := range devices {
		evaluations[device.Node.Handle] = map[string]compliance.Evaluation{}
	}
	guards := append([]ComplianceGuardrail{}, draft.Guardrails...)
	sort.Slice(guards, func(i, j int) bool { return guards[i].ID < guards[j].ID })
	for _, guard := range guards {
		resource := guard.Resource
		var ingress, egress []netip.Prefix
		switch {
		case resource.Selector == Wildcard:
			ingress = append(ingress, ingressScope...)
			egress = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}
		default:
			if prefix, err := netip.ParsePrefix(resource.Selector); err == nil {
				prefix = prefix.Masked()
				egress = []netip.Prefix{prefix}
				for _, scope := range ingressScope {
					if scope.Overlaps(prefix) {
						intersection := scope
						if prefix.Bits() > scope.Bits() {
							intersection = prefix
						}
						ingress = append(ingress, intersection)
					}
				}
			} else {
				for _, node := range inventory {
					if !d.matches(resource.Selector, node) {
						continue
					}
					egress = append(egress, owned[node.Handle]...)
					if node.Handle == target {
						ingress = append(ingress, owned[target]...)
					}
				}
			}
		}
		if len(ingress) == 0 && len(egress) == 0 {
			continue
		}
		inbound := ComplianceGate{GuardrailID: guard.ID, Destinations: normalizeCompliancePrefixes(ingress), Protocol: resource.Protocol, Ports: resource.Ports}
		outbound := ComplianceGate{GuardrailID: guard.ID, Destinations: normalizeCompliancePrefixes(egress), Protocol: resource.Protocol, Ports: resource.Ports}
		for _, device := range devices {
			if len(ingress) == 0 && device.Node.Handle != target {
				continue
			}
			passing := true
			var deadline time.Time
			for _, id := range guard.RequirementSets {
				evaluation, ok := evaluations[device.Node.Handle][id]
				if !ok {
					var err error
					evaluation, err = compliance.Evaluate(draft.RequirementSets[id], device.Subject, device.Evidence, now)
					if err != nil {
						return nil, err
					}
					evaluations[device.Node.Handle][id] = evaluation
				}
				if !evaluation.Satisfied() {
					passing = false
				}
				if !evaluation.ValidUntil.IsZero() && (deadline.IsZero() || evaluation.ValidUntil.Before(deadline)) {
					deadline = evaluation.ValidUntil
				}
			}
			if !passing {
				continue
			}
			decision := ComplianceSourceDecision{Handle: device.Node.Handle, ValidUntil: deadline}
			if len(ingress) > 0 {
				inbound.Sources = append(inbound.Sources, decision)
			}
			if len(egress) > 0 && device.Node.Handle == target {
				outbound.Sources = append(outbound.Sources, decision)
			}
		}
		sort.Slice(inbound.Sources, func(i, j int) bool { return inbound.Sources[i].Handle < inbound.Sources[j].Handle })
		if len(ingress) > 0 {
			result.Ingress = append(result.Ingress, inbound)
		}
		if len(egress) > 0 {
			result.Egress = append(result.Egress, outbound)
		}
	}
	result.valid = true
	return result, nil
}

func compliancePrefix(value string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(value)
	if err != nil || prefix.Addr().Is4In6() {
		return netip.Prefix{}, fmt.Errorf("compliance: invalid owned or routed prefix %q", value)
	}
	return prefix.Masked(), nil
}

func normalizeCompliancePrefixes(prefixes []netip.Prefix) []netip.Prefix {
	sort.Slice(prefixes, func(i, j int) bool {
		if order := prefixes[i].Addr().Compare(prefixes[j].Addr()); order != 0 {
			return order < 0
		}
		return prefixes[i].Bits() < prefixes[j].Bits()
	})
	out := make([]netip.Prefix, 0, len(prefixes))
	for _, prefix := range prefixes {
		if len(out) == 0 || out[len(out)-1] != prefix {
			out = append(out, prefix)
		}
	}
	return out
}

// IngressSatisfied is a reference evaluator of the compliance gate alone. A
// true result never substitutes for the independent identity/SSH decisions.
// No matching guardrail leaves unprotected traffic unconstrained by compliance;
// a matching guardrail denies unknown sources and nonpassing/expired evidence.
func (c *ComplianceCompilation) IngressSatisfied(source string, destination netip.Addr, protocol string, port uint16, now time.Time) bool {
	if c == nil || !c.valid || now.IsZero() || now.Before(c.CompiledAt) {
		return false
	}
	return complianceGatesSatisfied(c.Ingress, source, destination, protocol, port, now)
}

// EgressSatisfied evaluates the target device's own mandatory source decisions.
func (c *ComplianceCompilation) EgressSatisfied(destination netip.Addr, protocol string, port uint16, now time.Time) bool {
	if c == nil || !c.valid || now.IsZero() || now.Before(c.CompiledAt) {
		return false
	}
	return complianceGatesSatisfied(c.Egress, c.Node, destination, protocol, port, now)
}

func complianceGatesSatisfied(gates []ComplianceGate, source string, destination netip.Addr, protocol string, port uint16, now time.Time) bool {
	if source == "" || source == Wildcard || !destination.IsValid() || destination.Is4In6() || destination.Zone() != "" || (protocol != "tcp" && protocol != "udp") {
		return false
	}
	for _, gate := range gates {
		if gate.Protocol != Wildcard && gate.Protocol != protocol {
			continue
		}
		if port < gate.Ports.First || port > gate.Ports.Last {
			continue
		}
		matched := false
		for _, prefix := range gate.Destinations {
			if prefix.Contains(destination) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		satisfied := false
		for _, decision := range gate.Sources {
			if decision.Handle == source && now.Before(decision.ValidUntil) {
				satisfied = true
				break
			}
		}
		if !satisfied {
			return false
		}
	}
	return true
}
