// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package compliance

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net/netip"
	"strings"

	"github.com/netbirdio/netbird/shared/management/proto"
)

// PermitLifetimeMillis is a maximum validity budget from local request start,
// not a deadline restarted at response receipt. This is not active enforcement.
const PermitLifetimeMillis = 120000

// PermitBinding is trusted local request/enrollment context. PolicyRevision must
// come from the same authenticated policy transaction as the permit snapshot.
// A validator does not establish authenticity, consume nonces or issue leases.
type PermitBinding struct {
	Subject        Subject
	Handle         string
	PolicyRevision string
	Nonce          []byte
}

func validPermitID(value string) bool {
	return len(value) > 0 && len(value) <= 128 && strings.TrimSpace(value) == value
}
func validPermitHandle(value string) bool {
	raw, err := base64.StdEncoding.DecodeString(value)
	return err == nil && len(raw) == 32 && base64.StdEncoding.EncodeToString(raw) == value
}

// ValidatePermitRequest validates the reserved contract without enabling it.
func ValidatePermitRequest(request *proto.KarstCompliancePermitRequest) error {
	if request == nil || request.SchemaVersion != 1 || len(request.Nonce) != 32 {
		return fmt.Errorf("compliance: invalid permit request")
	}
	return nil
}

// ValidatePermitSnapshot validates the entire snapshot before installation.
// A failure invalidates the whole candidate; callers must never partially apply
// it or renew an older snapshot. Only an authenticated channel may supply it.
// Nonce consumption, freshness budgets, authoritative policy/evidence reads,
// capabilities and packet-path enforcement are not implemented by this helper.
func ValidatePermitSnapshot(snapshot *proto.KarstCompliancePermitSnapshot, binding PermitBinding) error {
	if snapshot == nil || snapshot.SchemaVersion != 1 {
		return fmt.Errorf("compliance: unsupported permit snapshot")
	}
	if !validPermitID(binding.Subject.TenantID) || !validPermitID(binding.Subject.DeviceID) || !validPermitHandle(binding.Handle) || !validPermitID(binding.PolicyRevision) || len(binding.Nonce) != 32 {
		return fmt.Errorf("compliance: invalid trusted permit binding")
	}
	if !bytes.Equal(snapshot.RequestNonce, binding.Nonce) || snapshot.TenantId != binding.Subject.TenantID || snapshot.EnforcerDeviceId != binding.Subject.DeviceID || snapshot.EnforcerHandle != binding.Handle || snapshot.PolicyRevision != binding.PolicyRevision {
		return fmt.Errorf("compliance: permit binding mismatch")
	}
	if snapshot.ValidForMillis == 0 || snapshot.ValidForMillis > PermitLifetimeMillis {
		return fmt.Errorf("compliance: invalid snapshot validity budget")
	}
	type sourceBinding struct {
		device     string
		generation uint64
	}
	bindings := map[string]sourceBinding{}
	deviceHandles := map[string]string{}
	for direction, gates := range [][]*proto.KarstCompliancePermitGate{snapshot.Ingress, snapshot.Egress} {
		ids := map[string]bool{}
		for _, gate := range gates {
			if gate == nil || !validPermitID(gate.GuardrailId) || ids[gate.GuardrailId] {
				return fmt.Errorf("compliance: invalid or duplicate permit guardrail")
			}
			ids[gate.GuardrailId] = true
			if gate.Protocol != proto.KarstCompliancePermitGate_TCP && gate.Protocol != proto.KarstCompliancePermitGate_UDP && gate.Protocol != proto.KarstCompliancePermitGate_ANY {
				return fmt.Errorf("compliance: unsupported permit protocol")
			}
			if gate.Ports == nil || gate.Ports.First > gate.Ports.Last || gate.Ports.Last > 65535 {
				return fmt.Errorf("compliance: invalid permit ports")
			}
			if len(gate.DestinationCidrs) == 0 {
				return fmt.Errorf("compliance: missing permit destinations")
			}
			prefixes := map[string]bool{}
			for _, value := range gate.DestinationCidrs {
				prefix, err := netip.ParsePrefix(value)
				if err != nil || prefix.Addr().Is4In6() || prefix.Masked().String() != value || prefixes[value] {
					return fmt.Errorf("compliance: invalid or duplicate permit CIDR")
				}
				prefixes[value] = true
			}
			handles, devices := map[string]bool{}, map[string]bool{}
			for _, source := range gate.Sources {
				if source == nil || !validPermitHandle(source.Handle) || !validPermitID(source.DeviceId) || source.EvidenceGeneration == 0 || handles[source.Handle] || devices[source.DeviceId] {
					return fmt.Errorf("compliance: invalid or duplicate source permit")
				}
				handles[source.Handle], devices[source.DeviceId] = true, true
				if direction == 1 && (source.Handle != binding.Handle || source.DeviceId != binding.Subject.DeviceID) {
					return fmt.Errorf("compliance: egress permit belongs to another device")
				}
				if source.ValidForMillis == 0 || source.ValidForMillis > snapshot.ValidForMillis {
					return fmt.Errorf("compliance: invalid source validity budget")
				}
				if (source.Handle == binding.Handle && source.DeviceId != binding.Subject.DeviceID) || (source.DeviceId == binding.Subject.DeviceID && source.Handle != binding.Handle) {
					return fmt.Errorf("compliance: source conflicts with enforcer enrollment")
				}
				if handle, ok := deviceHandles[source.DeviceId]; ok && handle != source.Handle {
					return fmt.Errorf("compliance: device has inconsistent source handles")
				}
				deviceHandles[source.DeviceId] = source.Handle
				current := sourceBinding{device: source.DeviceId, generation: source.EvidenceGeneration}
				if previous, ok := bindings[source.Handle]; ok && previous != current {
					return fmt.Errorf("compliance: inconsistent source generation or enrollment")
				}
				bindings[source.Handle] = current
			}
		}
	}
	return nil
}
