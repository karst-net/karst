// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package node

import (
	"context"
	"fmt"
	"time"
)

// ControlCheck describes an actual control-server capability evaluation, not
// an inference from release strings. Accepted means a netmap was constructed;
// it does not attest to the client applying it or to data-plane compatibility.
type ControlCheck struct {
	Status         string
	Capability     string
	RequiredSchema uint32
	ReportedSchema uint32
	ObservedAt     *time.Time
}

// RecordControlCheck stores an advisory diagnostic for an existing node. A
// success clears the previous rejection. Unrelated failures must not call this
// method, since they say nothing about whether a capability mismatch remains.
func (s *Store) RecordControlCheck(ctx context.Context, handle string, check ControlCheck) error {
	if check.ObservedAt == nil || check.ObservedAt.IsZero() {
		return fmt.Errorf("node: missing control check time")
	}
	switch check.Status {
	case "accepted":
		if check.Capability != "" || check.RequiredSchema != 0 || check.ReportedSchema != 0 {
			return fmt.Errorf("node: accepted control check contains a rejection")
		}
	case "incompatible":
		if (check.Capability != "relay_lifecycle_schema" && check.Capability != "gateway_ingress_schema") || check.RequiredSchema == 0 || check.ReportedSchema == check.RequiredSchema {
			return fmt.Errorf("node: invalid control capability rejection")
		}
	default:
		return fmt.Errorf("node: invalid control check status")
	}
	result := s.db.WithContext(ctx).Model(&Identity{}).Where("handle = ?", handle).Updates(map[string]any{
		"control_check_status": check.Status, "control_check_capability": check.Capability,
		"control_check_required_schema": check.RequiredSchema, "control_check_reported_schema": check.ReportedSchema,
		"control_check_observed_at": check.ObservedAt.UTC(),
	})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		_, err := s.Get(handle)
		return err
	}
	return nil
}
