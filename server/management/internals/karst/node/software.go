// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package node

import (
	"context"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// SoftwareIdentity is advisory build metadata, never an authorization claim.
// Empty fields explicitly mean unknown; a partial report replaces all fields
// rather than retaining an artifact identity from a different running build.
type SoftwareIdentity struct {
	Version, Revision, ArtifactID string
}

// RecordSoftware updates only an existing, authenticated node. The caller
// supplies server receipt time, never a client-controlled clock value.
func (s *Store) RecordSoftware(ctx context.Context, handle string, report SoftwareIdentity, received time.Time) error {
	for _, field := range []struct {
		value string
		limit int
	}{{report.Version, 128}, {report.Revision, 128}, {report.ArtifactID, 256}} {
		if len(field.value) > field.limit || !utf8.ValidString(field.value) || strings.IndexFunc(field.value, unicode.IsControl) >= 0 {
			return fmt.Errorf("node: invalid software identity")
		}
	}
	if received.IsZero() {
		return fmt.Errorf("node: missing software receipt time")
	}
	result := s.db.WithContext(ctx).Model(&Identity{}).Where("handle = ?", handle).Updates(map[string]any{
		"software_version":     strings.TrimSpace(report.Version),
		"software_revision":    strings.TrimSpace(report.Revision),
		"software_artifact_id": strings.TrimSpace(report.ArtifactID),
		"software_observed_at": received.UTC(),
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
