// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package meshdomain

// RenamePreview binds confirmation to the names and network revision the
// administrator reviewed. Revision is opaque; clients must return it unchanged.
type RenamePreview struct {
	RootID         string          `json:"root_id"`
	OldSuffix      string          `json:"old_suffix"`
	NewSuffix      string          `json:"new_suffix"`
	Revision       string          `json:"revision"`
	NamingRevision uint64          `json:"naming_revision"`
	DeviceCount    int             `json:"device_count"`
	DomainCount    int             `json:"domain_count"`
	Examples       []RenameExample `json:"examples"`
	Committed      bool            `json:"committed"`
	// No client application acknowledgment exists in the current protocol.
	Convergence string `json:"convergence"`
}

type RenameExample struct {
	Before string `json:"before"`
	After  string `json:"after"`
}
