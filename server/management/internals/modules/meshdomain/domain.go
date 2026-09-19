// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// Package meshdomain implements ADR-0032's hierarchical mesh-domain naming:
// an account-scoped tree an admin organizes devices into, and later
// delegates subtrees of to other admins. Deliberately not called "zone" (the
// unrelated zones package already owns that word for custom split-DNS
// records) or "aquifer" (spec/ponor-v1.md Sec5.4's flat relay-forwarding
// tenant-isolation tag, which this package does not touch or extend).
package meshdomain

import (
	"errors"
	"strings"

	"github.com/rs/xid"

	nbdns "github.com/netbirdio/netbird/dns"
)

// Domain is one node in an account's mesh-naming tree. A peer placed in a
// Domain has that domain's Path inserted between its own DNS label and the
// account's root DNS suffix -- see Domain.QualifyLabel.
//
// Domains are append-only for now: there is no rename or re-parent
// operation, only create and delete. Path is computed once at creation from
// the (immutable) parent chain, so every read is a single row lookup rather
// than a walk -- this is what makes qualifying a peer's name on every netmap
// build cheap.
type Domain struct {
	ID        string `gorm:"primaryKey"`
	AccountID string `gorm:"index"`
	// ParentID is empty for a top-level domain. A non-empty ParentID must
	// name another Domain in the same account.
	ParentID string `gorm:"index"`
	// Label is this domain's own DNS label, validated the same way a
	// device's name is (KarstDNS grammar: nbdns.GetParsedDomainLabel).
	Label string
	// Path is Label, or Label + "." + the parent's Path for a subdomain --
	// root-to-leaf order, matching how a DNS name reads. It is what actually
	// gets inserted into a member peer's DNSLabel.
	Path string
}

// TableName overrides gorm's default pluralized-struct-name convention
// ("domains"), which would otherwise collide with the pre-existing,
// unrelated reverseproxy/domain.Domain -- gorm names tables after the bare
// struct name, not the package, so two different "Domain" types across two
// packages default to the exact same table without this.
func (Domain) TableName() string {
	return "mesh_domains"
}

func NewDomain(accountID, parentID, label, parentPath string) *Domain {
	path := label
	if parentPath != "" {
		path = label + "." + parentPath
	}
	return &Domain{
		ID:        xid.New().String(),
		AccountID: accountID,
		ParentID:  parentID,
		Label:     label,
		Path:      path,
	}
}

// Validate checks Label in isolation. Sibling-uniqueness and parent-account
// checks need store access and live in the manager instead.
func (d *Domain) Validate() error {
	if len(d.Label) > 63 {
		return errors.New("domain label exceeds maximum length of 63 characters")
	}
	label, err := nbdns.GetParsedDomainLabel(d.Label)
	if err != nil || label != d.Label || strings.Trim(label, "-") == "" {
		return errors.New("domain label must be a valid DNS label (letters, digits, hyphens, at least one letter or digit)")
	}
	return nil
}

// QualifyLabel inserts this domain's Path ahead of a bare peer DNS label,
// the same composition every member peer's DNSLabel uses.
func (d *Domain) QualifyLabel(label string) string {
	if d == nil || d.Path == "" {
		return label
	}
	return label + "." + d.Path
}

// EventMeta returns activity event meta related to the domain.
func (d *Domain) EventMeta() map[string]any {
	return map[string]any{"label": d.Label, "path": d.Path, "parent_id": d.ParentID}
}
