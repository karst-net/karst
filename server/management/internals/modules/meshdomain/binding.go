// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package meshdomain

import "github.com/rs/xid"

// DomainRoleBinding grants UserID delegated admin rights over DomainID and
// everything beneath it -- ADR-0032's "top-level domain administrators
// should be able to create subdomains and delegate their administration"
// requirement. It is purely additive: an account-wide role (owner, admin)
// already covers every domain and never needs a binding.
//
// DomainPath is copied from the target Domain at bind time and used for
// subtree containment checks (permissions.Manager.ValidateDomainScopedPermission)
// without a second store round trip. Domains are append-only in this phase
// (no re-parenting), so this denormalized copy cannot go stale.
type DomainRoleBinding struct {
	ID         string `gorm:"primaryKey"`
	AccountID  string `gorm:"index"`
	DomainID   string `gorm:"index"`
	DomainPath string
	UserID     string `gorm:"index"`
}

// TableName is explicit for the same reason Domain.TableName is -- see its
// comment. This one does not currently collide with anything, but an
// implicit table name for a type this generically named ("domain_role_
// bindings") is exactly the kind of thing that silently collides later.
func (DomainRoleBinding) TableName() string {
	return "mesh_domain_role_bindings"
}

func NewDomainRoleBinding(accountID, domainID, domainPath, userID string) *DomainRoleBinding {
	return &DomainRoleBinding{
		ID:         xid.New().String(),
		AccountID:  accountID,
		DomainID:   domainID,
		DomainPath: domainPath,
		UserID:     userID,
	}
}

// Covers reports whether this binding's subtree contains the domain at
// candidatePath -- either the delegated domain itself or a descendant of it.
// Labels are already sanitized to [a-zA-Z0-9-] (Domain.Validate), so a
// same-or-suffix-after-a-dot match cannot cross a label boundary by
// accident.
func (b *DomainRoleBinding) Covers(candidatePath string) bool {
	if b.DomainPath == "" || candidatePath == "" {
		return false
	}
	return candidatePath == b.DomainPath || len(candidatePath) > len(b.DomainPath) &&
		candidatePath[len(candidatePath)-len(b.DomainPath)-1:] == "."+b.DomainPath
}
