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
// DomainPath is retained as historical/display metadata. Authorization uses
// DomainID and the current parent graph through AdminScope, never this cache.
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
