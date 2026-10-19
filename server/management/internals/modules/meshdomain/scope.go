// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package meshdomain

// AdminScope is a snapshot of a user's delegated authority in one account.
// DNS paths are display data: only bound domain IDs and parent edges establish
// containment. Build one snapshot per operation, not one per listed resource.
type AdminScope struct {
	domains map[string]*Domain
	grants  map[string]bool
}

// NewAdminScope combines account-local graph rows with this user's bindings.
// Missing or foreign rows never become authority through a matching DNS path.
func NewAdminScope(accountID, userID string, domains []*Domain, bindings []*DomainRoleBinding) *AdminScope {
	scope := &AdminScope{domains: make(map[string]*Domain), grants: make(map[string]bool)}
	for _, domain := range domains {
		if domain != nil && domain.AccountID == accountID && domain.ID != "" {
			// Copy the graph so a caller cannot change an authorization
			// snapshot by mutating a row it passed to the constructor.
			copy := *domain
			scope.domains[domain.ID] = &copy
		}
	}
	for _, binding := range bindings {
		if binding != nil && binding.AccountID == accountID && binding.UserID == userID && scope.domains[binding.DomainID] != nil {
			scope.grants[binding.DomainID] = true
		}
	}
	return scope
}

// Covers includes the bound domain and descendants. Validate the entire
// ancestry before accepting a grant: missing parents, cross-account edges,
// and cycles must fail closed even when a grant occurs before the bad edge.
// An empty ID means the legacy implicit root and never carries a delegation.
func (s *AdminScope) Covers(domainID string) bool {
	if s == nil || domainID == "" {
		return false
	}
	seen := make(map[string]bool)
	allowed := false
	for domainID != "" {
		if seen[domainID] {
			return false
		}
		seen[domainID] = true
		domain := s.domains[domainID]
		if domain == nil {
			return false
		}
		allowed = allowed || s.grants[domainID]
		domainID = domain.ParentID
	}
	return allowed
}
