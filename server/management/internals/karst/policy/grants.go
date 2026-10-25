// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package policy

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
)

// Grant is the persisted, form-driven authorization contract. Group IDs refer
// to the account registry, not to legacy policy user lists. A grant is additive
// to preserved legacy rules until an administrator explicitly migrates them.
type Grant struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	SourceGroups []string `json:"source_groups"`
	TargetGroups []string `json:"target_groups,omitempty"`
	TargetNodes  []string `json:"target_nodes,omitempty"`
	Networks     []string `json:"networks,omitempty"`
	Ports        string   `json:"ports"`
	SSH          bool     `json:"ssh,omitempty"`
}

func contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}

func (d *Document) UsesRegistryGroups() bool { return len(d.Grants) != 0 || len(d.GroupBindings) != 0 }

func (d *Document) RegistryGroupIDs() []string {
	var ids []string
	for _, id := range d.GroupBindings {
		ids = append(ids, id)
	}
	for _, grant := range d.Grants {
		ids = append(ids, grant.SourceGroups...)
		ids = append(ids, grant.TargetGroups...)
	}
	return ids
}

func (d *Document) validateGrants() error {
	ids := map[string]bool{}
	for name, id := range d.GroupBindings {
		if !strings.HasPrefix(name, "group:") || id == "" {
			return fmt.Errorf("%w: invalid group binding", ErrInvalid)
		}
		if _, ok := d.Groups[name]; !ok {
			return fmt.Errorf("%w: binding names an unknown legacy group", ErrInvalid)
		}
	}
	for _, g := range d.Grants {
		if g.ID == "" || ids[g.ID] || strings.TrimSpace(g.Name) == "" {
			return fmt.Errorf("%w: grant needs a unique ID and name", ErrInvalid)
		}
		ids[g.ID] = true
		if len(g.SourceGroups) == 0 || len(g.TargetGroups)+len(g.TargetNodes)+len(g.Networks) == 0 {
			return fmt.Errorf("%w: grant needs source groups and a destination", ErrInvalid)
		}
		for _, id := range append(append([]string{}, g.SourceGroups...), g.TargetGroups...) {
			if strings.TrimSpace(id) == "" || strings.ContainsAny(id, ":*\n\r") {
				return fmt.Errorf("%w: invalid registry group ID", ErrInvalid)
			}
		}
		for _, node := range g.TargetNodes {
			if node == "" || strings.ContainsAny(node, ":*\n\r") {
				return fmt.Errorf("%w: invalid target node", ErrInvalid)
			}
		}
		for _, network := range g.Networks {
			if _, err := netip.ParsePrefix(network); err != nil {
				return fmt.Errorf("%w: invalid destination network", ErrInvalid)
			}
		}
		if _, err := parsePorts(g.Ports); err != nil {
			return fmt.Errorf("%w: invalid grant ports: %v", ErrInvalid, err)
		}
		if g.SSH && len(g.Networks) > 0 {
			return fmt.Errorf("%w: SSH gates apply to machines, not routed networks", ErrInvalid)
		}
	}
	return nil
}

func (d *Document) packetRules() []Rule {
	rules := append([]Rule{}, d.ACLs...)
	for _, g := range d.Grants {
		var src, dst []string
		for _, id := range g.SourceGroups {
			src = append(src, "group-id:"+id)
		}
		for _, id := range g.TargetGroups {
			dst = append(dst, "group-id:"+id+":"+g.Ports)
		}
		for _, id := range g.TargetNodes {
			dst = append(dst, id+":"+g.Ports)
		}
		for _, network := range g.Networks {
			prefix, _ := netip.ParsePrefix(network)
			dst = append(dst, prefix.Masked().String()+":"+g.Ports)
		}
		rules = append(rules, Rule{Action: "accept", Src: src, Dst: dst})
	}
	return rules
}

func (d *Document) hasSSHGrants() bool {
	for _, g := range d.Grants {
		if g.SSH {
			return true
		}
	}
	return false
}
func (d *Document) sshRules() []SshRule {
	rules := append([]SshRule{}, d.Ssh...)
	for _, g := range d.Grants {
		if !g.SSH {
			continue
		}
		var src, dst []string
		for _, id := range g.SourceGroups {
			src = append(src, "group-id:"+id)
		}
		for _, id := range g.TargetGroups {
			dst = append(dst, "group-id:"+id)
		}
		dst = append(dst, g.TargetNodes...)
		rules = append(rules, SshRule{Action: "accept", Src: src, Dst: dst})
	}
	return rules
}

// MarshalJSON retains the empty SSH gate during automatic resource changes.
// Omitting an explicitly empty gate would turn deny-all SSH into ACL-only SSH.
func (d Document) MarshalJSON() ([]byte, error) {
	type documentAlias Document
	if d.Ssh == nil {
		return json.Marshal(documentAlias(d))
	}
	return json.Marshal(struct {
		documentAlias
		SSH []SshRule `json:"ssh"`
	}{documentAlias(d), d.Ssh})
}
