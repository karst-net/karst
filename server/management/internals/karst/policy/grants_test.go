// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package policy

import "testing"

func TestRegistryGrantLifecycle(t *testing.T) {
	doc := &Document{Grants: []Grant{{ID: "rule", Name: "Engineering to server", SourceGroups: []string{"engineering"}, TargetNodes: []string{"server"}, Ports: "443"}}}
	if err := doc.Validate(); err != nil {
		t.Fatal(err)
	}
	nodes := []Node{{Handle: "laptop", GroupIDs: []string{"engineering"}}, {Handle: "server"}, {Handle: "outsider"}}
	check := func(want bool) {
		t.Helper()
		inbound, err := doc.Compile(nodes[1], nodes)
		if err != nil {
			t.Fatal(err)
		}
		outbound, err := doc.CompileEgress(nodes[0], nodes)
		if err != nil {
			t.Fatal(err)
		}
		if inbound.Permits("laptop", 443) != want || outbound.Permits("server", 443) != want {
			t.Fatal("membership change did not affect both filters")
		}
		if inbound.Permits("outsider", 443) || inbound.Permits("laptop", 80) {
			t.Fatal("grant broadened access")
		}
	}
	check(true)
	nodes[0].Inactive = true
	check(false)
	nodes[0].Inactive = false
	check(true)
	nodes[0].GroupIDs = nil
	check(false)
}

func TestRegistryGrantNetworksAndSSH(t *testing.T) {
	d := &Document{Grants: []Grant{{ID: "exit", Name: "Internet", SourceGroups: []string{"g"}, Networks: []string{"0.0.0.0/0"}, Ports: "*"}}}
	n := Node{Handle: "laptop", GroupIDs: []string{"g"}}
	e, err := d.CompileEgress(n, []Node{n})
	if err != nil || !e.Permits("8.8.8.8", 443) {
		t.Fatalf("network grant: %v", err)
	}
	d.Grants = []Grant{{ID: "ssh", Name: "SSH", SourceGroups: []string{"g"}, TargetGroups: []string{"servers"}, Ports: "22", SSH: true}}
	target := Node{Handle: "server", GroupIDs: []string{"servers"}}
	gate, err := d.CompileSSH(target, []Node{n, target})
	if err != nil || gate == nil || !gate.Permits("laptop", 22) {
		t.Fatalf("SSH grant: %v", err)
	}
	n.GroupIDs = nil
	gate, err = d.CompileSSH(target, []Node{n, target})
	if err != nil || gate.Permits("laptop", 22) {
		t.Fatal("SSH membership revocation failed")
	}
}

func TestExplicitLegacyBinding(t *testing.T) {
	d := &Document{Groups: map[string][]string{"group:engineering": {"old-user"}}, GroupBindings: map[string]string{"group:engineering": "stable-id"}, ACLs: []Rule{{Action: "accept", Src: []string{"group:engineering"}, Dst: []string{"server:443"}}}}
	nodes := []Node{{Handle: "old", User: "old-user"}, {Handle: "new", GroupIDs: []string{"stable-id"}}, {Handle: "server"}}
	f, err := d.Compile(nodes[2], nodes)
	if err != nil || f.Permits("old", 443) || !f.Permits("new", 443) {
		t.Fatalf("explicit migration: %v", err)
	}
	delete(d.GroupBindings, "group:engineering")
	f, err = d.Compile(nodes[2], nodes)
	if err != nil || !f.Permits("old", 443) || f.Permits("new", 443) {
		t.Fatalf("legacy preservation: %v", err)
	}
}
