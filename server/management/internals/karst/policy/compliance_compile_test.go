// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package policy

import (
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"github.com/netbirdio/netbird/management/internals/karst/compliance"
	"github.com/stretchr/testify/require"
)

func compilationFixture() (*Document, ComplianceDraft, []ComplianceDevice, time.Time) {
	d, draft, nodes, flow, evidence, now := complianceFixture()
	d.ACLs = []Rule{
		{Action: "accept", Src: []string{"*"}, Dst: []string{"*:22,443", "10.99.0.0/24:443"}},
		{Action: "accept", Src: []string{"group:engineers"}, Dst: []string{"prod:443"}},
	}
	d.Groups["group:engineers"] = []string{"engineer"}
	devices := []ComplianceDevice{
		{Node: Node{Handle: "laptop", User: "engineer", Addresses: []string{"100.64.0.1/32"}}, Subject: flow.Subject, Evidence: evidence},
		{Node: Node{Handle: "desktop", User: "engineer", Addresses: []string{"100.64.0.2/32"}}, Subject: compliance.Subject{TenantID: draft.TenantID, DeviceID: "device-b"}},
		{Node: nodes[0], Subject: compliance.Subject{TenantID: draft.TenantID, DeviceID: "prod"}},
		{Node: nodes[1], Subject: compliance.Subject{TenantID: draft.TenantID, DeviceID: "help"}},
	}
	failing := *evidence
	failing.Subject = devices[1].Subject
	failing.ClientVersion.Version = "1.1.0"
	devices[1].Evidence = &failing
	return d, draft, devices, now
}

func TestCompiledComplianceSeparatesSameUserDevicesWithoutChangingACLs(t *testing.T) {
	d, draft, devices, now := compilationFixture()
	roster := []Node{}
	for _, device := range devices {
		roster = append(roster, device.Node)
	}
	identity, err := d.Compile(devices[2].Node, roster)
	require.NoError(t, err)
	receiver, err := d.CompileCompliance(draft, devices, "prod", nil, now)
	require.NoError(t, err)
	remediation, err := d.CompileCompliance(draft, devices, "help", nil, now)
	require.NoError(t, err)
	require.Empty(t, remediation.Ingress)
	for _, source := range []string{"laptop", "desktop"} {
		t.Run(source, func(t *testing.T) {
			require.True(t, identity.Permits(source, 443), "both overlapping identity grants remain present")
			sender, err := d.CompileCompliance(draft, devices, source, nil, now)
			require.NoError(t, err)
			prod := netip.MustParseAddr("100.64.0.3")
			expected := source == "laptop"
			require.Equal(t, expected, receiver.IngressSatisfied(source, prod, "tcp", 443, now))
			require.Equal(t, expected, sender.EgressSatisfied(prod, "tcp", 443, now))
			help := netip.MustParseAddr("100.64.0.4")
			require.True(t, remediation.IngressSatisfied(source, help, "tcp", 443, now))
			require.True(t, sender.EgressSatisfied(help, "tcp", 443, now))
			for _, gate := range sender.Egress {
				for _, decision := range gate.Sources {
					require.Equal(t, source, decision.Handle)
				}
			}
		})
	}
	require.False(t, receiver.IngressSatisfied("not-enrolled", netip.MustParseAddr("100.64.0.3"), "tcp", 443, now))
	require.Len(t, receiver.Ingress, 1)
	require.Equal(t, []ComplianceSourceDecision{{Handle: "laptop", ValidUntil: now.Add(compliance.EvidenceLifetime)}}, receiver.Ingress[0].Sources)
	// Passing compliance cannot grant traffic that identity or independent SSH denies.
	noIdentity := &Document{}
	filter, err := noIdentity.Compile(devices[2].Node, roster)
	require.NoError(t, err)
	require.False(t, filter.Permits("laptop", 443))
	d.Ssh = []SshRule{}
	ssh, err := d.CompileSSH(devices[2].Node, roster)
	require.NoError(t, err)
	require.False(t, ssh.Permits("laptop", 22))
	require.True(t, receiver.IngressSatisfied("laptop", netip.MustParseAddr("100.64.0.3"), "tcp", 22, now))
}

func TestCompiledComplianceFailureExpiryAndRecovery(t *testing.T) {
	for _, tc := range []struct {
		name    string
		change  func(*compliance.Evidence)
		missing bool
	}{
		{"missing report", func(*compliance.Evidence) {}, true},
		{"missing observation", func(e *compliance.Evidence) { e.ClientVersion = compliance.Observation{} }, false},
		{"unsupported", func(e *compliance.Evidence) {
			e.ClientVersion = compliance.Observation{Status: compliance.NotSupported}
		}, false},
		{"collection error", func(e *compliance.Evidence) {
			e.ClientVersion = compliance.Observation{Status: compliance.CollectionError}
		}, false},
		{"below minimum", func(e *compliance.Evidence) { e.ClientVersion.Version = "1.0.0" }, false},
		{"cross-device evidence", func(e *compliance.Evidence) { e.Subject.DeviceID = "device-b" }, false},
		{"cross-tenant evidence", func(e *compliance.Evidence) { e.Subject.TenantID = "foreign" }, false},
		{"future receipt", func(e *compliance.Evidence) { e.ReceivedAt = e.ReceivedAt.Add(time.Hour) }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, draft, devices, now := compilationFixture()
			bad := *devices[0].Evidence
			tc.change(&bad)
			devices[0].Evidence = &bad
			if tc.missing {
				devices[0].Evidence = nil
			}
			compiled, err := d.CompileCompliance(draft, devices, "prod", nil, now)
			require.NoError(t, err)
			require.Len(t, compiled.Ingress, 1)
			require.Empty(t, compiled.Ingress[0].Sources, "a denial must retain the mandatory gate")
			require.False(t, compiled.IngressSatisfied("laptop", netip.MustParseAddr("100.64.0.3"), "tcp", 443, now))
		})
	}
	d, draft, devices, now := compilationFixture()
	compiled, err := d.CompileCompliance(draft, devices, "prod", nil, now)
	require.NoError(t, err)
	addr := netip.MustParseAddr("100.64.0.3")
	deadline := now.Add(compliance.EvidenceLifetime)
	require.True(t, compiled.IngressSatisfied("laptop", addr, "tcp", 443, deadline.Add(-time.Nanosecond)))
	require.False(t, compiled.IngressSatisfied("laptop", addr, "tcp", 443, deadline))
	late, err := d.CompileCompliance(draft, devices, "prod", nil, deadline.Add(-time.Second))
	require.NoError(t, err)
	require.Equal(t, deadline, late.Ingress[0].Sources[0].ValidUntil, "recompiling must not restart evidence freshness")
	expired, err := d.CompileCompliance(draft, devices, "prod", nil, deadline)
	require.NoError(t, err)
	require.Empty(t, expired.Ingress[0].Sources)
	fresh := *devices[0].Evidence
	fresh.ReceivedAt = deadline
	devices[0].Evidence = &fresh
	recovered, err := d.CompileCompliance(draft, devices, "prod", nil, deadline)
	require.NoError(t, err)
	require.True(t, recovered.IngressSatisfied("laptop", addr, "tcp", 443, deadline))
	require.False(t, compiled.IngressSatisfied("laptop", addr, "tcp", 443, deadline), "a new report cannot mutate an old snapshot")
}

func TestCompiledComplianceRoutesUseGatewayOwnershipAndCIDRIntersections(t *testing.T) {
	for _, tc := range []struct{ guard, route, inside, outside string }{
		{"10.99.0.0/24", "10.99.0.0/16", "10.99.0.2", "10.99.1.2"},
		{"10.99.0.0/16", "10.99.0.0/24", "10.99.0.2", "10.99.1.2"},
		{"fd00:99::/64", "fd00::/16", "fd00:99::2", "fd00:98::2"},
		{"fd00::/16", "fd00:99::/64", "fd00:99::2", "fd00:98::2"},
	} {
		t.Run(tc.guard+" via "+tc.route, func(t *testing.T) {
			d, draft, devices, now := compilationFixture()
			draft.Guardrails[0].Resource.Selector = tc.guard
			gateway, err := d.CompileCompliance(draft, devices, "prod", []string{tc.route}, now)
			require.NoError(t, err)
			require.Len(t, gateway.Ingress, 1)
			require.False(t, gateway.IngressSatisfied("desktop", netip.MustParseAddr(tc.inside), "tcp", 443, now))
			require.True(t, gateway.IngressSatisfied("laptop", netip.MustParseAddr(tc.inside), "tcp", 443, now))
			require.True(t, gateway.IngressSatisfied("desktop", netip.MustParseAddr(tc.outside), "tcp", 443, now), "a gateway receives no gate outside its current prefix intersection")
			standby, err := d.CompileCompliance(draft, devices, "help", nil, now)
			require.NoError(t, err)
			require.Empty(t, standby.Ingress)
			sender, err := d.CompileCompliance(draft, devices, "desktop", nil, now)
			require.NoError(t, err)
			require.False(t, sender.EgressSatisfied(netip.MustParseAddr(tc.inside), "tcp", 443, now))
		})
	}
	d, draft, devices, now := compilationFixture()
	gateway, err := d.CompileCompliance(draft, devices, "prod", []string{"10.99.0.0/24"}, now)
	require.NoError(t, err)
	require.True(t, gateway.IngressSatisfied("desktop", netip.MustParseAddr("10.99.0.2"), "tcp", 443, now), "a guard on the gateway node is not a guard on its LAN")
	draft.Remediation = nil
	draft.Guardrails[0].Resource.Selector = "*"
	gateway, err = d.CompileCompliance(draft, devices, "prod", []string{"0.0.0.0/0", "::/0"}, now)
	require.NoError(t, err)
	require.False(t, gateway.IngressSatisfied("desktop", netip.MustParseAddr("2001:db8::2"), "tcp", 443, now))
	require.False(t, gateway.IngressSatisfied("desktop", netip.MustParseAddr("203.0.113.2"), "tcp", 443, now))
	require.True(t, gateway.IngressSatisfied("desktop", netip.MustParseAddr("203.0.113.2"), "udp", 443, now))
}

func TestCompiledComplianceOverlapsAndPreviewAgree(t *testing.T) {
	d, draft, devices, now := compilationFixture()
	draft.Guardrails = append(draft.Guardrails, ComplianceGuardrail{ID: "stricter-os", Resource: ComplianceResource{Selector: "100.64.0.0/24", Protocol: "tcp", Ports: PortRange{443, 443}}, RequirementSets: []string{"client", "os"}})
	draft.Remediation = nil
	older := *devices[0].Evidence
	older.OSVersion.Version = "22.04"
	devices[0].Evidence = &older
	receiver, err := d.CompileCompliance(draft, devices, "prod", nil, now)
	require.NoError(t, err)
	require.Len(t, receiver.Ingress, 2)
	nodes := []Node{}
	for _, device := range devices {
		nodes = append(nodes, device.Node)
	}
	for _, device := range devices[:2] {
		sender, err := d.CompileCompliance(draft, devices, device.Node.Handle, nil, now)
		require.NoError(t, err)
		for _, protocol := range []string{"tcp", "udp"} {
			for _, port := range []uint16{21, 22, 443, 444} {
				flow := ComplianceFlow{Subject: device.Subject, DestinationHandle: "prod", Address: netip.MustParseAddr("100.64.0.3"), Protocol: protocol, Port: port, IdentityAllowed: true, SSHAllowed: true}
				preview, err := d.PreviewCompliance(draft, nodes, flow, device.Evidence, now)
				require.NoError(t, err)
				require.Equal(t, preview.Allowed, receiver.IngressSatisfied(device.Node.Handle, flow.Address, protocol, port, now))
				require.Equal(t, preview.Allowed, sender.EgressSatisfied(flow.Address, protocol, port, now))
			}
		}
	}
	require.False(t, receiver.IngressSatisfied("laptop", netip.MustParseAddr("100.64.0.3"), "tcp", 443, now), "a passing first guard cannot bypass a failing overlapping guard")
}

func TestCompiledComplianceDeterminismAndInvalidInputs(t *testing.T) {
	d, draft, devices, now := compilationFixture()
	draft.Guardrails = append(draft.Guardrails, ComplianceGuardrail{ID: "lan", Resource: ComplianceResource{Selector: "10.99.0.0/16", Protocol: "*", Ports: AllPorts}, RequirementSets: []string{"client"}})
	first, err := d.CompileCompliance(draft, devices, "prod", []string{"10.99.1.0/24", "10.99.0.0/24"}, now)
	require.NoError(t, err)
	for i, j := 0, len(devices)-1; i < j; i, j = i+1, j-1 {
		devices[i], devices[j] = devices[j], devices[i]
	}
	draft.Guardrails[0], draft.Guardrails[1] = draft.Guardrails[1], draft.Guardrails[0]
	second, err := d.CompileCompliance(draft, devices, "prod", []string{"10.99.0.0/24", "10.99.1.0/24", "10.99.1.0/24"}, now)
	require.NoError(t, err)
	a, err := json.Marshal(first)
	require.NoError(t, err)
	b, err := json.Marshal(second)
	require.NoError(t, err)
	require.Equal(t, string(a), string(b))
	for _, tc := range []struct {
		name   string
		change func([]ComplianceDevice) []ComplianceDevice
	}{
		{"duplicate handle", func(ds []ComplianceDevice) []ComplianceDevice { return append(ds, ds[0]) }},
		{"duplicate device", func(ds []ComplianceDevice) []ComplianceDevice {
			ds[0].Subject.DeviceID = ds[1].Subject.DeviceID
			return ds
		}},
		{"foreign tenant", func(ds []ComplianceDevice) []ComplianceDevice { ds[0].Subject.TenantID = "foreign"; return ds }},
		{"empty device", func(ds []ComplianceDevice) []ComplianceDevice { ds[0].Subject.DeviceID = ""; return ds }},
		{"wildcard handle", func(ds []ComplianceDevice) []ComplianceDevice { ds[0].Node.Handle = "*"; return ds }},
		{"no addresses", func(ds []ComplianceDevice) []ComplianceDevice { ds[0].Node.Addresses = nil; return ds }},
		{"invalid address", func(ds []ComplianceDevice) []ComplianceDevice { ds[0].Node.Addresses = []string{"bad"}; return ds }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, draft, ds, now := compilationFixture()
			compiled, err := d.CompileCompliance(draft, tc.change(ds), "prod", nil, now)
			require.Error(t, err)
			require.Nil(t, compiled)
		})
	}
	d, draft, devices, now = compilationFixture()
	for _, routes := range [][]string{{"10.99.0.0/99"}, {"::ffff:10.99.0.0/120"}} {
		compiled, err := d.CompileCompliance(draft, devices, "prod", routes, now)
		require.Error(t, err)
		require.Nil(t, compiled)
	}
	_, err = d.CompileCompliance(draft, devices, "not-enrolled", nil, now)
	require.Error(t, err)
	_, err = d.CompileCompliance(draft, devices, "prod", nil, time.Time{})
	require.Error(t, err)
	zero := &ComplianceCompilation{}
	require.False(t, zero.IngressSatisfied("laptop", netip.MustParseAddr("100.64.0.3"), "tcp", 443, now))
	require.False(t, first.EgressSatisfied(netip.MustParseAddr("100.64.0.3"), "tcp", 443, now.Add(-time.Second)))
	require.False(t, first.IngressSatisfied("*", netip.MustParseAddr("100.64.0.3"), "tcp", 443, now))
	require.False(t, first.EgressSatisfied(netip.MustParseAddr("::ffff:100.64.0.3"), "tcp", 443, now))
}

func TestCompiledComplianceReevaluatesPolicyAndEnrollment(t *testing.T) {
	d, draft, devices, now := compilationFixture()
	destination := netip.MustParseAddr("100.64.0.3")
	original, err := d.CompileCompliance(draft, devices, "prod", nil, now)
	require.NoError(t, err)
	require.True(t, original.IngressSatisfied("laptop", destination, "tcp", 443, now))
	draft.RequirementSets["client"][0].MinimumVersion = "2.0.0"
	stricter, err := d.CompileCompliance(draft, devices, "prod", nil, now)
	require.NoError(t, err)
	require.False(t, stricter.IngressSatisfied("laptop", destination, "tcp", 443, now))
	draft.RequirementSets["client"][0].MinimumVersion = "1.2.0"
	removed, err := d.CompileCompliance(draft, devices[1:], "prod", nil, now)
	require.NoError(t, err)
	require.False(t, removed.IngressSatisfied("laptop", destination, "tcp", 443, now))
	// Removing the tag removes this resource match, independently of identity grants.
	devices[2].Node.Tags = nil
	changed, err := d.CompileCompliance(draft, devices, "prod", nil, now)
	require.NoError(t, err)
	require.Empty(t, changed.Ingress)
	// A selector change that protects a remediation node must fail the whole draft.
	devices[3].Node.Tags = []string{"tag:prod"}
	invalid, err := d.CompileCompliance(draft, devices, "prod", nil, now)
	require.ErrorContains(t, err, "remediation overlaps")
	require.Nil(t, invalid)
}
