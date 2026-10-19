// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package policy

import (
	"net/netip"
	"testing"
	"time"

	"github.com/netbirdio/netbird/management/internals/karst/compliance"
	"github.com/stretchr/testify/require"
)

func complianceFixture() (*Document, ComplianceDraft, []Node, ComplianceFlow, *compliance.Evidence, time.Time) {
	d := &Document{Groups: map[string][]string{"group:ops": {"operator"}}}
	nodes := []Node{{Handle: "prod", User: "operator", Tags: []string{"tag:prod"}, Addresses: []string{"100.64.0.3/32"}}, {Handle: "help", Addresses: []string{"100.64.0.4/32"}}}
	draft := ComplianceDraft{TenantID: "tenant-a", RequirementSets: map[string][]compliance.Requirement{
		"client": {{ID: "client-version", Kind: compliance.MinimumClientVersion, MinimumVersion: "1.2.0", Provenance: compliance.SelfReported}},
		"os":     {{ID: "os-version", Kind: compliance.MinimumOSVersion, Platform: compliance.Linux, Distribution: "ubuntu", MinimumVersion: "24.04", Provenance: compliance.SelfReported}},
	}, Guardrails: []ComplianceGuardrail{{ID: "production", Resource: ComplianceResource{Selector: "tag:prod", Protocol: "tcp", Ports: PortRange{22, 443}}, RequirementSets: []string{"client"}}}, Remediation: []ComplianceResource{{Selector: "help", Protocol: "tcp", Ports: PortRange{443, 443}}}}
	subject := compliance.Subject{TenantID: "tenant-a", DeviceID: "device-a"}
	flow := ComplianceFlow{Subject: subject, DestinationHandle: "prod", Address: netip.MustParseAddr("100.64.0.3"), Protocol: "tcp", Port: 443, IdentityAllowed: true, SSHAllowed: true}
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	evidence := &compliance.Evidence{Subject: subject, ReceivedAt: now, Provenance: compliance.SelfReported, Platform: compliance.Linux, Distribution: "ubuntu", ClientVersion: compliance.Observation{Status: compliance.Collected, Version: "1.2.3"}, OSVersion: compliance.Observation{Status: compliance.Collected, Version: "24.04"}}
	return d, draft, nodes, flow, evidence, now
}

func TestCompliancePreviewDeviceFailureExpiryAndRecovery(t *testing.T) {
	d, draft, nodes, flow, evidence, now := complianceFixture()
	passing, err := d.PreviewCompliance(draft, nodes, flow, evidence, now)
	require.NoError(t, err)
	require.True(t, passing.Allowed)
	require.Equal(t, now.Add(compliance.EvidenceLifetime), passing.ValidUntil)
	require.Equal(t, []string{"production"}, passing.Guardrails)
	for _, tc := range []struct {
		name   string
		mutate func(*compliance.Evidence)
		at     time.Time
		state  compliance.State
	}{
		{"below minimum", func(e *compliance.Evidence) { e.ClientVersion.Version = "1.1.0" }, now, compliance.Noncompliant},
		{"missing value", func(e *compliance.Evidence) { e.ClientVersion = compliance.Observation{} }, now, compliance.Unknown},
		{"unsupported", func(e *compliance.Evidence) {
			e.ClientVersion = compliance.Observation{Status: compliance.NotSupported}
		}, now, compliance.Unsupported},
		{"collection error", func(e *compliance.Evidence) {
			e.ClientVersion = compliance.Observation{Status: compliance.CollectionError}
		}, now, compliance.EvaluationError},
		{"exact expiry", func(*compliance.Evidence) {}, now.Add(compliance.EvidenceLifetime), compliance.Stale},
		{"wrong device", func(e *compliance.Evidence) { e.Subject.DeviceID = "other-device" }, now, compliance.EvaluationError},
		{"wrong tenant", func(e *compliance.Evidence) { e.Subject.TenantID = "other-tenant" }, now, compliance.EvaluationError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := *evidence
			tc.mutate(&changed)
			denied, err := d.PreviewCompliance(draft, nodes, flow, &changed, tc.at)
			require.NoError(t, err)
			require.False(t, denied.Allowed)
			require.True(t, denied.ValidUntil.IsZero())
			require.Equal(t, tc.state, denied.RequirementSets[0].Evaluation.Results[0].State)
			helpFlow := flow
			helpFlow.DestinationHandle = "help"
			helpFlow.Address = netip.MustParseAddr("100.64.0.4")
			help, err := d.PreviewCompliance(draft, nodes, helpFlow, &changed, tc.at)
			require.NoError(t, err)
			require.True(t, help.Allowed)
			require.Empty(t, help.Guardrails)
		})
	}
	missing, err := d.PreviewCompliance(draft, nodes, flow, nil, now)
	require.NoError(t, err)
	require.False(t, missing.Allowed)
	// A second device of the same user can recover without changing any identity grant.
	flow.Subject.DeviceID = "device-b"
	recovered := *evidence
	recovered.Subject = flow.Subject
	recovered.ReceivedAt = now.Add(time.Minute)
	preview, err := d.PreviewCompliance(draft, nodes, flow, &recovered, now.Add(time.Minute))
	require.NoError(t, err)
	require.True(t, preview.Allowed)
	flow.IdentityAllowed = false
	preview, err = d.PreviewCompliance(draft, nodes, flow, &recovered, now.Add(time.Minute))
	require.NoError(t, err)
	require.False(t, preview.Allowed)
}

func TestCompliancePreviewOverlapsAreConjunctiveAndPreserveSSH(t *testing.T) {
	d, draft, nodes, flow, evidence, now := complianceFixture()
	draft.Guardrails = append(draft.Guardrails, ComplianceGuardrail{ID: "all-ops", Resource: ComplianceResource{Selector: "group:ops", Protocol: "*", Ports: AllPorts}, RequirementSets: []string{"os", "client"}})
	evidence.OSVersion.Version = "22.04"
	preview, err := d.PreviewCompliance(draft, nodes, flow, evidence, now)
	require.NoError(t, err)
	require.False(t, preview.Allowed)
	require.Equal(t, []string{"all-ops", "production"}, preview.Guardrails)
	require.Len(t, preview.RequirementSets, 2)
	require.Equal(t, "client", preview.RequirementSets[0].ID)
	require.Equal(t, "os", preview.RequirementSets[1].ID)
	require.True(t, preview.ValidUntil.IsZero())
	evidence.OSVersion.Version = "24.04"
	flow.Port = 22
	flow.SSHAllowed = false
	preview, err = d.PreviewCompliance(draft, nodes, flow, evidence, now)
	require.NoError(t, err)
	require.False(t, preview.Allowed)
	flow.Port = 443
	preview, err = d.PreviewCompliance(draft, nodes, flow, evidence, now)
	require.NoError(t, err)
	require.True(t, preview.Allowed)
}

func TestComplianceRoutedAndIPv6Resources(t *testing.T) {
	for _, cidr := range []string{"10.99.0.0/24", "fd00:99::/64"} {
		t.Run(cidr, func(t *testing.T) {
			d, draft, nodes, flow, evidence, now := complianceFixture()
			draft.Guardrails[0].Resource.Selector = cidr
			flow.DestinationHandle = ""
			flow.Address = netip.MustParsePrefix(cidr).Addr().Next()
			preview, err := d.PreviewCompliance(draft, nodes, flow, nil, now)
			require.NoError(t, err)
			require.False(t, preview.Allowed)
			require.Len(t, preview.Guardrails, 1)
			preview, err = d.PreviewCompliance(draft, nodes, flow, evidence, now)
			require.NoError(t, err)
			require.True(t, preview.Allowed)
			flow.Protocol = "udp"
			preview, err = d.PreviewCompliance(draft, nodes, flow, nil, now)
			require.NoError(t, err)
			require.True(t, preview.Allowed)
			// A gateway identity selector must not accidentally protect/grant its routed LAN.
			draft.Guardrails[0].Resource.Selector = "prod"
			flow.Protocol = "tcp"
			preview, err = d.PreviewCompliance(draft, nodes, flow, nil, now)
			require.NoError(t, err)
			require.Empty(t, preview.Guardrails)
		})
	}
}

func TestComplianceRemediationIntersections(t *testing.T) {
	for _, tc := range []struct {
		name, guard, help, protocol string
		ports                       PortRange
		conflict                    bool
	}{
		{"wildcard", "*", "help", "tcp", PortRange{443, 443}, true},
		{"same handle", "prod", "prod", "tcp", PortRange{443, 443}, true},
		{"tag and user group", "tag:prod", "group:ops", "tcp", PortRange{443, 443}, true},
		{"node and cidr", "tag:prod", "100.64.0.0/24", "tcp", PortRange{443, 443}, true},
		{"cidr and node", "100.64.0.0/24", "prod", "tcp", PortRange{443, 443}, true},
		{"nested cidrs", "10.99.0.0/16", "10.99.1.0/24", "tcp", PortRange{443, 443}, true},
		{"disjoint cidrs", "10.99.0.0/24", "10.98.0.0/24", "tcp", PortRange{443, 443}, false},
		{"other protocol", "prod", "prod", "udp", PortRange{443, 443}, false},
		{"other ports", "prod", "prod", "tcp", PortRange{444, 445}, false},
		{"port boundary", "prod", "prod", "tcp", PortRange{443, 444}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, draft, nodes, _, _, _ := complianceFixture()
			draft.Guardrails[0].Resource.Selector = tc.guard
			draft.Remediation = []ComplianceResource{{Selector: tc.help, Protocol: tc.protocol, Ports: tc.ports}}
			err := d.ValidateComplianceDraft(draft, nodes)
			if tc.conflict {
				require.ErrorContains(t, err, "remediation overlaps")
			} else {
				require.NoError(t, err)
			}
		})
	}
	d, draft, nodes, _, _, _ := complianceFixture()
	require.NoError(t, d.ValidateComplianceDraft(draft, nodes))
	nodes[1].Tags = []string{"tag:prod"}
	require.ErrorContains(t, d.ValidateComplianceDraft(draft, nodes), "remediation overlaps")
}

func TestComplianceInvalidDraftsAndSubjectsDeny(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*ComplianceDraft)
	}{
		{"tenant", func(p *ComplianceDraft) { p.TenantID = "" }},
		{"missing set", func(p *ComplianceDraft) { delete(p.RequirementSets, "client") }},
		{"empty set", func(p *ComplianceDraft) { p.RequirementSets["client"] = nil }},
		{"bad requirement", func(p *ComplianceDraft) { p.RequirementSets["client"][0].MinimumVersion = "dev" }},
		{"duplicate requirement", func(p *ComplianceDraft) {
			p.RequirementSets["client"] = append(p.RequirementSets["client"], p.RequirementSets["client"][0])
		}},
		{"duplicate guard", func(p *ComplianceDraft) { p.Guardrails = append(p.Guardrails, p.Guardrails[0]) }},
		{"no references", func(p *ComplianceDraft) { p.Guardrails[0].RequirementSets = nil }},
		{"duplicate reference", func(p *ComplianceDraft) { p.Guardrails[0].RequirementSets = []string{"client", "client"} }},
		{"bad cidr", func(p *ComplianceDraft) { p.Guardrails[0].Resource.Selector = "10.0.0.0/99" }},
		{"undefined group", func(p *ComplianceDraft) { p.Guardrails[0].Resource.Selector = "group:missing" }},
		{"bad protocol", func(p *ComplianceDraft) { p.Guardrails[0].Resource.Protocol = "icmp" }},
		{"reversed ports", func(p *ComplianceDraft) { p.Guardrails[0].Resource.Ports = PortRange{443, 22} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, draft, nodes, flow, evidence, now := complianceFixture()
			tc.change(&draft)
			preview, err := d.PreviewCompliance(draft, nodes, flow, evidence, now)
			require.Error(t, err)
			require.False(t, preview.Allowed)
			require.True(t, preview.ValidUntil.IsZero())
		})
	}
	d, draft, nodes, flow, evidence, now := complianceFixture()
	flow.Subject.TenantID = "other"
	preview, err := d.PreviewCompliance(draft, nodes, flow, evidence, now)
	require.Error(t, err)
	require.False(t, preview.Allowed)
	// The ordinary policy parser must keep rejecting activation of the draft model.
	_, err = Parse([]byte(`{"acls":[],"compliance":{"guardrails":[]}}`))
	require.ErrorIs(t, err, ErrParse)
}

func TestCompliancePreviewRejectsInconsistentFlowInputs(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*ComplianceFlow)
	}{
		{"unknown node", func(f *ComplianceFlow) { f.DestinationHandle = "foreign" }},
		{"gateway cannot stand in for routed destination", func(f *ComplianceFlow) { f.Address = netip.MustParseAddr("10.99.0.2") }},
		{"missing device", func(f *ComplianceFlow) { f.Subject.DeviceID = "" }},
		{"missing address", func(f *ComplianceFlow) { f.Address = netip.Addr{} }},
		{"mapped address", func(f *ComplianceFlow) { f.Address = netip.MustParseAddr("::ffff:100.64.0.3") }},
		{"zoned address", func(f *ComplianceFlow) { f.Address = netip.MustParseAddr("fe80::1%eth0") }},
		{"unknown protocol", func(f *ComplianceFlow) { f.Protocol = "icmp" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, draft, nodes, flow, evidence, now := complianceFixture()
			tc.change(&flow)
			preview, err := d.PreviewCompliance(draft, nodes, flow, evidence, now)
			require.Error(t, err)
			require.False(t, preview.Allowed)
		})
	}
	d, draft, nodes, flow, evidence, _ := complianceFixture()
	_, err := d.PreviewCompliance(draft, nodes, flow, evidence, time.Time{})
	require.Error(t, err)
	for _, selector := range []string{"tag:prod:443", "100.64.0.3", "::ffff:100.64.0.0/120"} {
		draft.Guardrails[0].Resource.Selector = selector
		require.Error(t, d.ValidateComplianceDraft(draft, nodes))
	}
}

func TestComplianceWildcardProtectsRoutedTrafficAndPortBoundaries(t *testing.T) {
	d, draft, nodes, flow, _, now := complianceFixture()
	draft.Remediation = nil
	draft.Guardrails[0].Resource.Selector = "*"
	flow.DestinationHandle = ""
	flow.Address = netip.MustParseAddr("10.99.0.2")
	for _, port := range []uint16{21, 22, 443, 444} {
		flow.Port = port
		preview, err := d.PreviewCompliance(draft, nodes, flow, nil, now)
		require.NoError(t, err)
		require.Equal(t, port == 21 || port == 444, preview.Allowed)
	}
	// The preview's input identity decisions remain mandatory even for remediation.
	flow.IdentityAllowed = false
	flow.Port = 444
	preview, err := d.PreviewCompliance(draft, nodes, flow, nil, now)
	require.NoError(t, err)
	require.False(t, preview.Allowed)
}
