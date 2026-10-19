// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package compliance_test

import (
	"strings"
	"testing"

	"github.com/netbirdio/netbird/management/internals/karst/compliance"
)

func TestVersionOrdering(t *testing.T) {
	tests := []struct {
		name                    string
		platform                compliance.Platform
		distro, minimum, actual string
		state                   compliance.State
	}{
		{"client numeric", "", "", "0.9.0", "0.10.0", compliance.Compliant},
		{"client prefix", "", "", "v1.2.3", "1.2.3", compliance.Compliant},
		{"prerelease below release", "", "", "1.2.3", "1.2.3-rc.9", compliance.Noncompliant},
		{"prerelease numeric", "", "", "1.2.3-rc.9", "1.2.3-rc.10", compliance.Compliant},
		{"release after prerelease", "", "", "1.2.3-rc.9", "1.2.3", compliance.Compliant},
		{"build ignored", "", "", "1.2.3+git.a", "1.2.3+git.b", compliance.Compliant},
		{"CI below release", "", "", "0.1.0", "0.0.0+git.abc", compliance.Noncompliant},
		{"local dev", "", "", "0.1.0", "dev", compliance.EvaluationError},
		{"shorthand disallowed", "", "", "1.2.0", "1.2", compliance.EvaluationError},
		{"client zero prefix", "", "", "1.2.3", "01.2.3", compliance.EvaluationError},
		{"invalid prerelease", "", "", "1.2.3", "1.2.3-rc.01", compliance.EvaluationError},
		{"client huge input", "", "", "1.2.3", strings.Repeat("1", 129), compliance.EvaluationError},
		{"mac numeric", compliance.MacOS, "", "15.9", "15.10", compliance.Compliant},
		{"mac patch missing", compliance.MacOS, "", "15.1.0", "15.1", compliance.Compliant},
		{"mac below patch", compliance.MacOS, "", "15.1.1", "15.1", compliance.Noncompliant},
		{"mac no major only", compliance.MacOS, "", "15.1", "16", compliance.EvaluationError},
		{"mac no kernel", compliance.MacOS, "", "15.1", "Darwin 24.1.0", compliance.EvaluationError},
		{"windows build numeric", compliance.Windows, "", "10.0.9999", "10.0.26100", compliance.Compliant},
		{"windows build below", compliance.Windows, "", "10.0.26100", "10.0.22631", compliance.Noncompliant},
		{"windows revision", compliance.Windows, "", "10.0.26100.100", "10.0.26100.101", compliance.Compliant},
		{"windows no marketing name", compliance.Windows, "", "10.0.26100", "Windows 11", compliance.EvaluationError},
		{"ubuntu numeric", compliance.Linux, "ubuntu", "22.04", "24.04", compliance.Compliant},
		{"ubuntu zero padded", compliance.Linux, "ubuntu", "24.04", "24.4", compliance.Compliant},
		{"ubuntu below", compliance.Linux, "ubuntu", "24.10", "24.04", compliance.Noncompliant},
		{"ubuntu kernel rejected", compliance.Linux, "ubuntu", "24.04", "6.8.0", compliance.EvaluationError},
		{"debian major", compliance.Linux, "debian", "12.0", "12", compliance.Compliant},
		{"debian point release", compliance.Linux, "debian", "12.9", "12.10", compliance.Compliant},
		{"OS uint overflow", compliance.Windows, "", "10.0.26100", "10.0.4294967296", compliance.EvaluationError},
		{"OS signed", compliance.MacOS, "", "15.1", "+15.1", compliance.EvaluationError},
		{"OS empty component", compliance.MacOS, "", "15.1", "15..1", compliance.EvaluationError},
		{"OS trailing junk", compliance.MacOS, "", "15.1", "15.1beta", compliance.EvaluationError},
		{"OS whitespace", compliance.MacOS, "", "15.1", "15.1 ", compliance.EvaluationError},
		{"OS huge input", compliance.MacOS, "", "15.1", strings.Repeat("1", 65), compliance.EvaluationError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := clientRequirement()
			r.MinimumVersion = tt.minimum
			e := evidence()
			if tt.platform == "" {
				e.ClientVersion.Version = tt.actual
			} else {
				r.Kind = compliance.MinimumOSVersion
				r.Platform = tt.platform
				r.Distribution = tt.distro
				e.Platform = tt.platform
				e.Distribution = tt.distro
				e.OSVersion.Version = tt.actual
			}
			got, err := compliance.Evaluate([]compliance.Requirement{r}, subject, &e, now)
			if err != nil {
				t.Fatal(err)
			}
			if got.Results[0].State != tt.state {
				t.Fatalf("%q >= %q: %+v", tt.actual, tt.minimum, got)
			}
		})
	}
}
