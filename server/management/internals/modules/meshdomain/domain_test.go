// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package meshdomain

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRootDNSSuffixIsSeparateFromRelativePath(t *testing.T) {
	for _, suffix := range []string{"karst", "Acme.Example.", "büro.example"} {
		root, err := NewRoot("account", suffix)
		require.NoError(t, err)
		require.True(t, root.IsRoot())
		require.Empty(t, root.Label)
		require.Empty(t, root.Path)
		require.Equal(t, "laptop", root.QualifyLabel("laptop"))
		child := NewDomain("account", root.ID, "engineering", root.Path)
		require.Equal(t, "build.engineering", child.QualifyLabel("build"))
	}
	for _, suffix := range []string{"", "bad..example", "*.example", "bad_suffix", "-bad.example", "bad-.example", strings.Repeat("a", 64) + ".example"} {
		_, err := NewRoot("account", suffix)
		require.Error(t, err, "suffix %q", suffix)
	}
}
