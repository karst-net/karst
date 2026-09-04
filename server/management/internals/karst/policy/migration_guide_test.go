// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package policy

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestMigrationGuidePolicyIsValid(t *testing.T) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test source")
	}
	path := filepath.Clean(filepath.Join(filepath.Dir(source), "../../../../../docs/MIGRATING-FROM-WIREGUARD-TAILSCALE.md"))
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	const open = "```json migration-policy\n"
	start := strings.Index(string(contents), open)
	if start < 0 {
		t.Fatal("migration-policy fence not found")
	}
	policyText := string(contents)[start+len(open):]
	end := strings.Index(policyText, "\n```")
	if end < 0 {
		t.Fatal("migration-policy closing fence not found")
	}
	if _, err := Parse([]byte(policyText[:end])); err != nil {
		t.Fatalf("migration guide policy is invalid: %v", err)
	}
}
