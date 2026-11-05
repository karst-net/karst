// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package main

import "testing"

func TestParseRelayAllocateMaxConcurrent(t *testing.T) {
	t.Run("unset", func(t *testing.T) {
		value, warn, err := parseRelayAllocateMaxConcurrent("")
		if err != nil || warn || value != 0 {
			t.Fatalf("unset: got (%d, %t, %v), want (0, false, nil)", value, warn, err)
		}
	})

	t.Run("documented default of 0 is a graceful refuse-all, not a startup error", func(t *testing.T) {
		value, warn, err := parseRelayAllocateMaxConcurrent("0")
		if err != nil || !warn || value != 0 {
			t.Fatalf(`"0": got (%d, %t, %v), want (0, true, nil)`, value, warn, err)
		}
	})

	t.Run("negative is also a graceful refuse-all", func(t *testing.T) {
		value, warn, err := parseRelayAllocateMaxConcurrent("-1")
		if err != nil || !warn || value != 0 {
			t.Fatalf(`"-1": got (%d, %t, %v), want (0, true, nil)`, value, warn, err)
		}
	})

	t.Run("positive integer is used as-is", func(t *testing.T) {
		value, warn, err := parseRelayAllocateMaxConcurrent("10")
		if err != nil || warn || value != 10 {
			t.Fatalf(`"10": got (%d, %t, %v), want (10, false, nil)`, value, warn, err)
		}
	})

	t.Run("non-integer is a genuine misconfiguration", func(t *testing.T) {
		_, _, err := parseRelayAllocateMaxConcurrent("not-a-number")
		if err == nil {
			t.Fatal(`"not-a-number": got nil error, want a rejection`)
		}
	})
}
