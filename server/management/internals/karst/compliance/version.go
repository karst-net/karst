// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package compliance

import (
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/mod/semver"
)

// Require a full SemVer release (optional v prefix), matching KARST_VERSION
// release tags and CI's 0.0.0+git.SHA. Local "dev" builds are incomparable.
func clientVersion(s string) (string, error) {
	if len(s) > 128 || s == "" {
		return "", fmt.Errorf("invalid client version")
	}
	v := s
	if !strings.HasPrefix(v, "v") {
		v = "v" + v
	}
	core := strings.SplitN(strings.SplitN(v[1:], "+", 2)[0], "-", 2)[0]
	if strings.Count(core, ".") != 2 || !semver.IsValid(v) {
		return "", fmt.Errorf("invalid client version")
	}
	return v, nil
}

// OS values are product releases, never Linux kernel versions. Restrict each
// supported product to an explicitly documented numeric format; arbitrary
// distribution release schemes must gain their own comparator before use.
func osVersion(p Platform, distribution, s string) ([]uint32, error) {
	if !supportedOS(p, distribution) || s == "" || len(s) > 64 {
		return nil, fmt.Errorf("invalid OS version")
	}
	parts := strings.Split(s, ".")
	min, max := 2, 3 // macOS product major.minor[.patch]
	if p == Windows {
		min, max = 3, 4
	} // major.minor.build[.revision]
	if p == Linux {
		if distribution == "ubuntu" {
			min, max = 2, 2
		} else {
			min, max = 1, 2
		}
	}
	if len(parts) < min || len(parts) > max {
		return nil, fmt.Errorf("invalid OS version")
	}
	result := make([]uint32, 4)
	for i, part := range parts {
		if part == "" {
			return nil, fmt.Errorf("invalid OS version")
		}
		for _, c := range part {
			if c < '0' || c > '9' {
				return nil, fmt.Errorf("invalid OS version")
			}
		}
		n, err := strconv.ParseUint(part, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid OS version")
		}
		result[i] = uint32(n)
	}
	return result, nil
}

func compare(r Requirement, observed string) (int, error) {
	if r.Kind == MinimumClientVersion {
		actual, err := clientVersion(observed)
		if err != nil {
			return 0, err
		}
		minimum, err := clientVersion(r.MinimumVersion)
		if err != nil {
			return 0, err
		}
		return semver.Compare(actual, minimum), nil
	}
	actual, err := osVersion(r.Platform, r.Distribution, observed)
	if err != nil {
		return 0, err
	}
	minimum, err := osVersion(r.Platform, r.Distribution, r.MinimumVersion)
	if err != nil {
		return 0, err
	}
	for i := range actual {
		if actual[i] < minimum[i] {
			return -1, nil
		}
		if actual[i] > minimum[i] {
			return 1, nil
		}
	}
	return 0, nil
}
