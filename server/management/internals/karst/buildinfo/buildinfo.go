// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// Package buildinfo identifies the running Karst control binary.
package buildinfo

import "runtime/debug"

// Version and Revision are set by release builds with -ldflags -X.
var Version = "development"
var Revision = "unknown"

type Info struct {
	Version  string `json:"version"`
	Revision string `json:"revision"`
}

func Current() Info {
	info := Info{Version: Version, Revision: Revision}
	if build, ok := debug.ReadBuildInfo(); ok && info.Revision == "unknown" {
		for _, setting := range build.Settings {
			if setting.Key == "vcs.revision" {
				info.Revision = setting.Value
			}
			if setting.Key == "vcs.modified" && setting.Value == "true" {
				info.Version += " (modified)"
			}
		}
	}
	return info
}
