// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package buildinfo

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"
)

// Cache the first observation for this process. A failure is unknown, never a
// reason to refuse an administrative request or identify an installed upgrade
// as the process that is still running.
var currentArtifact = sync.OnceValue(observeArtifact)

func observeArtifact() string {
	if runtime.GOOS != "linux" {
		return ""
	}
	// This names the executing inode even if a package upgrade has replaced
	// its pathname. os.Executable() alone could identify that replacement.
	file, err := os.Open("/proc/self/exe")
	if err != nil {
		return ""
	}
	defer file.Close()
	identity, err := hashArtifact(file)
	if err != nil {
		return ""
	}
	return identity
}

func hashArtifact(reader io.Reader) (string, error) {
	digest := sha256.New()
	if _, err := io.Copy(digest, reader); err != nil {
		return "", err
	}
	return fmt.Sprintf("sha256:%x", digest.Sum(nil)), nil
}
