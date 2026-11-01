// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package buildinfo

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type unreadableArtifact struct{}

func (unreadableArtifact) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestArtifactHashRejectsPartialRead(t *testing.T) {
	got, err := hashArtifact(strings.NewReader("abc"))
	if err != nil || got != "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatalf("artifact hash: %q, %v", got, err)
	}
	got, err = hashArtifact(io.MultiReader(strings.NewReader("partial"), unreadableArtifact{}))
	if err == nil || got != "" {
		t.Fatalf("partial artifact must be unknown: %q, %v", got, err)
	}
}

func TestRunningArtifactSurvivesInstalledBinaryReplacement(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("running inode observation requires Linux procfs")
	}
	if os.Getenv("KARST_BUILDINFO_TEST_CHILD") == "1" {
		path, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		bytes, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		want := fmt.Sprintf("sha256:%x", sha256.Sum256(bytes))
		if err := os.WriteFile(path+".next", []byte("new installed executable"), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(path+".next", path); err != nil {
			t.Fatal(err)
		}
		if got := Current().ArtifactID; got != want {
			t.Fatalf("reported installed replacement instead of running executable: got %q, want %q", got, want)
		}
		return
	}
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	bytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	copy := filepath.Join(t.TempDir(), "control-test")
	if err := os.WriteFile(copy, bytes, 0700); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(copy, "-test.run=^TestRunningArtifactSurvivesInstalledBinaryReplacement$")
	command.Env = append(os.Environ(), "KARST_BUILDINFO_TEST_CHILD=1")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("running executable observation failed: %v\n%s", err, output)
	}
}
