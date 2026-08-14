// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// Command karst-control is the Karst coordination server.
//
// It is the forked NetBird management daemon with KarstControlService attached
// (ADR-0011). Everything the fork does is unchanged; Karst adds a second gRPC
// service on the same port.
//
// # Why a separate main
//
// The fork's own `management/main.go` is left untouched. Attaching here uses
// two seams the fork already exposes — `cmd.SetNewServer`, which replaces the
// server constructor, and `BaseServer.RegisterGRPCExtension`, documented as "a
// generic extension point with no knowledge of any specific service" — so
// **not one forked file is modified**.
//
// That is not tidiness. Spike 0001 §5.3 measured 28% of upstream commits
// landing on the files we would otherwise diverge on; every line changed there
// is a future conflict when cherry-picking a security fix.
package main

import (
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/cmd"
	"github.com/netbirdio/netbird/management/internals/karst/bootstrap"
	"github.com/netbirdio/netbird/management/internals/karst/policy"
	nbserver "github.com/netbirdio/netbird/management/internals/server"
)

// karstPolicyEnv names a file holding the ACL document (PLAN.md §4.3).
//
// Absent means no policy, which compiles to an empty packet filter and so to
// **default deny**. A server that has not been given a policy therefore denies
// traffic rather than permitting all of it: the symptom is a network that does
// not work, rather than one that works too well.
const karstPolicyEnv = "KARST_POLICY_FILE"

func main() {
	pol, err := loadPolicy()
	if err != nil {
		fmt.Fprintf(os.Stderr, "karst: %v\n", err)
		os.Exit(1)
	}

	cmd.SetNewServer(func(cfg *nbserver.Config) nbserver.Server {
		s := nbserver.NewServer(cfg)
		if _, err := bootstrap.Install(s, pol); err != nil {
			// Failing to start is deliberate. A management server that comes up
			// without KarstControlService looks healthy and silently accepts no
			// Karst node, which is harder to diagnose than not starting.
			log.Fatalf("karst: cannot install the control service: %v", err)
		}
		return s
	})

	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func loadPolicy() (*policy.Document, error) {
	path := os.Getenv(karstPolicyEnv)
	if path == "" {
		log.Warnf("karst: no %s set; the packet filter will be empty, which is default deny",
			karstPolicyEnv)
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy %s: %w", path, err)
	}
	// Parsed at startup rather than on first use: a malformed policy should
	// stop the server now, not compile to an empty filter that locks the
	// network out at the moment someone first connects.
	doc, err := policy.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("policy %s: %w", path, err)
	}
	log.Infof("karst: loaded policy from %s (%d rules)", path, len(doc.ACLs))
	return doc, nil
}
