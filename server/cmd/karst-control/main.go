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
	"context"
	"fmt"
	"os"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/cmd"
	"github.com/netbirdio/netbird/management/internals/karst/bootstrap"
	"github.com/netbirdio/netbird/management/internals/karst/policy"
	"github.com/netbirdio/netbird/management/internals/karst/relayreg"
	"github.com/netbirdio/netbird/management/internals/karst/roster"
	nbserver "github.com/netbirdio/netbird/management/internals/server"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// karstPolicyEnv names a file holding the ACL document (PLAN.md §4.3).
//
// Absent means no policy, which compiles to an empty packet filter and so to
// **default deny**. A server that has not been given a policy therefore denies
// traffic rather than permitting all of it: the symptom is a network that does
// not work, rather than one that works too well.
const karstPolicyEnv = "KARST_POLICY_FILE"

// The co-located relay's roster — PLAN.md §5, FINDINGS.md 42.
//
// Unset means no roster is written, which is right for a server with no relay
// beside it. Set, the file is rewritten on an interval whether or not
// membership changed, because the relay's admission lease is refreshed by the
// file's modification time and expires after ninety seconds.
const (
	karstRosterFileEnv     = "KARST_RELAY_ROSTER_FILE"
	karstRosterAquiferEnv  = "KARST_AQUIFER"
	karstRosterIntervalEnv = "KARST_RELAY_ROSTER_INTERVAL"
)

// karstRelayRegistryEnv names the relay registry published to every node.
//
// The counterpart of the roster and easily confused with it: the roster tells a
// relay which nodes to admit, and the registry tells nodes which relays exist.
// A deployment needs both, and having only one is silent — the relay admits
// nobody who ever arrives, because nobody was told to arrive.
const karstRelayRegistryEnv = "KARST_RELAY_REGISTRY_FILE"

func main() {
	pol, err := loadPolicy()
	if err != nil {
		fmt.Fprintf(os.Stderr, "karst: %v\n", err)
		os.Exit(1)
	}
	relays, err := loadRelays()
	if err != nil {
		fmt.Fprintf(os.Stderr, "karst: %v\n", err)
		os.Exit(1)
	}

	// Canceled when main returns, which is the only shutdown signal this
	// process has: cmd.Execute blocks until the daemon stops.
	ctx, stop := context.WithCancel(context.Background())
	defer stop()

	cmd.SetNewServer(func(cfg *nbserver.Config) nbserver.Server {
		s := nbserver.NewServer(cfg)
		k, err := bootstrap.Install(s, pol, relays)
		if err != nil {
			// Failing to start is deliberate. A management server that comes up
			// without KarstControlService looks healthy and silently accepts no
			// Karst node, which is harder to diagnose than not starting.
			log.Fatalf("karst: cannot install the control service: %v", err)
		}
		startRosterRefresher(ctx, k)
		return s
	})

	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// startRosterRefresher keeps a co-located relay's admission file current.
//
// **Fatal on a bad configuration, and silent when there is none.** An operator
// who set the path meant to run a relay beside this server; starting anyway
// would produce a relay that admits nodes for ninety seconds and then stops,
// which is the failure this exists to prevent and is remarkably hard to
// diagnose from the relay's end. An operator who set nothing gets nothing.
func startRosterRefresher(ctx context.Context, k *bootstrap.Karst) {
	path := os.Getenv(karstRosterFileEnv)
	if path == "" {
		return
	}
	interval := roster.DefaultInterval
	if raw := os.Getenv(karstRosterIntervalEnv); raw != "" {
		parsed, err := time.ParseDuration(raw)
		if err != nil {
			log.Fatalf("karst: %s=%q is not a duration: %v", karstRosterIntervalEnv, raw, err)
		}
		interval = parsed
	}
	r, err := roster.New(k.Nodes, roster.Config{
		Path:     path,
		Aquifer:  os.Getenv(karstRosterAquiferEnv),
		Interval: interval,
	}, log.Warnf)
	if err != nil {
		log.Fatalf("karst: relay roster: %v", err)
	}
	log.Infof("karst: writing the relay roster to %s every %s", path, interval)
	go r.Run(ctx)
}

// loadRelays reads the relay registry a node is told about — §4.2.
//
// **Unset is not a safe default here, only a quiet one.** With no registry the
// server runs correctly and hands every node an empty relay list, so nodes that
// cannot reach each other directly cannot reach each other at all; nothing
// fails, relaying simply never happens. The warning is emitted by
// bootstrap.Install, which is the one place that sees the final list.
//
// A registry that is set and unreadable is fatal, for the reason a bad policy
// is: karstd fails the *entire* netmap over one malformed entry, so a typo here
// takes the whole deployment down with a symptom that points nowhere near it.
func loadRelays() ([]*proto.KarstRelay, error) {
	path := os.Getenv(karstRelayRegistryEnv)
	if path == "" {
		return nil, nil
	}
	relays, err := relayreg.Load(path)
	if err != nil {
		return nil, err
	}
	log.Infof("karst: loaded %d relays from %s", len(relays), path)
	return relays, nil
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
