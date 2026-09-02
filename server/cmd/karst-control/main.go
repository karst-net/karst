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
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/cmd"
	"github.com/netbirdio/netbird/management/internals/karst/bedrock"
	"github.com/netbirdio/netbird/management/internals/karst/bootstrap"
	"github.com/netbirdio/netbird/management/internals/karst/policy"
	"github.com/netbirdio/netbird/management/internals/karst/relayreg"
	"github.com/netbirdio/netbird/management/internals/karst/roster"
	nbserver "github.com/netbirdio/netbird/management/internals/server"
	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/shared/auth"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// karstPolicyEnv names a file holding the ACL document (PLAN.md §4.3).
//
// Absent means no policy, which compiles to an empty packet filter and so to
// **default deny**. A server that has not been given a policy therefore denies
// traffic rather than permitting all of it: the symptom is a network that does
// not work, rather than one that works too well.
const karstPolicyEnv = "KARST_POLICY_FILE"

// The co-located relay's roster — PLAN.md §5, GitHub issue [#47](https://github.com/karst-net/karst/issues/47).
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

// The anchor scheduler's configuration — ADR-0016, GitHub issue [#61](https://github.com/karst-net/karst/issues/61).
//
// Unset means what it has always meant for this deployment: nobody anchors
// the audit log but the offline authority ceremony, which is a human running
// `karst-bedrock sign` when they remember to. Set, the key file must hold the
// raw 32-byte seed `karst-bedrock init anchor` writes — this reads exactly
// that file, so the same key generated for the offline ceremony can be
// pointed at the server instead, or a fresh one made for it.
//
// A key here can only ever sign `anchor` (ADR-0016's whole point), so this is
// deliberately a lighter bar than the roster or bootstrap-key envs above: a
// bad or unenabled key logs and waits rather than failing startup, because
// the ordinary rollout order is "start the server with this set, then run
// the root ceremony that adds the key to the chain" — treating the interim
// as fatal would make that order impossible.
const (
	karstBedrockAnchorKeyEnv        = "KARST_BEDROCK_ANCHOR_KEY_FILE"
	karstBedrockAnchorMaxAgeEnv     = "KARST_BEDROCK_ANCHOR_MAX_AGE"
	karstBedrockAnchorMinEntriesEnv = "KARST_BEDROCK_ANCHOR_MIN_ENTRIES"
)

// karstBedrockAnchorPollInterval is how often the scheduler checks AnchorDue,
// not how often it anchors — see bedrock.AnchorDue's own doc for why those
// are different knobs. Not configurable: it is cheap (a handful of local
// reads against a log that is small by construction) and operationally
// meaningless on its own, unlike karstBedrockAnchorMaxAgeEnv.
const karstBedrockAnchorPollInterval = 5 * time.Minute

// karstBedrockAnchorDefaultMaxAge and karstBedrockAnchorDefaultMinEntries are
// AnchorDue's two thresholds when an operator sets a key but not a pace.
// A day and a thousand entries are arbitrary in the sense any default is;
// they are chosen to be quiet on a small self-hosted deployment while still
// bounding the undetectable-truncation window to a day at most.
const (
	karstBedrockAnchorDefaultMaxAge     = 24 * time.Hour
	karstBedrockAnchorDefaultMinEntries = 1000
)

// karstBootstrapKeyEnv names a file to mint the first enrollment key into.
//
// Set, and if the file does not already exist, the server creates one setup
// key at startup and writes it there — the only way to enroll a node on a
// deployment with no identity provider, which is every deployment on its first
// day (GETTING-STARTED.md §8). Unset, nothing happens and the only path to a
// key is the authenticated API, which is right for a deployment that has one.
//
// Existence is the whole idempotence rule: the plaintext is recoverable from
// nowhere else, so a server that minted a second key on every restart would
// leave a trail of live credentials nobody could revoke by name.
const karstBootstrapKeyEnv = "KARST_BOOTSTRAP_SETUP_KEY_FILE"

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
		writeBootstrapKey(ctx, s.AccountManager())
		startBedrockAnchorScheduler(ctx, k, s.AccountManager())
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

// writeBootstrapKey mints the first enrollment key when there is no IdP.
//
// Fatal on every failure, and deliberately so: an operator who set the path is
// waiting to read a key out of that file, and a server that started without
// writing one would leave them running `karstd` against a key that is not
// there, diagnosing an enrollment error whose cause is three layers away.
//
// The order below is not incidental. The file is created **empty and
// exclusively before the key is minted**, so the two failures that would
// otherwise strand a live credential — the path is unwritable, or another
// process is doing this at the same moment — happen while there is still
// nothing to strand.
func writeBootstrapKey(ctx context.Context, accounts account.Manager) {
	path := os.Getenv(karstBootstrapKeyEnv)
	if path == "" {
		return
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	switch {
	case errors.Is(err, fs.ErrExist):
		log.Infof("karst: an enrollment key is already in %s; keeping it", path)
		return
	case err != nil:
		log.Fatalf("karst: %s=%s: %v", karstBootstrapKeyEnv, path, err)
	}

	key, err := bootstrap.MintBootstrapKey(ctx, accounts, bootstrap.BootstrapKeyOptions{})
	if err != nil {
		_ = f.Close()
		// The placeholder must go, or the next start reads "already there" off
		// an empty file and never tries again.
		_ = os.Remove(path)
		log.Fatalf("karst: %v", err)
	}

	_, writeErr := fmt.Fprintln(f, key)
	closeErr := f.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		// The key is real, is in the database, and is now in no file. Say that,
		// rather than a bare I/O error: it is the difference between an
		// operator who revokes it and one who does not know it exists.
		log.Fatalf("karst: an enrollment key was created but could not be saved to %s (%v). "+
			"It is live and its plaintext is lost; revoke %q from the console once one works.",
			path, err, bootstrap.BootstrapKeyName)
	}
	log.Warnf("karst: wrote a bootstrap enrollment key to %s. Put it in a node's "+
		"[control] setup_key, and revoke it once an identity provider is configured.", path)
}

// startBedrockAnchorScheduler runs ADR-0016's anchor tier automatically: the
// job that gives bedrock.AnchorDue its first production caller.
//
// **Fatal on a bad key, quiet forever after that.** An operator who set the
// path meant this key to sign; a seed that will not load is a configuration
// mistake worth stopping on, the same call startRosterRefresher makes. Once
// loaded, though, the key not yet being in the chain's anchor list is not a
// mistake — it is the ordinary gap between starting the server and running
// the root ceremony that enables it — so the scheduler itself only logs
// that, once, and keeps ticking.
func startBedrockAnchorScheduler(ctx context.Context, k *bootstrap.Karst, accounts account.Manager) {
	path := os.Getenv(karstBedrockAnchorKeyEnv)
	if path == "" {
		return
	}
	seed, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("karst: %s=%s: %v", karstBedrockAnchorKeyEnv, path, err)
	}
	key, err := bedrock.AnchorFromSeed(seed)
	if err != nil {
		log.Fatalf("karst: %s=%s: %v", karstBedrockAnchorKeyEnv, path, err)
	}

	maxAge := karstBedrockAnchorDefaultMaxAge
	if raw := os.Getenv(karstBedrockAnchorMaxAgeEnv); raw != "" {
		parsed, err := time.ParseDuration(raw)
		if err != nil {
			log.Fatalf("karst: %s=%q is not a duration: %v", karstBedrockAnchorMaxAgeEnv, raw, err)
		}
		maxAge = parsed
	}
	minEntries := uint64(karstBedrockAnchorDefaultMinEntries)
	if raw := os.Getenv(karstBedrockAnchorMinEntriesEnv); raw != "" {
		parsed, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			log.Fatalf("karst: %s=%q is not a non-negative integer: %v", karstBedrockAnchorMinEntriesEnv, raw, err)
		}
		minEntries = parsed
	}

	// Single-account mode's resolution, the same one MintBootstrapKey uses:
	// an empty domain with any user ID routes to the one account a
	// self-hosted deployment has. See enroll.go's comment on why that is
	// also correct for a multi-account deployment, which routes an unknown
	// user to a fresh account of their own rather than this one.
	accountID, _, err := accounts.GetAccountIDFromUserAuth(ctx, auth.UserAuth{UserId: bootstrap.BootstrapUserID})
	if err != nil {
		log.Fatalf("karst: %s: resolve account: %v", karstBedrockAnchorKeyEnv, err)
	}

	s := &bedrock.Scheduler{
		Log: k.Chain, Audit: k.Audit, AccountID: accountID, Key: key,
		MinEntries: minEntries, MaxAge: maxAge,
	}
	log.Infof("karst: bedrock anchor scheduler enabled for %s: checking every %s, "+
		"anchoring after %d entries or %s, whichever comes first",
		accountID, karstBedrockAnchorPollInterval, minEntries, maxAge)
	go s.Run(ctx, karstBedrockAnchorPollInterval)
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
