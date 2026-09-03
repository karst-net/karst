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
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/cmd"
	"github.com/netbirdio/netbird/management/internals/karst/bedrock"
	"github.com/netbirdio/netbird/management/internals/karst/bootstrap"
	"github.com/netbirdio/netbird/management/internals/karst/policy"
	"github.com/netbirdio/netbird/management/internals/karst/relayreg"
	"github.com/netbirdio/netbird/management/internals/karst/roster"
	"github.com/netbirdio/netbird/management/internals/karst/turncred"
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

// TURN fallback configuration — ADR-0008 §4.
//
// All three unset is the common case and means exactly what it always has:
// no TURN, nodes fall back to the co-located relay alone. Configuring TURN
// needs both the registry (which servers) and the shared secret (how to mint
// credentials for them) — one without the other is as silent a
// misconfiguration as the roster/registry split above, so both are read
// together in loadTurn.
const (
	karstTurnRegistryEnv      = "KARST_TURN_REGISTRY_FILE"
	karstTurnSharedSecretEnv  = "KARST_TURN_SHARED_SECRET_FILE"
	karstTurnCredentialTTLEnv = "KARST_TURN_CREDENTIAL_TTL"
)

// karstTurnDefaultCredentialTTL is the credential lifetime when an operator
// sets a shared secret but not a TTL. Long enough that a node polling the
// netmap at its ordinary cadence always has a live credential in hand, short
// enough that a leaked one is not useful for long — the same "quiet, bounded
// default" reasoning karstBedrockAnchorDefaultMaxAge uses.
const karstTurnDefaultCredentialTTL = 12 * time.Hour

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
	turnServers, turnMinter, err := loadTurn()
	if err != nil {
		fmt.Fprintf(os.Stderr, "karst: %v\n", err)
		os.Exit(1)
	}

	// Canceled when main returns, which is the only shutdown signal this
	// process has: cmd.Execute blocks until the daemon stops.
	ctx, stop := context.WithCancel(context.Background())
	defer stop()

	cmd.SetNewServer(func(cfg *nbserver.Config) nbserver.Server {
		rejectLegacyTurnConfig(cfg)
		s := nbserver.NewServer(cfg)
		k, err := bootstrap.Install(s, pol, relays, turnServers, turnMinter)
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

// loadTurn reads ADR-0008 §4's TURN fallback configuration: the server
// registry and the shared secret credentials are minted from.
//
// Either set without the other is fatal rather than silently partial — a
// registry with no secret can mint nothing, and a secret with no registry
// has nothing to attach a credential to, and both look like "TURN is
// configured" to an operator reading their own environment.
func loadTurn() ([]turncred.Entry, *turncred.Minter, error) {
	registryPath := os.Getenv(karstTurnRegistryEnv)
	secretPath := os.Getenv(karstTurnSharedSecretEnv)
	if registryPath == "" && secretPath == "" {
		return nil, nil, nil
	}
	if registryPath == "" || secretPath == "" {
		return nil, nil, fmt.Errorf("karst: %s and %s must be set together",
			karstTurnRegistryEnv, karstTurnSharedSecretEnv)
	}

	servers, err := turncred.Load(registryPath)
	if err != nil {
		return nil, nil, err
	}

	secretRaw, err := os.ReadFile(secretPath)
	if err != nil {
		return nil, nil, fmt.Errorf("karst: %s=%s: %w", karstTurnSharedSecretEnv, secretPath, err)
	}
	secret := strings.TrimSpace(string(secretRaw))

	ttl := karstTurnDefaultCredentialTTL
	if raw := os.Getenv(karstTurnCredentialTTLEnv); raw != "" {
		ttl, err = time.ParseDuration(raw)
		if err != nil {
			return nil, nil, fmt.Errorf("karst: %s=%q is not a duration: %w", karstTurnCredentialTTLEnv, raw, err)
		}
	}

	minter, err := turncred.NewMinter(secret, ttl)
	if err != nil {
		return nil, nil, fmt.Errorf("karst: %s: %w", karstTurnSharedSecretEnv, err)
	}
	log.Infof("karst: loaded %d turn servers from %s, credential ttl %s", len(servers), registryPath, ttl)
	return servers, minter, nil
}

// rejectLegacyTurnConfig refuses to start against the fork's own
// `turn:`/`credentials` block in management.json — GitHub issue #92's "two
// parallel TURN-credential channels" question, resolved as: disabled, fatal
// rather than silent.
//
// The fork's TimeBasedAuthSecretsManager (server.go, wired in controllers.go)
// delivers TURN credentials over SyncResponse.NetbirdConfig.Turns, a channel
// with no relationship to karst_control.proto's turn_servers field and no
// awareness of KARST_TURN_REGISTRY_FILE/KARST_TURN_SHARED_SECRET_FILE above.
// Karst does not modify the forked files that implement it — the same reason
// bootstrap.go gives for attaching through seams instead — so the config
// surface stays reachable if an operator points --config at a management.json
// carrying a turn block, most plausibly by reusing one written for a plain
// NetBird deployment. Left alone, that produces exactly the failure mode this
// package's other loaders are fatal about: two credential-delivery paths an
// operator believes are one, silently disagreeing about which servers and
// secrets are live.
//
// A present-but-empty block is not that failure and must stay allowed:
// deploy/compose/bootstrap.sh writes exactly one, `TimeBasedCredentials:
// false` with no `Turns`, to every deployment today, as an inert placeholder
// the fork's config loader is happy to see absent or present. server.go's
// sendInitialSync only ever calls GenerateTurnToken behind
// `TURNConfig.TimeBasedCredentials`, and conversion.go's `turns` projection
// only ever has entries to iterate when `TURNConfig.Turns` is non-empty — so
// neither flag set is the bar for "actually a second channel", not mere
// presence of the struct.
//
// Fatal rather than a warning because a warning is exactly what would get
// missed in the startup log of the one deployment where it matters. Use
// KARST_TURN_REGISTRY_FILE and KARST_TURN_SHARED_SECRET_FILE instead, and
// drop the turn block from management.json.
func rejectLegacyTurnConfig(cfg *nbserver.Config) {
	if err := checkLegacyTurnConfig(cfg); err != nil {
		log.Fatalf("karst: %v", err)
	}
}

// checkLegacyTurnConfig is rejectLegacyTurnConfig's testable half.
func checkLegacyTurnConfig(cfg *nbserver.Config) error {
	if cfg == nil || cfg.NbConfig == nil || cfg.NbConfig.TURNConfig == nil {
		return nil
	}
	turn := cfg.NbConfig.TURNConfig
	if !turn.TimeBasedCredentials && len(turn.Turns) == 0 {
		return nil
	}
	return fmt.Errorf("management.json's turn config block is active (TimeBasedCredentials=%t, "+
		"%d server(s)), which karst-control does not support — it is a second, uncoordinated "+
		"TURN-credential path alongside karst_control.proto's turn_servers field. Configure TURN "+
		"with %s and %s instead, and remove the turn block from the config file.",
		turn.TimeBasedCredentials, len(turn.Turns), karstTurnRegistryEnv, karstTurnSharedSecretEnv)
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
