// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// Package node maps Karst's post-quantum identities onto the forked server's
// peer model.
//
// The forked schema keys peers on a 44-character base64 WireGuard public key,
// with a uniqueness index on the column (`idx_peers_key_unique`). An ML-DSA-87
// public key is 2592 bytes — 3456 characters in base64 — which is not a
// sensible index and would force a change to forked migrations.
//
// So a node's *handle* is a hash of its identity key, base64-encoded to
// exactly the same 44 characters a WireGuard key occupies. It drops into the
// existing column and index unchanged. The full identity key lives in a
// separate Karst-owned table, because signature verification on reconnect
// needs the real key and the peer row has nowhere to put it.
//
// This is the same shape as ADR-0005's peer_id_hint: a hash of a public key,
// used as a lookup handle rather than as key material.
package node

import (
	"crypto/mlkem"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/netbirdio/netbird/management/internals/karst/channel"
	"github.com/netbirdio/netbird/management/internals/karst/identity"
)

// handleContext domain-separates the handle hash from every other hash of the
// same public key — notably the data plane's peer_id_hint (ADR-0005), which
// hashes the *KEM* key with its own label. Two hashes of related material
// that happen to collide in construction is the kind of coincidence that turns
// into a correlation channel.
const handleContext = "karst-node-handle-v1"

// HandleLength is the padded URL-safe base64 length of a SHA-256 digest: 44
// characters, the same as a WireGuard public key.
const HandleLength = 44

var (
	ErrUnknownNode  = errors.New("node: unknown handle")
	ErrKeyMismatch  = errors.New("node: handle is registered to a different identity key")
	ErrBadPublicKey = errors.New("node: malformed identity public key")
	ErrBadHomeRelay = errors.New("node: malformed home relay id")
)

// Handle derives the stable string identifier for an ML-DSA-87 identity.
func Handle(identityPub []byte) string {
	h := sha256.New()
	h.Write([]byte(handleContext))
	h.Write(identityPub)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// Identity is the Karst-owned row holding a node's full ML-DSA-87 public key.
//
// Karst tables carry a karst_ prefix and go through GORM, matching the fork
// rather than introducing a second persistence idiom (PLAN.md §4.1).
type Identity struct {
	Handle string `gorm:"primaryKey;size:64"`
	// ML-DSA-87 identity key. Authenticates the control channel; deliberately
	// not used by PHREATIC (phreatic-v1.md §4).
	PublicKey []byte `gorm:"not null"`
	// PHREATIC authenticates against static KEM S (ML-KEM-1024, 1568 B).
	// The netmap distributes this key to peers.
	KemPublicKey []byte

	// HomeRelay is the Ponor relay this node reports holding a connection to
	// (ponor-v1.md §9.1), or empty for a node holding none.
	//
	// Reported by the node rather than decided here: the choice is made from
	// round-trip times only the node can measure. The server's job is to
	// remember it and hand it to the node's peers, which is what makes a peer
	// behind a symmetric NAT reachable at all — a peer that dials the wrong
	// relay reaches nothing, so this being stale is not a slow path but a
	// missing one.
	HomeRelay            []byte
	RelayLifecycleSchema uint32 `gorm:"not null;default:0"`

	// Candidates is this node's own self-reported AVEN candidate list
	// (`karst_control.proto`'s `KarstNetmapRequest.candidates`), order
	// preserved, redistributed to this node's peers as
	// `KarstNetmapPeer.candidates` — see `NetmapHandler.Handle`'s own
	// comment on why a relay-only path left same-LAN peers unable to find
	// each other whenever the relay itself was unreachable.
	//
	// JSON-encoded into a plain string column rather than through GORM's
	// `serializer:json` tag (unlike `relayalloc`/`relayservice`'s `[]string`
	// fields): `SetCandidates`' own change-detection `WHERE` clause needs to
	// compare it as ordinary text, the same way `SetHomeRelay`'s already
	// does for `home_relay` — binding a raw `[]string` into that clause
	// would have GORM try to expand it as a SQL `IN` list instead. Empty
	// (the default, and the zero value a migration leaves on existing rows)
	// decodes to no candidates, not a parse error — see `CandidateList`.
	Candidates string `gorm:"not null;default:''"`

	// Latest software report, independent of enrollment and compliance evidence.
	// A nil receipt time means no report has ever been observed.
	SoftwareVersion    string
	SoftwareRevision   string
	SoftwareArtifactID string
	SoftwareObservedAt *time.Time
	ControlCheck       ControlCheck `gorm:"embedded;embeddedPrefix:control_check_"`
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

// CandidateList decodes Candidates, treating anything that fails to parse
// (including the empty default on a pre-existing row) as no candidates
// rather than an error a caller would have to handle — the same tolerance
// `KarstNetmapPeer.candidates`'s own doc comment already asks a node to have
// toward what a peer reports: a stale or malformed entry costs that one
// candidate, never the rest of the netmap.
func (id Identity) CandidateList() []string {
	if id.Candidates == "" {
		return nil
	}
	var out []string
	if err := json.Unmarshal([]byte(id.Candidates), &out); err != nil {
		return nil
	}
	return out
}

// EnrollmentOwner binds a portal or invitation credential to its device owner.
// Only the SHA-256 digest is stored. Reusable invitations retain the binding
// after successful registration so later devices receive the same owner.
type EnrollmentOwner struct {
	Reusable  bool   `gorm:"not null;default:false"`
	KeyHash   string `gorm:"primaryKey;size:64"`
	UserID    string `gorm:"not null;index"`
	CreatedAt time.Time
}

// SessionObservation is the last session fact a node reported for one peer.
// It intentionally has no key or PSK fields: the REST API needs posture, not
// the material from which a session could be reconstructed.
type SessionObservation struct {
	ReporterHandle string `gorm:"primaryKey;size:64"`
	PeerHandle     string `gorm:"primaryKey;size:64"`
	Path           string `gorm:"not null"`
	Endpoint       string
	LatticeOnly    bool
	PSKEpoch       uint32
	Suite          string
	// TxBytes/RxBytes are running totals for the lifetime of the reporter's
	// session slot with this peer, not a delta since the last report — the
	// same accounting `bins/karstd/src/engine.rs`'s PeerStatus already keeps.
	TxBytes    uint64
	RxBytes    uint64
	ObservedAt time.Time `gorm:"not null;index"`
}

// InvitationAssignee records which account member a device invitation was
// issued for, keyed by the setup key's own ID rather than its secret hash
// (unlike EnrollmentOwner, which must be looked up by secret at redemption
// time): the console needs to display "this invitation is for Alice" on an
// invitation list or a user's detail long after the plaintext secret shown
// once at creation is gone. EnrollmentOwner remains the mechanism that
// actually assigns the resulting peer's owner at redemption; this table is
// for display only.
type InvitationAssignee struct {
	KeyID     string `gorm:"primaryKey;size:64"`
	UserID    string `gorm:"not null;index"`
	CreatedAt time.Time
}

func (SessionObservation) TableName() string { return "karst_session_observations" }

func (Identity) TableName() string { return "karst_node_identities" }

func (EnrollmentOwner) TableName() string { return "karst_enrollment_owners" }

func (InvitationAssignee) TableName() string { return "karst_invitation_assignees" }

// Store persists node identities.
type Store struct{ db *gorm.DB }

// NewStore migrates the Karst identity table and returns a store over it.
func NewStore(db *gorm.DB) (*Store, error) {
	if db == nil {
		return nil, errors.New("node: nil database")
	}
	if err := db.AutoMigrate(&Identity{}, &SessionObservation{}, &EnrollmentOwner{}, &InvitationAssignee{}, &DeviceSession{}); err != nil {
		return nil, fmt.Errorf("node: migrate: %w", err)
	}
	return &Store{db: db}, nil
}

func enrollmentKeyHash(key string) string {
	sum := sha256.Sum256([]byte(key))
	return fmt.Sprintf("%x", sum[:])
}

// BindEnrollmentKey records the owner of a credential. The optional reusable
// flag defaults to false for one-off portal keys. Rebinding replaces the
// previous owner; expiry and usage limits remain enforced by the account manager.
func (s *Store) BindEnrollmentKey(key, userID string, reusable ...bool) error {
	if key == "" || userID == "" {
		return errors.New("node: enrollment key and user are required")
	}
	owner := EnrollmentOwner{KeyHash: enrollmentKeyHash(key), UserID: userID, Reusable: len(reusable) > 0 && reusable[0]}
	if err := s.db.Save(&owner).Error; err != nil {
		return fmt.Errorf("node: bind enrollment key: %w", err)
	}
	return nil
}

// EnrollmentOwner returns the portal owner for an unused setup key. A missing
// binding is normal for administrator-issued keys and must not turn into an
// authorization error.
func (s *Store) EnrollmentOwner(key string) (string, error) {
	if key == "" {
		return "", nil
	}
	var owner EnrollmentOwner
	err := s.db.Where("key_hash = ?", enrollmentKeyHash(key)).Take(&owner).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("node: lookup enrollment owner: %w", err)
	}
	return owner.UserID, nil
}

// ConsumeEnrollmentKey removes a one-off binding after accepted registration
// and retains reusable bindings. Failed attempts keep their owner
// association for a retry until the setup key itself expires.
func (s *Store) ConsumeEnrollmentKey(key string) error {
	if key == "" {
		return nil
	}
	if err := s.db.Where("key_hash = ? AND reusable = ?", enrollmentKeyHash(key), false).Delete(&EnrollmentOwner{}).Error; err != nil {
		return fmt.Errorf("node: consume enrollment key: %w", err)
	}
	return nil
}

// SetInvitationAssignee records which user a device invitation (identified
// by its setup key ID) was issued for. Calling it twice replaces the prior
// assignee, same as BindEnrollmentKey.
func (s *Store) SetInvitationAssignee(keyID, userID string) error {
	if keyID == "" || userID == "" {
		return errors.New("node: invitation key id and user are required")
	}
	assignee := InvitationAssignee{KeyID: keyID, UserID: userID}
	if err := s.db.Save(&assignee).Error; err != nil {
		return fmt.Errorf("node: set invitation assignee: %w", err)
	}
	return nil
}

// InvitationAssignees batch-resolves assignees for a page of invitations, so
// listing invitations costs one query rather than one per row.
func (s *Store) InvitationAssignees(keyIDs []string) (map[string]string, error) {
	result := make(map[string]string, len(keyIDs))
	if len(keyIDs) == 0 {
		return result, nil
	}
	var rows []InvitationAssignee
	if err := s.db.Where("key_id IN ?", keyIDs).Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("node: list invitation assignees: %w", err)
	}
	for _, row := range rows {
		result[row.KeyID] = row.UserID
	}
	return result, nil
}

// DeleteInvitationAssignee removes the display record for a revoked or
// expired invitation. Best-effort from the caller's perspective: a missing
// row is not an error, since not every setup key is a device invitation.
func (s *Store) DeleteInvitationAssignee(keyID string) error {
	if keyID == "" {
		return nil
	}
	if err := s.db.Where("key_id = ?", keyID).Delete(&InvitationAssignee{}).Error; err != nil {
		return fmt.Errorf("node: delete invitation assignee: %w", err)
	}
	return nil
}

// ReplaceSessionObservations atomically replaces a reporter's complete view.
// The server, not the node, timestamps the observation so an offline node
// cannot make stale information look fresh.
func (s *Store) ReplaceSessionObservations(reporter string, observations []SessionObservation) error {
	if len(observations) > maxSessionReports {
		return fmt.Errorf("node: too many session observations")
	}
	seen := make(map[string]struct{}, len(observations))
	now := time.Now().UTC()
	for i := range observations {
		o := &observations[i]
		if o.PeerHandle == "" || o.PeerHandle == reporter || len(o.PeerHandle) > HandleLength {
			return fmt.Errorf("node: invalid session peer handle")
		}
		if o.Path != "direct" && o.Path != "relay" && o.Path != "turn" && o.Path != "unreachable" {
			return fmt.Errorf("node: invalid session path %q", o.Path)
		}
		if len(o.Endpoint) > maxSessionText || len(o.Suite) > maxSessionText {
			return fmt.Errorf("node: session observation text too long")
		}
		if _, ok := seen[o.PeerHandle]; ok {
			return fmt.Errorf("node: duplicate session peer %q", o.PeerHandle)
		}
		seen[o.PeerHandle] = struct{}{}
		o.ReporterHandle = reporter
		o.ObservedAt = now
	}
	return s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("reporter_handle = ?", reporter).Delete(&SessionObservation{}).Error; err != nil {
			return fmt.Errorf("node: delete session observations: %w", err)
		}
		if len(observations) == 0 {
			return nil
		}
		if err := tx.Create(&observations).Error; err != nil {
			return fmt.Errorf("node: create session observations: %w", err)
		}
		return nil
	})
}

// SessionObservations returns a reporter's last complete observation batch.
func (s *Store) SessionObservations(reporter string) ([]SessionObservation, error) {
	var observations []SessionObservation
	if err := s.db.Where("reporter_handle = ?", reporter).Order("peer_handle").Find(&observations).Error; err != nil {
		return nil, fmt.Errorf("node: list session observations: %w", err)
	}
	return observations, nil
}

// AllSessionObservations returns all persisted reports for account-level
// aggregation. Callers must apply account authorization before exposing rows.
func (s *Store) AllSessionObservations() ([]SessionObservation, error) {
	var observations []SessionObservation
	if err := s.db.Order("observed_at DESC").Find(&observations).Error; err != nil {
		return nil, fmt.Errorf("node: list all session observations: %w", err)
	}
	return observations, nil
}

// DataPlaneKeys are a node's PHREATIC keys, supplied at registration.
type DataPlaneKeys struct {
	KemPublicKey []byte // ML-KEM-1024, 1568 B
}

const (
	kemPublicKeySize = 1568

	// A Ponor relay id is a SHA-256 digest over the relay's identity key.
	relayIDSize       = 32
	maxSessionReports = 4096
	maxSessionText    = 512
)

// ValidateRegistration checks the identity and data-plane keys without
// persisting anything, and returns the handle Register will use.
//
// Callers that must authorize an enrollment before making any durable change
// use this before calling their business layer. Register repeats the check so
// it remains safe when used directly.
func ValidateRegistration(pub []byte, keys DataPlaneKeys) (string, error) {
	if len(pub) != identity.PublicKeySize {
		return "", fmt.Errorf("%w: %d bytes, want %d", ErrBadPublicKey, len(pub), identity.PublicKeySize)
	}
	// Parsed, not merely measured. A length check alone accepts 1568 bytes of
	// anything, and that key is then shipped to *every* peer in the account —
	// none of which can handshake with it, and each of which has to decide what
	// to do with an entry it cannot use. Rejecting it at registration is the
	// only place the problem is contained to the one node that caused it.
	//
	// FIPS 203 gives the check for free: ByteDecode must round-trip, so a
	// coefficient outside [0, q) is refused by the standard library.
	if _, err := mlkem.NewEncapsulationKey1024(keys.KemPublicKey); err != nil {
		if len(keys.KemPublicKey) != kemPublicKeySize {
			return "", fmt.Errorf("%w: kem key is %d bytes, want %d",
				ErrBadPublicKey, len(keys.KemPublicKey), kemPublicKeySize)
		}
		return "", fmt.Errorf("%w: kem key is not a valid ML-KEM-1024 encapsulation key: %v",
			ErrBadPublicKey, err)
	}
	return Handle(pub), nil
}

// Register records an identity, returning its handle.
//
// Idempotent: re-registering the same key is a no-op, which is what a node
// re-running enrollment after losing its local state does. Registering a
// *different* key under an existing handle is impossible without a SHA-256
// collision, but it is checked rather than assumed — the cost is one
// comparison and the alternative is a silent identity takeover.
func (s *Store) Register(pub []byte, keys DataPlaneKeys) (string, error) {
	handle, err := ValidateRegistration(pub, keys)
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()

	var existing Identity
	err = s.db.Where("handle = ?", handle).First(&existing).Error
	switch {
	case err == nil:
		if !bytesEqual(existing.PublicKey, pub) {
			return "", ErrKeyMismatch
		}
		// The data-plane keys MAY change: they are rotated independently of
		// the identity, and a node that regenerates them re-registers under
		// the same handle. The identity key is what must not move.
		if !bytesEqual(existing.KemPublicKey, keys.KemPublicKey) {
			if err := s.db.Model(&Identity{}).Where("handle = ?", handle).
				Updates(map[string]any{
					"kem_public_key": keys.KemPublicKey,
					"updated_at":     now,
				}).Error; err != nil {
				return "", fmt.Errorf("node: update keys: %w", err)
			}
		}
		return handle, nil
	case errors.Is(err, gorm.ErrRecordNotFound):
	default:
		return "", fmt.Errorf("node: lookup: %w", err)
	}

	rec := Identity{
		Handle:       handle,
		PublicKey:    pub,
		KemPublicKey: keys.KemPublicKey,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	// DoNothing rather than an error: two connections from the same node can
	// race here, and both should succeed.
	if err := s.db.Clauses(clause.OnConflict{DoNothing: true}).Create(&rec).Error; err != nil {
		return "", fmt.Errorf("node: register: %w", err)
	}
	return handle, nil
}

// Get returns the full identity record for a handle.
func (s *Store) Get(handle string) (*Identity, error) {
	var rec Identity
	if err := s.db.Where("handle = ?", handle).First(&rec).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUnknownNode
		}
		return nil, fmt.Errorf("node: get: %w", err)
	}
	return &rec, nil
}

// Delete removes a deprovisioned node and every session observation in which
// it participated. Observations have no useful meaning once either endpoint
// has been removed, and retaining them can otherwise expose stale topology in
// later posture views.
func (s *Store) Delete(handle string) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("reporter_handle = ? OR peer_handle = ?", handle, handle).Delete(&SessionObservation{}).Error; err != nil {
			return fmt.Errorf("node: delete session observations: %w", err)
		}
		result := tx.Where("handle = ?", handle).Delete(&Identity{})
		if result.Error != nil {
			return fmt.Errorf("node: delete identity: %w", result.Error)
		}
		if result.RowsAffected == 0 {
			return ErrUnknownNode
		}
		return nil
	})
}

// SetHomeRelay records the relay a node reports holding a connection to.
//
// Writes only when the value actually moved. Every node reports this on every
// netmap poll, so an unconditional write would be one row update per node per
// refresh interval — churn that buys nothing, and that would move UpdatedAt on
// rows nothing had changed.
//
// An unknown handle is not an error: the caller has already authenticated the
// node, and a row that has not been registered yet has nothing to hold.
func (s *Store) SetHomeRelay(handle string, relayID []byte) error {
	if len(relayID) != 0 && len(relayID) != relayIDSize {
		return fmt.Errorf("%w: %d bytes, want %d or 0", ErrBadHomeRelay, len(relayID), relayIDSize)
	}
	// Normalized to empty rather than nil so the comparison below has one
	// representation of "no relay" to test against.
	if relayID == nil {
		relayID = []byte{}
	}
	err := s.db.Model(&Identity{}).
		Where("handle = ? AND (home_relay IS NULL OR home_relay <> ?)", handle, relayID).
		Updates(map[string]any{"home_relay": relayID}).Error
	if err != nil {
		return fmt.Errorf("node: set home relay: %w", err)
	}
	return nil
}

// SetCandidates records a node's own self-reported AVEN candidate list —
// see Identity.Candidates' own doc comment.
//
// Writes only when the value actually changed, the same reasoning
// SetHomeRelay's own comment gives: every node reports this on every netmap
// poll (`bins/karstd/src/run.rs`'s `refresh_netmap`, every tick, not only on
// a real change — unlike `set_local_candidates`'s own client-side dedup,
// which only governs when a `CallMeMaybe` goes out, not what this report
// carries), so an unconditional write would be one row update per node per
// refresh interval for no reason.
//
// An unknown handle is not an error, for the same reason SetHomeRelay's
// is not: the caller has already authenticated the node, and a row that has
// not been registered yet has nothing to hold.
func (s *Store) SetCandidates(handle string, candidates []string) error {
	encoded, err := json.Marshal(candidates)
	if err != nil {
		return fmt.Errorf("node: encode candidates: %w", err)
	}
	err = s.db.Model(&Identity{}).
		Where("handle = ? AND candidates <> ?", handle, string(encoded)).
		Updates(map[string]any{"candidates": string(encoded)}).Error
	if err != nil {
		return fmt.Errorf("node: set candidates: %w", err)
	}
	return nil
}

// GetMany returns the identity records for a set of handles, keyed by handle.
// Handles with no record are simply absent — a peer that has not completed
// registration has no data-plane keys to distribute.
func (s *Store) GetMany(handles []string) (map[string]*Identity, error) {
	out := make(map[string]*Identity, len(handles))
	if len(handles) == 0 {
		return out, nil
	}
	var recs []Identity
	if err := s.db.Where("handle IN ?", handles).Find(&recs).Error; err != nil {
		return nil, fmt.Errorf("node: get many: %w", err)
	}
	for i := range recs {
		out[recs[i].Handle] = &recs[i]
	}
	return out, nil
}

// All returns every enrolled identity, ordered by handle.
//
// Ordered because the caller that needs this is rendering the relay's roster
// (ponor-v1.md §5.3), and a file whose lines shuffle between renders is a file
// that appears to change on every write. The relay reloads on any change, so
// unordered output would turn a no-op refresh into a parse and a swap of the
// admission table several times a minute.
func (s *Store) All() ([]Identity, error) {
	var recs []Identity
	if err := s.db.Order("handle").Find(&recs).Error; err != nil {
		return nil, fmt.Errorf("node: all: %w", err)
	}
	return recs, nil
}

// AccountsByHandle returns the owning account ID for each of the given
// handles that currently has a live peer — ADR-0033. A handle is looked up
// by joining against the forked server's own `peers` table, on the same
// column identity (`peers.key`) node.go's own package doc explains: a
// handle *is* the value stored in `Peer.Key`.
//
// A handle absent from the result has no live peer right now — most often
// because its peer was since deleted, orphaning the Karst-owned identity row
// that outlives it. That is not "account unknown, guess a default"; the
// caller (the roster renderer) must treat it as "this identity is not
// currently enrolled anywhere" and admit it nowhere, which is exactly what
// an identity with no live peer should get.
func (s *Store) AccountsByHandle(handles []string) (map[string]string, error) {
	if len(handles) == 0 {
		return map[string]string{}, nil
	}
	if !s.db.Migrator().HasTable("peers") {
		// Not an error: a database genuinely missing the peers table has no
		// accounts to report, and the roster's own fail-safe is an empty
		// roster (admits nobody), not a hard failure that takes the relay's
		// admission down entirely over what may be a fixture or a bootstrap
		// ordering quirk rather than real misconfiguration.
		return map[string]string{}, nil
	}
	type row struct {
		Key       string
		AccountID string
	}
	var rows []row
	if err := s.db.Table("peers").
		Select("key, account_id").
		Where("key IN ?", handles).
		Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("node: accounts by handle: %w", err)
	}
	out := make(map[string]string, len(rows))
	for _, r := range rows {
		out[r.Key] = r.AccountID
	}
	return out, nil
}

// Lookup returns the stored public key for a handle, or ErrUnknownNode.
func (s *Store) Lookup(handle string) ([]byte, error) {
	var rec Identity
	if err := s.db.Where("handle = ?", handle).First(&rec).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUnknownNode
		}
		return nil, fmt.Errorf("node: lookup: %w", err)
	}
	return rec.PublicKey, nil
}

// LookupFunc adapts the store to channel.IdentityLookup.
//
// It returns nil for anything it cannot resolve, including on a database
// error. That is deliberate: the caller is mid-handshake with an
// unauthenticated peer, and a nil result means "verify against the presented
// key or reject", which is the safe reading of every failure here. The
// alternative — distinguishing "unknown" from "database down" to the peer —
// is a node-ID oracle.
func (s *Store) LookupFunc() channel.IdentityLookup {
	return func(nodeID []byte) []byte {
		if len(nodeID) == 0 {
			return nil
		}
		pub, err := s.Lookup(string(nodeID))
		if err != nil {
			return nil
		}
		return pub
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
