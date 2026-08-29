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
	// The two keys PHREATIC does use: static KEM S (ML-KEM-768, 1184 B) and
	// static DH D (X25519, 32 B). Peers cannot handshake without them, and the
	// netmap is how they are distributed.
	KemPublicKey []byte
	DhPublicKey  []byte
	// HomeRelay is the Ponor relay this node reports holding a connection to
	// (ponor-v1.md §9.1), or empty for a node holding none.
	//
	// Reported by the node rather than decided here: the choice is made from
	// round-trip times only the node can measure. The server's job is to
	// remember it and hand it to the node's peers, which is what makes a peer
	// behind a symmetric NAT reachable at all — a peer that dials the wrong
	// relay reaches nothing, so this being stale is not a slow path but a
	// missing one.
	HomeRelay []byte
	CreatedAt time.Time
	UpdatedAt time.Time
}

// EnrollmentOwner binds the secret of a portal-issued, one-time setup key to
// its authenticated owner until registration succeeds. The setup-key schema we
// inherit does not carry an owner; storing only a SHA-256 digest here prevents
// this Karst table from becoming another plaintext-key store.
type EnrollmentOwner struct {
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
	ObservedAt     time.Time `gorm:"not null;index"`
}

func (SessionObservation) TableName() string { return "karst_session_observations" }

func (Identity) TableName() string { return "karst_node_identities" }

func (EnrollmentOwner) TableName() string { return "karst_enrollment_owners" }

// Store persists node identities.
type Store struct{ db *gorm.DB }

// NewStore migrates the Karst identity table and returns a store over it.
func NewStore(db *gorm.DB) (*Store, error) {
	if db == nil {
		return nil, errors.New("node: nil database")
	}
	if err := db.AutoMigrate(&Identity{}, &SessionObservation{}, &EnrollmentOwner{}, &DeviceSession{}); err != nil {
		return nil, fmt.Errorf("node: migrate: %w", err)
	}
	return &Store{db: db}, nil
}

func enrollmentKeyHash(key string) string {
	sum := sha256.Sum256([]byte(key))
	return fmt.Sprintf("%x", sum[:])
}

// BindEnrollmentKey records the portal user who may claim a one-time key.
// Calling it twice intentionally replaces a still-unused binding; the key is
// never returned by this package, and the account manager remains the source
// of truth for expiry and single-use enforcement.
func (s *Store) BindEnrollmentKey(key, userID string) error {
	if key == "" || userID == "" {
		return errors.New("node: enrollment key and user are required")
	}
	owner := EnrollmentOwner{KeyHash: enrollmentKeyHash(key), UserID: userID}
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

// ConsumeEnrollmentKey removes an owner binding only after the inherited
// account manager has accepted registration. Failed attempts keep their owner
// association for a retry until the setup key itself expires.
func (s *Store) ConsumeEnrollmentKey(key string) error {
	if key == "" {
		return nil
	}
	if err := s.db.Where("key_hash = ?", enrollmentKeyHash(key)).Delete(&EnrollmentOwner{}).Error; err != nil {
		return fmt.Errorf("node: consume enrollment key: %w", err)
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
		if o.Path != "direct" && o.Path != "relay" && o.Path != "unreachable" {
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
	KemPublicKey []byte // ML-KEM-768, 1184 B
	DhPublicKey  []byte // X25519, 32 B
}

const (
	kemPublicKeySize = 1184
	dhPublicKeySize  = 32
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
	// Parsed, not merely measured. A length check alone accepts 1184 bytes of
	// anything, and that key is then shipped to *every* peer in the account —
	// none of which can handshake with it, and each of which has to decide what
	// to do with an entry it cannot use. Rejecting it at registration is the
	// only place the problem is contained to the one node that caused it.
	//
	// FIPS 203 gives the check for free: ByteDecode must round-trip, so a
	// coefficient outside [0, q) is refused by the standard library.
	if _, err := mlkem.NewEncapsulationKey768(keys.KemPublicKey); err != nil {
		if len(keys.KemPublicKey) != kemPublicKeySize {
			return "", fmt.Errorf("%w: kem key is %d bytes, want %d",
				ErrBadPublicKey, len(keys.KemPublicKey), kemPublicKeySize)
		}
		return "", fmt.Errorf("%w: kem key is not a valid ML-KEM-768 encapsulation key: %v",
			ErrBadPublicKey, err)
	}
	if len(keys.DhPublicKey) != dhPublicKeySize {
		return "", fmt.Errorf("%w: dh key is %d bytes, want %d", ErrBadPublicKey, len(keys.DhPublicKey), dhPublicKeySize)
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
		if !bytesEqual(existing.KemPublicKey, keys.KemPublicKey) ||
			!bytesEqual(existing.DhPublicKey, keys.DhPublicKey) {
			if err := s.db.Model(&Identity{}).Where("handle = ?", handle).
				Updates(map[string]any{
					"kem_public_key": keys.KemPublicKey,
					"dh_public_key":  keys.DhPublicKey,
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
		DhPublicKey:  keys.DhPublicKey,
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
