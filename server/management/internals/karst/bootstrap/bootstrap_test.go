// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package bootstrap

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func newDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(
		sqlite.Open(fmt.Sprintf("file:bootstrap%s?mode=memory&cache=shared", t.Name())),
		&gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("db: %v", err)
	}
	if err := db.Exec("DROP TABLE IF EXISTS karst_server_keys").Error; err != nil {
		t.Fatalf("reset: %v", err)
	}
	return db
}

// The single most consequential property in this package. Nodes *pin* the
// public halves of these keys, so regenerating them on restart does not
// degrade gracefully — it breaks every enrolled node at once, and each one
// reports that the server failed to authenticate. An outage that looks like an
// attack.
func TestServerKeysSurviveRestart(t *testing.T) {
	db := newDB(t)

	first, err := loadOrCreateKeys(db)
	if err != nil {
		t.Fatalf("first start: %v", err)
	}
	second, err := loadOrCreateKeys(db)
	if err != nil {
		t.Fatalf("restart: %v", err)
	}

	if !bytes.Equal(first.KemSeed, second.KemSeed) {
		t.Fatal("the KEM seed changed across a restart; every pinned node would break")
	}
	if !bytes.Equal(first.IdentitySeed, second.IdentitySeed) {
		t.Fatal("the identity seed changed across a restart")
	}
	if !bytes.Equal(first.PSKMaster, second.PSKMaster) {
		t.Fatal("the PSK master changed; every PSK in the network would change silently")
	}
}

func TestGeneratedKeysAreTheRightSizeAndNotEmpty(t *testing.T) {
	keys, err := loadOrCreateKeys(newDB(t))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	for _, c := range []struct {
		name string
		got  []byte
		want int
	}{
		{"kem seed", keys.KemSeed, 64},
		{"identity seed", keys.IdentitySeed, 32},
		{"psk master", keys.PSKMaster, 32},
	} {
		if len(c.got) != c.want {
			t.Errorf("%s is %d bytes, want %d", c.name, len(c.got), c.want)
		}
		if allZero(c.got) {
			t.Errorf("%s is all zeros, so the CSPRNG did not run", c.name)
		}
	}
}

// Two fresh databases must not produce the same keys.
func TestSeparateDeploymentsGetSeparateKeys(t *testing.T) {
	a, err := loadOrCreateKeys(newDB(t))
	if err != nil {
		t.Fatalf("a: %v", err)
	}
	// A distinct in-memory DSN.
	db, err := gorm.Open(sqlite.Open("file:bootstrap-other?mode=memory&cache=shared"),
		&gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("db: %v", err)
	}
	if err := db.Exec("DROP TABLE IF EXISTS karst_server_keys").Error; err != nil {
		t.Fatalf("reset: %v", err)
	}
	b, err := loadOrCreateKeys(db)
	if err != nil {
		t.Fatalf("b: %v", err)
	}
	if bytes.Equal(a.PSKMaster, b.PSKMaster) {
		t.Fatal("two deployments derived the same PSK master")
	}
}

// Concurrent first starts must converge on one set of keys. Two processes each
// keeping their own would give half the fleet a pin the other half rejects.
func TestConcurrentFirstStartConverges(t *testing.T) {
	db := newDB(t)

	const n = 4
	type result struct {
		keys *ServerKeys
		err  error
	}
	results := make(chan result, n)
	for i := 0; i < n; i++ {
		go func() {
			k, err := loadOrCreateKeys(db)
			results <- result{k, err}
		}()
	}

	var first *ServerKeys
	for i := 0; i < n; i++ {
		r := <-results
		if r.err != nil {
			t.Fatalf("concurrent start: %v", r.err)
		}
		if first == nil {
			first = r.keys
			continue
		}
		if !bytes.Equal(first.PSKMaster, r.keys.PSKMaster) {
			t.Fatal("concurrent first starts produced different keys")
		}
	}
}

// The epoch is a pure function of the clock, so every instance agrees without
// coordinating and a restart cannot lose its place.
func TestCurrentEpochIsDerivedFromTheClock(t *testing.T) {
	base := time.Unix(1_700_000_000, 0).UTC()

	first, second := CurrentEpoch(base), CurrentEpoch(base)
	if first != second {
		t.Fatal("the epoch is not a function of its input")
	}
	if CurrentEpoch(base) != CurrentEpoch(base.Add(time.Hour)) {
		t.Fatal("the epoch changed within a single period")
	}
	if CurrentEpoch(base) == CurrentEpoch(base.Add(EpochSeconds*time.Second)) {
		t.Fatal("the epoch did not advance after a full period")
	}
	if CurrentEpoch(base.Add(EpochSeconds*time.Second)) != CurrentEpoch(base)+1 {
		t.Fatal("the epoch advanced by more than one across one period")
	}
}

// §7.3 accepts epochs n and n-1, so the tolerance to clock skew is one full
// period. Recorded as a test because it is the number an operator needs when
// deciding how much NTP failure is survivable.
func TestClockSkewToleranceIsOnePeriod(t *testing.T) {
	base := time.Unix(1_700_000_000, 0).UTC()
	within := CurrentEpoch(base.Add(-EpochSeconds * time.Second))
	if CurrentEpoch(base)-within != 1 {
		t.Fatal("a full period of skew is not exactly one epoch")
	}
}

// The router dispatches on the first byte, and an unknown kind must not reach
// a handler.
func TestHandlerRoutesOnKind(t *testing.T) {
	h := &handler{}
	ctx := context.Background()

	if _, err := h.Handle(ctx, nil, nil, nil); err == nil {
		t.Fatal("an empty request was accepted")
	}
	if _, err := h.Handle(ctx, nil, nil, []byte{99}); err == nil {
		t.Fatal("an unknown request kind was accepted")
	}
	// Kinds are on the wire, so their values may not drift.
	if KindLogin != 1 || KindNetmap != 2 {
		t.Fatal("request kind values changed; existing nodes would break")
	}
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}
