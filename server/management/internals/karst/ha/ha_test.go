// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package ha

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// This is deliberately a real Postgres test: LISTEN/NOTIFY timing and a
// dedicated listener connection are the behavior this package exists to own.
// The CI job may set KARST_TEST_POSTGRES_DSN; developers can use the compose
// command documented in plans/phase-6/09-ha.md's HA overlay.
func TestClaimNotifiesOtherReplica(t *testing.T) {
	dsn := os.Getenv("KARST_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("KARST_TEST_POSTGRES_DSN is not set")
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	pool, err := pgxpool.New(context.Background(), dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	channel := "karst_ha_test_" + time.Now().UTC().Format("150405000000000")
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	a, err := New(ctx, db, pool, "a", channel)
	require.NoError(t, err)
	b, err := New(ctx, db, pool, "b", channel)
	require.NoError(t, err)
	received := make(chan event, 1)
	b.OnSession(func(identity, replica, token string) {
		received <- event{Identity: identity, ReplicaID: replica, Token: token}
	})
	require.NoError(t, a.Claim(context.Background(), "identity", "token"))
	select {
	case got := <-received:
		require.Equal(t, event{Identity: "identity", ReplicaID: "a", Token: "token"}, got)
	case <-time.After(5 * time.Second):
		t.Fatal("other replica did not receive session notification")
	}
	var before ControlSession
	require.NoError(t, db.Where("identity_pub_key = ?", "identity").First(&before).Error)
	time.Sleep(time.Millisecond)
	require.NoError(t, a.Touch(context.Background(), "identity", "token"))
	var after ControlSession
	require.NoError(t, db.Where("identity_pub_key = ?", "identity").First(&after).Error)
	require.True(t, after.LastSeenAt.After(before.LastSeenAt), "heartbeat must advance durable liveness")

	// Registering after Claim models a replica that was offline while the
	// notification fired. Reconciliation must still expose the current owner.
	reconciled := make(chan event, 1)
	b.OnSession(func(identity, replica, token string) {
		reconciled <- event{Identity: identity, ReplicaID: replica, Token: token}
	})
	require.NoError(t, b.Reconcile(context.Background()))
	select {
	case got := <-reconciled:
		require.Equal(t, event{Identity: "identity", ReplicaID: "a", Token: "token"}, got)
	case <-time.After(time.Second):
		t.Fatal("reconciliation did not deliver durable session ownership")
	}
}
