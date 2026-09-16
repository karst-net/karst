package update_channel

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/netbirdio/netbird/management/internals/controllers/network_map"
	"github.com/netbirdio/netbird/management/internals/karst/ha"
	"github.com/netbirdio/netbird/shared/management/proto"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// var peersUpdater *PeersUpdateManager

func TestNotificationChannelIsNotASyncChannel(t *testing.T) {
	ctx := context.Background()
	manager := NewPeersUpdateManager(nil)
	notifications := manager.CreateNotificationChannel(ctx, "peer")

	if manager.HasChannel("peer") {
		t.Fatal("notification subscriber must not pass the full-sync channel gate")
	}
	manager.SendNotification(ctx, "peer")
	select {
	case <-notifications:
	default:
		t.Fatal("notification was not delivered")
	}

	manager.CloseChannel(ctx, "peer")
	if _, ok := <-notifications; ok {
		t.Fatal("notification channel was not closed")
	}
}

// Cross-process delivery is deliberately tested against Postgres, not a mock:
// this catches the LISTEN connection and notification timing that an in-memory
// manager cannot represent.
func TestNotificationReachesPeerOnOtherReplica(t *testing.T) {
	dsn := os.Getenv("KARST_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("KARST_TEST_POSTGRES_DSN is not set")
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	channel := "karst_updates_" + time.Now().UTC().Format("150405000000000")
	a, err := ha.New(ctx, db, pool, "a", channel)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ha.New(ctx, db, pool, "b", channel)
	if err != nil {
		t.Fatal(err)
	}
	left, right := NewPeersUpdateManager(nil), NewPeersUpdateManager(nil)
	left.PublishNotificationsWith(func(ctx context.Context, peerID string) {
		if err := a.PublishPeer(ctx, peerID); err != nil {
			t.Error(err)
		}
	})
	b.OnPeer(func(peerID string) { right.DeliverNotification(context.Background(), peerID) })
	updates := right.CreateNotificationChannel(context.Background(), "peer-on-b")
	left.SendNotification(context.Background(), "peer-on-b")
	select {
	case <-updates:
	case <-time.After(5 * time.Second):
		t.Fatal("peer notification was not delivered to the other replica")
	}
}

// GitHub issue #155: PostgreSQL LISTEN/NOTIFY has no delivery guarantee and
// no queue — a notification published while the target replica's listener
// is down or reconnecting is not delayed, it is gone. This forces exactly
// that gap (terminating replica b's own LISTEN backend, mid-test) and
// confirms a notification published into it never arrives, even generously
// past how long a reconnect actually takes. `TestResyncOnListenEstablished
// RecoversANotificationLostDuringReconnect` is the same setup with the fix
// wired in, for contrast.
func TestPeerNotificationLostDuringReconnectWithoutResync(t *testing.T) {
	dsn := os.Getenv("KARST_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("KARST_TEST_POSTGRES_DSN is not set")
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	poolA, err := pgxpool.New(context.Background(), dsn+"&application_name=karst_ha_test_a")
	if err != nil {
		t.Fatal(err)
	}
	defer poolA.Close()
	poolB, err := pgxpool.New(context.Background(), dsn+"&application_name=karst_ha_test_b")
	if err != nil {
		t.Fatal(err)
	}
	defer poolB.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	channel := "karst_lost_" + time.Now().UTC().Format("150405000000000")
	a, err := ha.New(ctx, db, poolA, "a", channel)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ha.New(ctx, db, poolB, "b", channel)
	if err != nil {
		t.Fatal(err)
	}
	left, right := NewPeersUpdateManager(nil), NewPeersUpdateManager(nil)
	left.PublishNotificationsWith(func(ctx context.Context, peerID string) {
		if err := a.PublishPeer(ctx, peerID); err != nil {
			t.Error(err)
		}
	})
	b.OnPeer(func(peerID string) { right.DeliverNotification(context.Background(), peerID) })
	updates := right.CreateNotificationChannel(context.Background(), "peer-lost")

	terminateReplicaBListener(t, db, "karst_ha_test_b")
	// Long enough that replica b's listener has certainly noticed the drop
	// and is sitting in its one-second reconnect backoff (ha.go's `listen`),
	// short enough to stay well clear of the reconnect actually completing.
	time.Sleep(300 * time.Millisecond)

	left.SendNotification(context.Background(), "peer-lost")

	select {
	case <-updates:
		t.Fatal("a notification published into a dead LISTEN connection was delivered anyway — the fixture no longer demonstrates the gap ResyncAllNotifiedPeers exists to close")
	case <-time.After(3 * time.Second):
		// Expected: PostgreSQL NOTIFY has no queue, so nothing was ever
		// going to deliver this one.
	}
}

// terminateReplicaBListener kills the PostgreSQL backend running a
// replica's LISTEN, identified by `application_name` — the two replicas in
// these tests share one notify channel, so the query text alone
// ("LISTEN <channel>") cannot tell them apart.
func terminateReplicaBListener(t *testing.T, db *gorm.DB, applicationName string) {
	t.Helper()
	var pid int
	if err := db.Raw(
		"SELECT pid FROM pg_stat_activity WHERE application_name = ? AND query LIKE 'LISTEN %'",
		applicationName,
	).Scan(&pid).Error; err != nil {
		t.Fatalf("locating replica b's LISTEN backend: %v", err)
	}
	if pid == 0 {
		t.Fatal("replica b's LISTEN backend was not found in pg_stat_activity")
	}
	if err := db.Exec("SELECT pg_terminate_backend(?)", pid).Error; err != nil {
		t.Fatalf("terminating replica b's LISTEN backend: %v", err)
	}
}

// The fix: with OnListenEstablished wired to ResyncAllNotifiedPeers, the
// very same forced disconnect in the test above now recovers instead of
// silently losing the notification, because the reconnect itself wakes
// every peer replica b still has a live subscriber for.
func TestResyncOnListenEstablishedRecoversANotificationLostDuringReconnect(t *testing.T) {
	dsn := os.Getenv("KARST_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("KARST_TEST_POSTGRES_DSN is not set")
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	poolA, err := pgxpool.New(context.Background(), dsn+"&application_name=karst_ha_test_a")
	if err != nil {
		t.Fatal(err)
	}
	defer poolA.Close()
	poolB, err := pgxpool.New(context.Background(), dsn+"&application_name=karst_ha_test_b")
	if err != nil {
		t.Fatal(err)
	}
	defer poolB.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	channel := "karst_resync_" + time.Now().UTC().Format("150405000000000")
	a, err := ha.New(ctx, db, poolA, "a", channel)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ha.New(ctx, db, poolB, "b", channel)
	if err != nil {
		t.Fatal(err)
	}
	left, right := NewPeersUpdateManager(nil), NewPeersUpdateManager(nil)
	left.PublishNotificationsWith(func(ctx context.Context, peerID string) {
		if err := a.PublishPeer(ctx, peerID); err != nil {
			t.Error(err)
		}
	})
	b.OnPeer(func(peerID string) { right.DeliverNotification(context.Background(), peerID) })
	b.OnListenEstablished(func() { right.ResyncAllNotifiedPeers(context.Background()) })
	updates := right.CreateNotificationChannel(context.Background(), "peer-reconnect")

	terminateReplicaBListener(t, db, "karst_ha_test_b")
	time.Sleep(300 * time.Millisecond)

	// Genuinely lost at the PostgreSQL level, same as the test above —
	// nothing downstream of `pg_notify` can change that. Only the
	// reconnect's own resync recovers it.
	left.SendNotification(context.Background(), "peer-reconnect")

	select {
	case <-updates:
		// Recovered by the reconnect's ResyncAllNotifiedPeers dispatch.
	case <-time.After(10 * time.Second):
		t.Fatal("replica b's reconnect did not resync the peer that missed its notification")
	}
}

func TestCreateChannel(t *testing.T) {
	peer := "test-create"
	peersUpdater := NewPeersUpdateManager(nil)
	defer peersUpdater.CloseChannel(context.Background(), peer)

	_ = peersUpdater.CreateChannel(context.Background(), peer)
	if _, ok := peersUpdater.peerChannels[peer]; !ok {
		t.Error("Error creating the channel")
	}
}

func TestSendUpdate(t *testing.T) {
	peer := "test-sendupdate"
	peersUpdater := NewPeersUpdateManager(nil)
	update1 := &network_map.UpdateMessage{
		Update: &proto.SyncResponse{
			NetworkMap: &proto.NetworkMap{
				Serial: 0,
			},
		},
		MessageType: network_map.MessageTypeNetworkMap,
	}
	_ = peersUpdater.CreateChannel(context.Background(), peer)
	if _, ok := peersUpdater.peerChannels[peer]; !ok {
		t.Error("Error creating the channel")
	}
	peersUpdater.SendUpdate(context.Background(), peer, update1)
	select {
	case <-peersUpdater.peerChannels[peer]:
	default:
		t.Error("Update wasn't send")
	}

	for range [channelBufferSize]int{} {
		peersUpdater.SendUpdate(context.Background(), peer, update1)
	}

	update2 := &network_map.UpdateMessage{
		Update: &proto.SyncResponse{
			NetworkMap: &proto.NetworkMap{
				Serial: 10,
			},
		},
		MessageType: network_map.MessageTypeNetworkMap,
	}

	peersUpdater.SendUpdate(context.Background(), peer, update2)
	timeout := time.After(5 * time.Second)
	for range [channelBufferSize]int{} {
		select {
		case <-timeout:
			t.Error("timed out reading previously sent updates")
		case updateReader := <-peersUpdater.peerChannels[peer]:
			if updateReader.Update.NetworkMap.Serial == update2.Update.NetworkMap.Serial {
				t.Error("got the update that shouldn't have been sent")
			}
		}
	}

}

// GetAllConnectedPeers and GetAllNotifiedPeers track two different maps
// (peerChannels vs. notificationChannels) — a caller reaching for "every
// connected peer" while meaning "every Karst node" must get the second one.
// control.EpochScheduler is the first caller that matters here.
func TestGetAllNotifiedPeersIsDistinctFromGetAllConnectedPeers(t *testing.T) {
	ctx := context.Background()
	manager := NewPeersUpdateManager(nil)
	defer manager.CloseChannel(ctx, "sync-peer")
	defer manager.CloseChannel(ctx, "karst-peer")

	_ = manager.CreateChannel(ctx, "sync-peer")
	_ = manager.CreateNotificationChannel(ctx, "karst-peer")

	connected := manager.GetAllConnectedPeers()
	if _, ok := connected["sync-peer"]; !ok {
		t.Error("sync-peer should appear in GetAllConnectedPeers")
	}
	if _, ok := connected["karst-peer"]; ok {
		t.Error("karst-peer uses a notification channel only and must not appear in GetAllConnectedPeers")
	}

	notified := manager.GetAllNotifiedPeers()
	if _, ok := notified["karst-peer"]; !ok {
		t.Error("karst-peer should appear in GetAllNotifiedPeers")
	}
	if _, ok := notified["sync-peer"]; ok {
		t.Error("sync-peer uses a full-sync channel only and must not appear in GetAllNotifiedPeers")
	}
}

func TestCloseChannel(t *testing.T) {
	peer := "test-close"
	peersUpdater := NewPeersUpdateManager(nil)
	_ = peersUpdater.CreateChannel(context.Background(), peer)
	if _, ok := peersUpdater.peerChannels[peer]; !ok {
		t.Error("Error creating the channel")
	}
	peersUpdater.CloseChannel(context.Background(), peer)
	if _, ok := peersUpdater.peerChannels[peer]; ok {
		t.Error("Error closing the channel")
	}
}
