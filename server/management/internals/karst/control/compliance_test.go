// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package control_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"
	pb "google.golang.org/protobuf/proto"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/netbirdio/netbird/management/internals/controllers/network_map/update_channel"
	"github.com/netbirdio/netbird/management/internals/karst/channel"
	"github.com/netbirdio/netbird/management/internals/karst/compliance"
	"github.com/netbirdio/netbird/management/internals/karst/control"
	"github.com/netbirdio/netbird/management/internals/karst/identity"
	"github.com/netbirdio/netbird/management/internals/karst/node"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/shared/management/proto"
)

type complianceEnrollment struct {
	ID        string `gorm:"primaryKey"`
	AccountID string
	Key       string
}

func (complianceEnrollment) TableName() string { return "peers" }
func complianceDB(t *testing.T) (*gorm.DB, *compliance.Store) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "control.db")), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { _ = sqlDB.Close() })
	require.NoError(t, db.AutoMigrate(&complianceEnrollment{}))
	store, err := compliance.NewStore(db)
	require.NoError(t, err)
	return db, store
}
func challengeRequest() *proto.KarstComplianceRequest {
	return &proto.KarstComplianceRequest{SchemaVersion: 1, Operation: &proto.KarstComplianceRequest_Challenge{Challenge: true}}
}
func complianceReport(token []byte) *proto.KarstComplianceRequest {
	return &proto.KarstComplianceRequest{SchemaVersion: 1, Operation: &proto.KarstComplianceRequest_Report{Report: &proto.KarstComplianceReport{
		Challenge: token, CollectorVersion: "v0.1.0", Platform: "darwin", ClientVersion: &proto.KarstComplianceObservation{Status: proto.KarstComplianceObservation_COLLECTED, Version: "v0.1.0"}, OsVersion: &proto.KarstComplianceObservation{Status: proto.KarstComplianceObservation_COLLECTED, Version: "15.1"},
	}}}
}
func marshalCompliance(t *testing.T, r *proto.KarstComplianceRequest) []byte {
	t.Helper()
	b, err := pb.Marshal(r)
	require.NoError(t, err)
	return b
}

func TestComplianceIngestOverAuthenticatedChannel(t *testing.T) {
	db, store := complianceDB(t)
	clock := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	peers := &fakePeers{byKey: map[string]*nbpeer.Peer{}}
	h := &control.ComplianceHandler{Store: store, Peers: peers, Now: func() time.Time { return clock }}
	f := newFixture(t, nil, control.HandlerFunc(func(ctx context.Context, id, identity, payload []byte) ([]byte, error) {
		if len(payload) == 0 || payload[0] != control.KindCompliance {
			return nil, status.Error(codes.InvalidArgument, "wrong kind")
		}
		return h.Handle(ctx, id, identity, payload[1:])
	}))
	defer f.cleanup()
	handle := node.Handle(f.nodeKey.Public())
	subject := compliance.Subject{TenantID: "account-a", DeviceID: "enrollment-a"}
	peers.byKey[handle] = &nbpeer.Peer{ID: subject.DeviceID, AccountID: subject.TenantID, Key: handle}
	require.NoError(t, db.Create(&complianceEnrollment{ID: subject.DeviceID, AccountID: subject.TenantID, Key: handle}).Error)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := f.client.Session(ctx)
	require.NoError(t, err)
	client, err := control.Dial(stream, f.svc.Pins(), identity.ControlVerifier{}, nil, identity.ControlSigner{Key: f.nodeKey}, true)
	require.NoError(t, err)
	request := func(r *proto.KarstComplianceRequest) *proto.KarstComplianceResponse {
		t.Helper()
		out, err := client.Request(append([]byte{control.KindCompliance}, marshalCompliance(t, r)...))
		require.NoError(t, err)
		response := &proto.KarstComplianceResponse{}
		require.NoError(t, pb.Unmarshal(out, response))
		return response
	}
	challenge := request(challengeRequest())
	require.Len(t, challenge.Challenge, 32)
	require.Equal(t, uint32(60), challenge.ValidForSeconds)
	require.False(t, challenge.Accepted)
	clock = clock.Add(time.Second)
	// Unknown identity-like payload fields have no effect: only the handshake
	// identity and its authoritative enrollment select the evidence destination.
	r := complianceReport(challenge.Challenge)
	unknown := protowire.AppendTag(nil, 100, protowire.BytesType)
	unknown = protowire.AppendString(unknown, "victim-tenant/victim-device")
	r.ProtoReflect().SetUnknown(unknown)
	accepted := request(r)
	require.True(t, accepted.Accepted)
	require.Empty(t, accepted.Challenge)
	latest, err := store.Latest(ctx, subject, handle, clock)
	require.NoError(t, err)
	require.Equal(t, subject, latest.Evidence.Subject)
	require.Equal(t, compliance.SelfReported, latest.Evidence.Provenance)
	require.Equal(t, clock, latest.Evidence.ReceivedAt)
	_, err = store.Latest(ctx, compliance.Subject{TenantID: "victim-tenant", DeviceID: "victim-device"}, handle, clock)
	require.ErrorIs(t, err, compliance.ErrNotEnrolled)
	// A replay is refused even though the authenticated stream is still valid.
	_, err = client.Request(append([]byte{control.KindCompliance}, marshalCompliance(t, r)...))
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
}

func TestComplianceHandlerRefusesSpoofingAndReplacesFailures(t *testing.T) {
	db, store := complianceDB(t)
	clock := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	first, err := identity.Generate()
	require.NoError(t, err)
	second, err := identity.Generate()
	require.NoError(t, err)
	handle := node.Handle(first.Public())
	otherHandle := node.Handle(second.Public())
	peers := &fakePeers{byKey: map[string]*nbpeer.Peer{
		handle: {ID: "device-a", AccountID: "account-a", Key: handle}, otherHandle: {ID: "device-b", AccountID: "account-b", Key: otherHandle},
	}}
	for _, p := range peers.byKey {
		require.NoError(t, db.Create(&complianceEnrollment{ID: p.ID, AccountID: p.AccountID, Key: p.Key}).Error)
	}
	h := &control.ComplianceHandler{Store: store, Peers: peers, Now: func() time.Time { return clock }}
	call := func(key *identity.Key, r *proto.KarstComplianceRequest) (*proto.KarstComplianceResponse, error) {
		out, err := h.Handle(context.Background(), []byte("forged-node-id"), key.Public(), marshalCompliance(t, r))
		if err != nil {
			return nil, err
		}
		resp := &proto.KarstComplianceResponse{}
		require.NoError(t, pb.Unmarshal(out, resp))
		return resp, nil
	}
	c, err := call(first, challengeRequest())
	require.NoError(t, err)
	_, err = call(second, complianceReport(c.Challenge))
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	_, err = call(first, complianceReport(c.Challenge))
	require.NoError(t, err)
	for _, o := range []*proto.KarstComplianceObservation{
		nil,
		{Status: proto.KarstComplianceObservation_UNSUPPORTED},
		{Status: proto.KarstComplianceObservation_COLLECTION_ERROR},
		{Status: proto.KarstComplianceObservation_Status(99)},
		{Status: proto.KarstComplianceObservation_COLLECTION_ERROR, Version: "cached-pass"},
	} {
		clock = clock.Add(time.Second)
		c, err = call(first, challengeRequest())
		require.NoError(t, err)
		r := complianceReport(c.Challenge)
		r.GetReport().ClientVersion = o
		_, err = call(first, r)
		require.NoError(t, err)
		latest, err := store.Latest(context.Background(), compliance.Subject{TenantID: "account-a", DeviceID: "device-a"}, handle, clock)
		require.NoError(t, err)
		result, err := compliance.Evaluate([]compliance.Requirement{{ID: "client", Kind: compliance.MinimumClientVersion, Provenance: compliance.SelfReported, MinimumVersion: "0.1.0"}}, latest.Evidence.Subject, &latest.Evidence, clock)
		require.NoError(t, err)
		require.False(t, result.Satisfied())
	}
	// Stale manager/cache data cannot authorize a deleted enrollment: the store
	// rechecks and locks the authoritative peer within the ingestion transaction.
	require.NoError(t, db.Delete(&complianceEnrollment{}, "id = ?", "device-a").Error)
	_, err = call(first, challengeRequest())
	require.Equal(t, codes.NotFound, status.Code(err))
}

func TestComplianceHandlerInputValidation(t *testing.T) {
	db, store := complianceDB(t)
	key, err := identity.Generate()
	require.NoError(t, err)
	handle := node.Handle(key.Public())
	peers := &fakePeers{byKey: map[string]*nbpeer.Peer{handle: {ID: "device", AccountID: "account", Key: handle}}}
	require.NoError(t, db.Create(&complianceEnrollment{ID: "device", AccountID: "account", Key: handle}).Error)
	h := &control.ComplianceHandler{Store: store, Peers: peers}
	tests := []struct {
		name    string
		payload []byte
	}{
		{"invalid protobuf", []byte{0xff}},
		{"empty", nil},
		{"unsupported schema", marshalCompliance(t, &proto.KarstComplianceRequest{SchemaVersion: 2})},
		{"missing operation", marshalCompliance(t, &proto.KarstComplianceRequest{SchemaVersion: 1})},
		{"false challenge", marshalCompliance(t, &proto.KarstComplianceRequest{SchemaVersion: 1, Operation: &proto.KarstComplianceRequest_Challenge{}})},
		{"oversize payload", []byte(strings.Repeat("x", 4097))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := h.Handle(context.Background(), nil, key.Public(), tt.payload)
			require.Equal(t, codes.InvalidArgument, status.Code(err))
		})
	}
	r := complianceReport(make([]byte, 32))
	r.GetReport().CollectorVersion = strings.Repeat("x", 129)
	_, err = h.Handle(context.Background(), nil, key.Public(), marshalCompliance(t, r))
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	h.Store = nil
	_, err = h.Handle(context.Background(), nil, key.Public(), marshalCompliance(t, challengeRequest()))
	require.Equal(t, codes.Unimplemented, status.Code(err))
}

func TestComplianceExpiryPushesTheAuthenticatedControlStream(t *testing.T) {
	db, store := complianceDB(t)
	f := newFixture(t, nil, nil)
	defer f.cleanup()
	handle := node.Handle(f.nodeKey.Public())
	subject := compliance.Subject{TenantID: "account-expiry", DeviceID: "device-expiry"}
	peer := &nbpeer.Peer{ID: subject.DeviceID, AccountID: subject.TenantID, Key: handle}
	require.NoError(t, db.Create(&complianceEnrollment{ID: peer.ID, AccountID: peer.AccountID, Key: peer.Key}).Error)
	peers := &fakePeers{byKey: map[string]*nbpeer.Peer{handle: peer}}
	updates := update_channel.NewPeersUpdateManager(nil)
	f.svc.SubscribeToUpdatesWith(peers, updates)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := f.client.Session(ctx)
	require.NoError(t, err)
	hello, err := stream.Recv()
	require.NoError(t, err)
	init, ch, err := channel.Initiate(hello.GetHello(), f.svc.Pins(), identity.ControlVerifier{}, []byte(handle), identity.ControlSigner{Key: f.nodeKey}, true)
	require.NoError(t, err)
	require.NoError(t, stream.Send(&proto.KarstClientMessage{Msg: &proto.KarstClientMessage_Init{Init: init}}))
	require.Eventually(t, func() bool { return updates.HasNotificationChannel(subject.DeviceID) }, 2*time.Second, 10*time.Millisecond)
	received := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	challenge, err := store.Issue(ctx, subject, handle, received)
	require.NoError(t, err)
	require.NoError(t, store.Submit(ctx, subject, handle, challenge.Token, compliance.Report{CollectorVersion: "0.1.0", Platform: compliance.MacOS, ClientVersion: compliance.Observation{Status: compliance.Collected, Version: "0.1.0"}}, received))
	publish := func(ctx context.Context, id string) error { updates.SendNotification(ctx, id); return nil }
	assertPush := func() {
		t.Helper()
		message, err := stream.Recv()
		require.NoError(t, err)
		require.NotNil(t, message.GetEnvelope())
		body, err := ch.Open(message.GetEnvelope())
		require.NoError(t, err)
		require.Equal(t, []byte{control.KindPush}, body)
	}
	require.NoError(t, store.ProcessInvalidations(ctx, received, publish))
	assertPush()
	// No report or client request is needed to wake the held stream at expiry.
	require.NoError(t, store.ProcessInvalidations(ctx, received.Add(compliance.EvidenceLifetime), publish))
	assertPush()
}
