// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package control_test

import (
	"context"
	"sync"
	"testing"

	pb "google.golang.org/protobuf/proto"

	"github.com/netbirdio/netbird/management/internals/karst/ephemeralanchor"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// fakeEphemeralAnchors stands in for *ephemeralanchor.Store, mirroring
// fakeRegionAllow's own reasoning: what is under test here is the handler's
// own validation, not the store's bucketing (ephemeralanchor's own tests
// already cover that).
type fakeEphemeralAnchors struct {
	mu                  sync.Mutex
	anchors             []ephemeralanchor.AnchorEntry
	windowPeriodSeconds uint32
	dutyCycleSeconds    uint32
	recorded            []fakeEphemeralAnchorRTTRecord
}

type fakeEphemeralAnchorRTTRecord struct {
	label string
	rttMs uint32
}

func (f *fakeEphemeralAnchors) Anchors(context.Context) ([]ephemeralanchor.AnchorEntry, error) {
	return f.anchors, nil
}

func (f *fakeEphemeralAnchors) Schedule(context.Context) (uint32, uint32, error) {
	return f.windowPeriodSeconds, f.dutyCycleSeconds, nil
}

func (f *fakeEphemeralAnchors) RecordEphemeralAnchorRTT(_ context.Context, label string, rttMs uint32) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.recorded = append(f.recorded, fakeEphemeralAnchorRTTRecord{label, rttMs})
	return nil
}

func (f *fakeEphemeralAnchors) snapshot() []fakeEphemeralAnchorRTTRecord {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]fakeEphemeralAnchorRTTRecord(nil), f.recorded...)
}

func requestNetmapWithEphemeralAnchorRTT(t *testing.T, f *netFixture, reports []*proto.KarstEphemeralAnchorRtt) {
	t.Helper()
	payload, err := pb.Marshal(&proto.KarstNetmapRequest{EphemeralAnchorRtt: reports})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := f.handler.Handle(context.Background(), nil, f.self.Public(), payload); err != nil {
		t.Fatalf("netmap: %v", err)
	}
}

func TestEphemeralAnchorRTTInsideTheAnchorListIsRecorded(t *testing.T) {
	f := newNetmapFixture(t, 1)
	anchors := &fakeEphemeralAnchors{anchors: []ephemeralanchor.AnchorEntry{
		{Label: "aws:us-west-2-den-1a", Address: "10.0.0.1", Port: 22},
	}}
	f.handler.EphemeralAnchors = anchors

	requestNetmapWithEphemeralAnchorRTT(t, f, []*proto.KarstEphemeralAnchorRtt{
		{Label: "aws:us-west-2-den-1a", RttMs: 6},
	})

	got := anchors.snapshot()
	if len(got) != 1 {
		t.Fatalf("recorded %d reports, want 1", len(got))
	}
	if got[0] != (fakeEphemeralAnchorRTTRecord{"aws:us-west-2-den-1a", 6}) {
		t.Fatalf("recorded %+v, want aws:us-west-2-den-1a/6ms", got[0])
	}
}

// A buggy or compromised node reporting a label outside the deployment's
// current anchor list must not pollute the aggregate — the same defense in
// depth recordAnchorRTT already applies to an out-of-allowlist region.
func TestEphemeralAnchorRTTOutsideTheAnchorListIsIgnored(t *testing.T) {
	f := newNetmapFixture(t, 1)
	anchors := &fakeEphemeralAnchors{anchors: []ephemeralanchor.AnchorEntry{
		{Label: "aws:us-west-2-den-1a", Address: "10.0.0.1", Port: 22},
	}}
	f.handler.EphemeralAnchors = anchors

	requestNetmapWithEphemeralAnchorRTT(t, f, []*proto.KarstEphemeralAnchorRtt{
		{Label: "aws:us-east-1-bos-1a", RttMs: 6},
	})

	if got := anchors.snapshot(); len(got) != 0 {
		t.Fatalf("recorded %d reports outside the anchor list, want 0: %+v", len(got), got)
	}
}

// With no EphemeralAnchors store configured at all (as a deployment that
// never set KARST_EPHEMERAL_ANCHORS_FILE), a reported RTT is dropped rather
// than causing a netmap failure — matching every other piece of advisory
// telemetry on this path.
func TestEphemeralAnchorRTTWithNoStoreConfiguredIsDroppedNotFatal(t *testing.T) {
	f := newNetmapFixture(t, 1)

	resp := requestNetmap(t, f, 0)
	if resp == nil {
		t.Fatal("expected a netmap response")
	}
	requestNetmapWithEphemeralAnchorRTT(t, f, []*proto.KarstEphemeralAnchorRtt{
		{Label: "aws:us-west-2-den-1a", RttMs: 6},
	})
}

// An empty anchor list (EphemeralAnchors configured but Reconciled with
// nothing) rejects every report — the empty-table guarantee's handler-level
// proof, the same fail-closed default TestAnchorRTTWithAnEmptyAllowlistIsIgnored
// documents for the region allowlist.
func TestEphemeralAnchorRTTWithAnEmptyAnchorListIsIgnored(t *testing.T) {
	f := newNetmapFixture(t, 1)
	anchors := &fakeEphemeralAnchors{}
	f.handler.EphemeralAnchors = anchors

	requestNetmapWithEphemeralAnchorRTT(t, f, []*proto.KarstEphemeralAnchorRtt{
		{Label: "aws:us-west-2-den-1a", RttMs: 6},
	})

	if got := anchors.snapshot(); len(got) != 0 {
		t.Fatalf("recorded %d reports against an empty anchor list, want 0", len(got))
	}
}
