// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package control_test

import (
	"context"
	"sync"
	"testing"

	pb "google.golang.org/protobuf/proto"

	"github.com/netbirdio/netbird/management/internals/karst/regionallow"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// fakeRegionAllow stands in for *regionallow.Store. It records every
// RecordAnchorRTT call rather than bucketing/persisting it, because what is
// under test here is the handler's own validation — which reports reach the
// store at all — not the store's own bucketing, which regionallow's own
// tests already cover.
type fakeRegionAllow struct {
	mu       sync.Mutex
	doc      regionallow.Document
	recorded []fakeAnchorRTTRecord
}

type fakeAnchorRTTRecord struct {
	provider, region string
	rttMs            uint32
}

func (f *fakeRegionAllow) AllowedRegions(context.Context) (regionallow.Document, error) {
	return f.doc, nil
}

func (f *fakeRegionAllow) RecordAnchorRTT(_ context.Context, provider, region string, rttMs uint32) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.recorded = append(f.recorded, fakeAnchorRTTRecord{provider, region, rttMs})
	return nil
}

func (f *fakeRegionAllow) snapshot() []fakeAnchorRTTRecord {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]fakeAnchorRTTRecord(nil), f.recorded...)
}

func requestNetmapWithAnchorRTT(t *testing.T, f *netFixture, reports []*proto.KarstAnchorRtt) {
	t.Helper()
	payload, err := pb.Marshal(&proto.KarstNetmapRequest{AnchorRtt: reports})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := f.handler.Handle(context.Background(), nil, f.self.Public(), payload); err != nil {
		t.Fatalf("netmap: %v", err)
	}
}

func TestAnchorRTTInsideTheAllowlistIsRecorded(t *testing.T) {
	f := newNetmapFixture(t, 1)
	regions := &fakeRegionAllow{doc: regionallow.Document{"aws": {"us-east-1"}}}
	f.handler.RegionAllow = regions

	requestNetmapWithAnchorRTT(t, f, []*proto.KarstAnchorRtt{
		{Provider: "aws", Region: "us-east-1", RttMs: 42},
	})

	got := regions.snapshot()
	if len(got) != 1 {
		t.Fatalf("recorded %d reports, want 1", len(got))
	}
	if got[0] != (fakeAnchorRTTRecord{"aws", "us-east-1", 42}) {
		t.Fatalf("recorded %+v, want aws/us-east-1/42ms", got[0])
	}
}

// A buggy or compromised node reporting a region outside the deployment's
// current allowlist must not pollute the aggregate — the same defense in
// depth the session-observation path already applies to an unauthorized peer
// handle.
func TestAnchorRTTOutsideTheAllowlistIsIgnored(t *testing.T) {
	f := newNetmapFixture(t, 1)
	regions := &fakeRegionAllow{doc: regionallow.Document{"aws": {"us-east-1"}}}
	f.handler.RegionAllow = regions

	requestNetmapWithAnchorRTT(t, f, []*proto.KarstAnchorRtt{
		{Provider: "aws", Region: "eu-west-1", RttMs: 42},
		{Provider: "gcp", Region: "us-east-1", RttMs: 42},
	})

	if got := regions.snapshot(); len(got) != 0 {
		t.Fatalf("recorded %d reports outside the allowlist, want 0: %+v", len(got), got)
	}
}

// With no allowlist configured at all (RegionAllow nil, as a deployment that
// never set KARST_ALLOWED_REGIONS_FILE), a reported anchor RTT is dropped
// rather than causing a netmap failure — matching every other piece of
// advisory telemetry on this path.
func TestAnchorRTTWithNoRegionAllowConfiguredIsDroppedNotFatal(t *testing.T) {
	f := newNetmapFixture(t, 1)

	resp := requestNetmap(t, f, 0)
	if resp == nil {
		t.Fatal("expected a netmap response")
	}
	requestNetmapWithAnchorRTT(t, f, []*proto.KarstAnchorRtt{
		{Provider: "aws", Region: "us-east-1", RttMs: 42},
	})
}

// An empty allowlist document (RegionAllow configured but Reconciled with
// nothing) rejects every report, the same fail-closed default §4c's own
// allowlist uses for cost-model validation.
func TestAnchorRTTWithAnEmptyAllowlistIsIgnored(t *testing.T) {
	f := newNetmapFixture(t, 1)
	regions := &fakeRegionAllow{doc: regionallow.Document{}}
	f.handler.RegionAllow = regions

	requestNetmapWithAnchorRTT(t, f, []*proto.KarstAnchorRtt{
		{Provider: "aws", Region: "us-east-1", RttMs: 42},
	})

	if got := regions.snapshot(); len(got) != 0 {
		t.Fatalf("recorded %d reports against an empty allowlist, want 0", len(got))
	}
}
