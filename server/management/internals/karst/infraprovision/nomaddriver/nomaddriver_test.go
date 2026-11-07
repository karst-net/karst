// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package nomaddriver

import (
	"context"
	"fmt"
	"testing"

	nomadapi "github.com/hashicorp/nomad/api"

	"github.com/netbirdio/netbird/management/internals/karst/infraprovision"
)

// fakeJobs is a hand-rolled, in-memory stand-in for the handful of Nomad
// Jobs calls this driver makes -- satisfies jobsAPI, so tests never need
// a real Nomad cluster.
type fakeJobs struct {
	jobs          map[string]*fakeJob
	nextID        int
	dispatchErr   error
	dispatchCalls int
}

type fakeJob struct {
	parentID string
	status   string
	meta     map[string]string
}

func newFakeJobs() *fakeJobs { return &fakeJobs{jobs: map[string]*fakeJob{}} }

func (f *fakeJobs) ListOptions(_ *nomadapi.JobListOptions, _ *nomadapi.QueryOptions) ([]*nomadapi.JobListStub, *nomadapi.QueryMeta, error) {
	var out []*nomadapi.JobListStub
	for id, j := range f.jobs {
		out = append(out, &nomadapi.JobListStub{ID: id, ParentID: j.parentID, Status: j.status, Meta: j.meta})
	}
	return out, nil, nil
}

func (f *fakeJobs) Info(jobID string, _ *nomadapi.QueryOptions) (*nomadapi.Job, *nomadapi.QueryMeta, error) {
	j, ok := f.jobs[jobID]
	if !ok {
		return nil, nil, fmt.Errorf("job %s not found", jobID)
	}
	id, parentID, status := jobID, j.parentID, j.status
	return &nomadapi.Job{ID: &id, ParentID: &parentID, Status: &status, Meta: j.meta}, nil, nil
}

func (f *fakeJobs) Dispatch(jobID string, meta map[string]string, _ []byte, _ string, _ *nomadapi.WriteOptions) (*nomadapi.JobDispatchResponse, *nomadapi.WriteMeta, error) {
	f.dispatchCalls++
	if f.dispatchErr != nil {
		return nil, nil, f.dispatchErr
	}
	f.nextID++
	id := fmt.Sprintf("%s/dispatch-%d", jobID, f.nextID)
	f.jobs[id] = &fakeJob{parentID: jobID, status: "running", meta: meta}
	return &nomadapi.JobDispatchResponse{DispatchedJobID: id}, nil, nil
}

func (f *fakeJobs) Deregister(jobID string, purge bool, _ *nomadapi.WriteOptions) (string, *nomadapi.WriteMeta, error) {
	j, ok := f.jobs[jobID]
	if !ok {
		return "", nil, nil
	}
	if purge {
		delete(f.jobs, jobID)
	} else {
		j.status = "dead"
	}
	return "", nil, nil
}

func testDriver(jobs jobsAPI) *Driver {
	return &Driver{jobs: jobs, jobID: "relay-launch", datacenter: "dc1"}
}

func TestCreateDispatchesOnceAndFindsExistingOnRetry(t *testing.T) {
	fake := newFakeJobs()
	d := testDriver(fake)
	ctx := context.Background()
	req := infraprovision.CreateRequest{ControlAPIBase: "https://control.example", Token: "tok-1"}

	first, err := d.Create(ctx, "alloc-1", req)
	if err != nil {
		t.Fatalf("first create: %v", err)
	}
	if first.ID == "" || first.TLSServerName == "" {
		t.Fatalf("got %+v, want a populated instance", first)
	}
	if fake.dispatchCalls != 1 {
		t.Fatalf("got %d Dispatch calls, want exactly 1", fake.dispatchCalls)
	}
	if got := fake.jobs[first.ID].meta[datacenterMetaKey]; got != "dc1" {
		t.Fatalf("got datacenter meta %q, want %q to flow through from the driver's own config", got, "dc1")
	}

	second, err := d.Create(ctx, "alloc-1", req)
	if err != nil {
		t.Fatalf("second create (retry): %v", err)
	}
	if second != first {
		t.Fatalf("got %+v on retry, want the same already-live instance %+v", second, first)
	}
	if fake.dispatchCalls != 1 {
		t.Fatalf("got %d Dispatch calls after a retry, want still exactly 1 (find-before-create)", fake.dispatchCalls)
	}
}

func TestCreateIgnoresADeadDispatchWithTheSameAllocationID(t *testing.T) {
	fake := newFakeJobs()
	d := testDriver(fake)
	ctx := context.Background()
	req := infraprovision.CreateRequest{ControlAPIBase: "https://control.example", Token: "tok-2"}

	first, err := d.Create(ctx, "alloc-2", req)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	fake.jobs[first.ID].status = "dead" // simulate a torn-down previous allocation reusing nothing

	second, err := d.Create(ctx, "alloc-2", req)
	if err != nil {
		t.Fatalf("create after dead: %v", err)
	}
	if second.ID == first.ID {
		t.Fatalf("got the dead job's id reused, want a fresh dispatch once the previous one is dead")
	}
	if fake.dispatchCalls != 2 {
		t.Fatalf("got %d Dispatch calls, want 2 (first live one found-not, second after dead)", fake.dispatchCalls)
	}
}

func TestDestroyReadsMetaBeforePurging(t *testing.T) {
	fake := newFakeJobs()
	d := testDriver(fake)
	ctx := context.Background()

	created, err := d.Create(ctx, "alloc-3", infraprovision.CreateRequest{ControlAPIBase: "https://control.example", Token: "tok-3"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	name, err := d.Destroy(ctx, created.ID)
	if err != nil {
		t.Fatalf("destroy: %v", err)
	}
	if name != created.TLSServerName {
		t.Fatalf("got tls server name %q, want %q", name, created.TLSServerName)
	}
	if _, ok := fake.jobs[created.ID]; ok {
		t.Fatalf("job %s still present after Destroy", created.ID)
	}
}

func TestDrainDeregistersWithoutPurgeAndReachesDead(t *testing.T) {
	fake := newFakeJobs()
	d := testDriver(fake)
	ctx := context.Background()

	created, err := d.Create(ctx, "alloc-4", infraprovision.CreateRequest{ControlAPIBase: "https://control.example", Token: "tok-4"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := d.Drain(ctx, created.ID); err != nil {
		t.Fatalf("drain: %v", err)
	}
	if fake.jobs[created.ID].status != "dead" {
		t.Fatalf("got status %q after drain, want dead", fake.jobs[created.ID].status)
	}
}

func TestCreatePropagatesADispatchFailure(t *testing.T) {
	fake := newFakeJobs()
	fake.dispatchErr = fmt.Errorf("no such parameterized job")
	d := testDriver(fake)

	if _, err := d.Create(context.Background(), "alloc-5", infraprovision.CreateRequest{ControlAPIBase: "https://control.example", Token: "tok-5"}); err == nil {
		t.Fatal("got nil error, want the underlying Dispatch failure surfaced")
	}
}
