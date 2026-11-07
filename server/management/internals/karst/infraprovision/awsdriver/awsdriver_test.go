// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package awsdriver

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/netbirdio/netbird/management/internals/karst/infraprovision"
)

// fakeEC2 is a hand-rolled, in-memory stand-in for the handful of EC2
// calls this driver makes -- satisfies ec2API, so tests never need a real
// AWS account or SDK transport mock.
type fakeEC2 struct {
	instances map[string]*fakeInstance
	nextID    int
	runErr    error
	runCalls  int
}

type fakeInstance struct {
	state ec2types.InstanceStateName
	tags  []ec2types.Tag
}

func newFakeEC2() *fakeEC2 { return &fakeEC2{instances: map[string]*fakeInstance{}} }

func (f *fakeEC2) RunInstances(_ context.Context, in *ec2.RunInstancesInput, _ ...func(*ec2.Options)) (*ec2.RunInstancesOutput, error) {
	f.runCalls++
	if f.runErr != nil {
		return nil, f.runErr
	}
	f.nextID++
	id := fmt.Sprintf("i-%d", f.nextID)
	var tags []ec2types.Tag
	if len(in.TagSpecifications) > 0 {
		tags = in.TagSpecifications[0].Tags
	}
	f.instances[id] = &fakeInstance{state: ec2types.InstanceStateNameRunning, tags: tags}
	return &ec2.RunInstancesOutput{Instances: []ec2types.Instance{{InstanceId: aws.String(id)}}}, nil
}

func (f *fakeEC2) DescribeInstances(_ context.Context, in *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	var matched []ec2types.Instance
	for id, inst := range f.instances {
		if len(in.InstanceIds) > 0 && !containsStr(in.InstanceIds, id) {
			continue
		}
		if len(in.Filters) > 0 && !matchesFilters(inst, in.Filters) {
			continue
		}
		matched = append(matched, ec2types.Instance{
			InstanceId: aws.String(id),
			State:      &ec2types.InstanceState{Name: inst.state},
			Tags:       inst.tags,
		})
	}
	return &ec2.DescribeInstancesOutput{Reservations: []ec2types.Reservation{{Instances: matched}}}, nil
}

func (f *fakeEC2) StopInstances(_ context.Context, in *ec2.StopInstancesInput, _ ...func(*ec2.Options)) (*ec2.StopInstancesOutput, error) {
	for _, id := range in.InstanceIds {
		if inst, ok := f.instances[id]; ok {
			inst.state = ec2types.InstanceStateNameStopped
		}
	}
	return &ec2.StopInstancesOutput{}, nil
}

func (f *fakeEC2) TerminateInstances(_ context.Context, in *ec2.TerminateInstancesInput, _ ...func(*ec2.Options)) (*ec2.TerminateInstancesOutput, error) {
	for _, id := range in.InstanceIds {
		delete(f.instances, id)
	}
	return &ec2.TerminateInstancesOutput{}, nil
}

func containsStr(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

func matchesFilters(inst *fakeInstance, filters []ec2types.Filter) bool {
	for _, f := range filters {
		name := aws.ToString(f.Name)
		switch {
		case strings.HasPrefix(name, "tag:"):
			if !containsStr(f.Values, tagValue(inst.tags, strings.TrimPrefix(name, "tag:"))) {
				return false
			}
		case name == "instance-state-name":
			if !containsStr(f.Values, string(inst.state)) {
				return false
			}
		}
	}
	return true
}

func testDriver(client ec2API) *Driver {
	return &Driver{client: client, defaults: LaunchDefaults{
		AMIID: "ami-test", InstanceType: "t3.micro", SubnetID: "subnet-test", SecurityGroupIDs: []string{"sg-test"},
	}}
}

func TestCreateLaunchesOnceAndFindsExistingOnRetry(t *testing.T) {
	fake := newFakeEC2()
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
	if fake.runCalls != 1 {
		t.Fatalf("got %d RunInstances calls, want exactly 1", fake.runCalls)
	}

	second, err := d.Create(ctx, "alloc-1", req)
	if err != nil {
		t.Fatalf("second create (retry): %v", err)
	}
	if second != first {
		t.Fatalf("got %+v on retry, want the same already-live instance %+v", second, first)
	}
	if fake.runCalls != 1 {
		t.Fatalf("got %d RunInstances calls after a retry, want still exactly 1 (find-before-create)", fake.runCalls)
	}
}

func TestDestroyReadsTagBeforeTerminating(t *testing.T) {
	fake := newFakeEC2()
	d := testDriver(fake)
	ctx := context.Background()

	created, err := d.Create(ctx, "alloc-2", infraprovision.CreateRequest{ControlAPIBase: "https://control.example", Token: "tok-2"})
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
	if _, ok := fake.instances[created.ID]; ok {
		t.Fatalf("instance %s still present after Destroy", created.ID)
	}
}

func TestDrainStopsAndReportsStopped(t *testing.T) {
	fake := newFakeEC2()
	d := testDriver(fake)
	ctx := context.Background()

	created, err := d.Create(ctx, "alloc-3", infraprovision.CreateRequest{ControlAPIBase: "https://control.example", Token: "tok-3"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := d.Drain(ctx, created.ID); err != nil {
		t.Fatalf("drain: %v", err)
	}
	if fake.instances[created.ID].state != ec2types.InstanceStateNameStopped {
		t.Fatalf("got state %q after drain, want stopped", fake.instances[created.ID].state)
	}
}

func TestCreatePropagatesARunInstancesFailure(t *testing.T) {
	fake := newFakeEC2()
	fake.runErr = fmt.Errorf("quota exceeded")
	d := testDriver(fake)

	if _, err := d.Create(context.Background(), "alloc-4", infraprovision.CreateRequest{ControlAPIBase: "https://control.example", Token: "tok-4"}); err == nil {
		t.Fatal("got nil error, want the underlying RunInstances failure surfaced")
	}
}
