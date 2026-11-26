// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package cloudformationdriver

import (
	"context"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	cftypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/netbirdio/netbird/management/internals/karst/infraprovision"
)

// fakeEC2 holds the DescribeInstances/StopInstances surface this driver
// reads and acts on -- it never calls RunInstances/TerminateInstances
// itself (fakeCFN's own CreateStack/DeleteStack simulate those side
// effects instead, exactly as the real CloudFormation service would).
type fakeEC2 struct {
	instances map[string]*fakeInstance
	nextID    int
}

type fakeInstance struct {
	state ec2types.InstanceStateName
	tags  []ec2types.Tag
}

func newFakeEC2() *fakeEC2 { return &fakeEC2{instances: map[string]*fakeInstance{}} }

func (f *fakeEC2) addInstance(tags []ec2types.Tag) string {
	f.nextID++
	id := fmt.Sprintf("i-%d", f.nextID)
	f.instances[id] = &fakeInstance{state: ec2types.InstanceStateNameRunning, tags: tags}
	return id
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

func containsStr(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

func matchesFilters(inst *fakeInstance, filters []ec2types.Filter) bool {
	for _, filter := range filters {
		name := aws.ToString(filter.Name)
		if name == "tag:"+poolTagKey {
			if !containsStr(filter.Values, tagValue(inst.tags, poolTagKey)) {
				return false
			}
		}
	}
	return true
}

// fakeCFN simulates just enough of CloudFormation for this driver:
// CreateStack records the stack and, unless instantComplete is false,
// immediately plays out what a real stack would eventually do -- create
// the tagged EC2 instance and mark itself CREATE_COMPLETE. instantComplete
// = false lets a test observe the CREATE_IN_PROGRESS window TLSServerName
// must treat as "not yet", not a failure.
type fakeCFN struct {
	ec2             *fakeEC2
	stacks          map[string]*fakeStack
	instantComplete bool
	createErr       error
	createCalls     int
	lastParams      map[string]string
	deletedStacks   []string
}

type fakeStack struct {
	status cftypes.StackStatus
}

func newFakeCFN(ec2Fake *fakeEC2) *fakeCFN {
	return &fakeCFN{ec2: ec2Fake, stacks: map[string]*fakeStack{}, instantComplete: true}
}

func (f *fakeCFN) CreateStack(_ context.Context, in *cloudformation.CreateStackInput, _ ...func(*cloudformation.Options)) (*cloudformation.CreateStackOutput, error) {
	f.createCalls++
	if f.createErr != nil {
		return nil, f.createErr
	}
	name := aws.ToString(in.StackName)
	f.lastParams = map[string]string{}
	for _, p := range in.Parameters {
		f.lastParams[aws.ToString(p.ParameterKey)] = aws.ToString(p.ParameterValue)
	}
	status := cftypes.StackStatusCreateInProgress
	if f.instantComplete {
		status = cftypes.StackStatusCreateComplete
		f.ec2.addInstance([]ec2types.Tag{
			{Key: aws.String(poolTagKey), Value: aws.String(f.lastParams["PoolId"])},
			{Key: aws.String(tlsServerNameTagKey), Value: aws.String(f.lastParams["TlsServerName"])},
		})
	}
	f.stacks[name] = &fakeStack{status: status}
	return &cloudformation.CreateStackOutput{}, nil
}

func (f *fakeCFN) DescribeStacks(_ context.Context, in *cloudformation.DescribeStacksInput, _ ...func(*cloudformation.Options)) (*cloudformation.DescribeStacksOutput, error) {
	name := aws.ToString(in.StackName)
	stack, ok := f.stacks[name]
	if !ok {
		return nil, fmt.Errorf("ValidationError: Stack with id %s does not exist", name)
	}
	return &cloudformation.DescribeStacksOutput{Stacks: []cftypes.Stack{{StackName: aws.String(name), StackStatus: stack.status}}}, nil
}

func (f *fakeCFN) DeleteStack(_ context.Context, in *cloudformation.DeleteStackInput, _ ...func(*cloudformation.Options)) (*cloudformation.DeleteStackOutput, error) {
	name := aws.ToString(in.StackName)
	f.deletedStacks = append(f.deletedStacks, name)
	delete(f.stacks, name)
	return &cloudformation.DeleteStackOutput{}, nil
}

// completeStack flips an in-progress stack to CREATE_COMPLETE and spawns
// its instance -- simulating a later tick after CloudFormation finishes.
func (f *fakeCFN) completeStack(name string) {
	f.stacks[name].status = cftypes.StackStatusCreateComplete
	f.ec2.addInstance([]ec2types.Tag{
		{Key: aws.String(poolTagKey), Value: aws.String(f.lastParams["PoolId"])},
		{Key: aws.String(tlsServerNameTagKey), Value: aws.String(f.lastParams["TlsServerName"])},
	})
}

func testDriver(cfn cfnAPI, ec2Fake ec2API) *Driver {
	return &Driver{cfn: cfn, ec2: ec2Fake, defaults: LaunchDefaults{
		AMIID: "ami-test", InstanceType: "t3.micro", SubnetID: "subnet-test", SecurityGroupIDs: []string{"sg-test"},
	}}
}

func TestCreateLaunchesStackOnceAndFindsExistingOnRetry(t *testing.T) {
	ec2Fake := newFakeEC2()
	cfn := newFakeCFN(ec2Fake)
	d := testDriver(cfn, ec2Fake)
	ctx := context.Background()
	req := infraprovision.CreateRequest{ControlAPIBase: "https://control.example", Token: "tok-1"}

	first, err := d.Create(ctx, "alloc-1", req)
	if err != nil {
		t.Fatalf("first create: %v", err)
	}
	if first.ID != stackNameFor("alloc-1") {
		t.Fatalf("got instance id %q, want the stack name %q", first.ID, stackNameFor("alloc-1"))
	}
	if cfn.createCalls != 1 {
		t.Fatalf("got %d CreateStack calls, want exactly 1", cfn.createCalls)
	}

	second, err := d.Create(ctx, "alloc-1", req)
	if err != nil {
		t.Fatalf("second create (retry): %v", err)
	}
	if second.ID != first.ID {
		t.Fatalf("got %+v on retry, want the same stack id as %+v", second, first)
	}
	if cfn.createCalls != 1 {
		t.Fatalf("got %d CreateStack calls after a retry, want still exactly 1 (find-before-create)", cfn.createCalls)
	}
}

func TestTLSServerNameRetriesWhileStackInProgressThenResolves(t *testing.T) {
	ec2Fake := newFakeEC2()
	cfn := newFakeCFN(ec2Fake)
	cfn.instantComplete = false
	d := testDriver(cfn, ec2Fake)
	ctx := context.Background()

	created, err := d.Create(ctx, "alloc-2", infraprovision.CreateRequest{ControlAPIBase: "https://control.example", Token: "tok-2"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	name, err := d.TLSServerName(ctx, created.ID)
	if err != nil {
		t.Fatalf("TLSServerName while stack is CREATE_IN_PROGRESS: unexpected error %v", err)
	}
	if name != "" {
		t.Fatalf("got %q while stack is still in progress, want \"\" (not yet, not a failure)", name)
	}

	cfn.completeStack(created.ID)
	name, err = d.TLSServerName(ctx, created.ID)
	if err != nil {
		t.Fatalf("TLSServerName after completion: %v", err)
	}
	if name == "" {
		t.Fatal("got \"\" after the stack completed, want the derived tls server name")
	}
}

func TestTLSServerNameReturnsErrorOnStackFailure(t *testing.T) {
	ec2Fake := newFakeEC2()
	cfn := newFakeCFN(ec2Fake)
	cfn.instantComplete = false
	d := testDriver(cfn, ec2Fake)
	ctx := context.Background()

	created, err := d.Create(ctx, "alloc-3", infraprovision.CreateRequest{ControlAPIBase: "https://control.example", Token: "tok-3"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	cfn.stacks[created.ID].status = cftypes.StackStatusRollbackComplete

	if _, err := d.TLSServerName(ctx, created.ID); err == nil {
		t.Fatal("got nil error for a ROLLBACK_COMPLETE stack, want a failure surfaced (not a \"retry\" empty string)")
	}
}

func TestDestroyDeletesStackAndReturnsTag(t *testing.T) {
	ec2Fake := newFakeEC2()
	cfn := newFakeCFN(ec2Fake)
	d := testDriver(cfn, ec2Fake)
	ctx := context.Background()

	created, err := d.Create(ctx, "alloc-4", infraprovision.CreateRequest{ControlAPIBase: "https://control.example", Token: "tok-4"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	wantName, err := d.TLSServerName(ctx, created.ID)
	if err != nil || wantName == "" {
		t.Fatalf("precondition: TLSServerName = %q, %v", wantName, err)
	}

	gotName, err := d.Destroy(ctx, created.ID)
	if err != nil {
		t.Fatalf("destroy: %v", err)
	}
	if gotName != wantName {
		t.Fatalf("got tls server name %q, want %q", gotName, wantName)
	}
	if len(cfn.deletedStacks) != 1 || cfn.deletedStacks[0] != created.ID {
		t.Fatalf("got deleted stacks %v, want exactly [%s]", cfn.deletedStacks, created.ID)
	}
}

func TestDrainStopsTheUnderlyingInstance(t *testing.T) {
	ec2Fake := newFakeEC2()
	cfn := newFakeCFN(ec2Fake)
	d := testDriver(cfn, ec2Fake)
	ctx := context.Background()

	created, err := d.Create(ctx, "alloc-5", infraprovision.CreateRequest{ControlAPIBase: "https://control.example", Token: "tok-5"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := d.Drain(ctx, created.ID); err != nil {
		t.Fatalf("drain: %v", err)
	}
	var stopped bool
	for _, inst := range ec2Fake.instances {
		if inst.state == ec2types.InstanceStateNameStopped {
			stopped = true
		}
	}
	if !stopped {
		t.Fatal("no instance reached stopped after Drain")
	}
}

func TestCreatePropagatesACreateStackFailure(t *testing.T) {
	ec2Fake := newFakeEC2()
	cfn := newFakeCFN(ec2Fake)
	cfn.createErr = fmt.Errorf("quota exceeded")
	d := testDriver(cfn, ec2Fake)

	if _, err := d.Create(context.Background(), "alloc-6", infraprovision.CreateRequest{ControlAPIBase: "https://control.example", Token: "tok-6"}); err == nil {
		t.Fatal("got nil error, want the underlying CreateStack failure surfaced")
	}
}

// TestCreateHonorsAnImageOverride mirrors awsdriver's own test for issue
// #560's zero-downtime version replacement: CreateRequest.Image, when set,
// must be the AMI passed to CreateStack instead of the connection's own
// stored LaunchDefaults.AMIID.
func TestCreateHonorsAnImageOverride(t *testing.T) {
	ec2Fake := newFakeEC2()
	cfn := newFakeCFN(ec2Fake)
	d := testDriver(cfn, ec2Fake)
	ctx := context.Background()

	if _, err := d.Create(ctx, "alloc-7", infraprovision.CreateRequest{ControlAPIBase: "https://control.example", Token: "tok-7"}); err != nil {
		t.Fatalf("create: %v", err)
	}
	if cfn.lastParams["AmiId"] != "ami-test" {
		t.Fatalf("got AmiId %q with no override, want the connection's own default %q", cfn.lastParams["AmiId"], "ami-test")
	}

	if _, err := d.Create(ctx, "alloc-8", infraprovision.CreateRequest{ControlAPIBase: "https://control.example", Token: "tok-8", Image: "ami-v2"}); err != nil {
		t.Fatalf("create: %v", err)
	}
	if cfn.lastParams["AmiId"] != "ami-v2" {
		t.Fatalf("got AmiId %q with an override set, want %q", cfn.lastParams["AmiId"], "ami-v2")
	}
}
