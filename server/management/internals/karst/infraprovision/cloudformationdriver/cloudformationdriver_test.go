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
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"

	"github.com/netbirdio/netbird/management/internals/karst/infraprovision"
)

// fakeECS holds the DescribeServices/UpdateService surface this driver
// reads and acts on -- it never calls CreateService/DeleteService itself
// (fakeCFN's own CreateStack/DeleteStack simulate those side effects
// instead, exactly as the real CloudFormation service would).
type fakeECS struct {
	services map[string]*fakeService
}

type fakeService struct {
	arn          string
	runningCount int32
	tags         []ecstypes.Tag
}

func newFakeECS() *fakeECS { return &fakeECS{services: map[string]*fakeService{}} }

func (f *fakeECS) addService(name string, tags []ecstypes.Tag) {
	f.services[name] = &fakeService{arn: "arn:aws:ecs:test:service/" + name, runningCount: 1, tags: tags}
}

func (f *fakeECS) DescribeServices(_ context.Context, in *ecs.DescribeServicesInput, _ ...func(*ecs.Options)) (*ecs.DescribeServicesOutput, error) {
	var out []ecstypes.Service
	for _, name := range in.Services {
		if svc, ok := f.services[name]; ok {
			out = append(out, ecstypes.Service{
				ServiceArn:   aws.String(svc.arn),
				RunningCount: svc.runningCount,
				Tags:         svc.tags,
			})
		}
	}
	return &ecs.DescribeServicesOutput{Services: out}, nil
}

func (f *fakeECS) UpdateService(_ context.Context, in *ecs.UpdateServiceInput, _ ...func(*ecs.Options)) (*ecs.UpdateServiceOutput, error) {
	name := aws.ToString(in.Service)
	if svc, ok := f.services[name]; ok {
		if in.DesiredCount != nil && *in.DesiredCount == 0 {
			svc.runningCount = 0
		}
	}
	return &ecs.UpdateServiceOutput{}, nil
}

// fakeCFN simulates just enough of CloudFormation for this driver:
// CreateStack records the stack and, unless instantComplete is false,
// immediately plays out what a real stack would eventually do -- register
// the tagged ECS service and mark itself CREATE_COMPLETE. instantComplete
// = false lets a test observe the CREATE_IN_PROGRESS window TLSServerName
// must treat as "not yet", not a failure.
type fakeCFN struct {
	ecs             *fakeECS
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

func newFakeCFN(ecsFake *fakeECS) *fakeCFN {
	return &fakeCFN{ecs: ecsFake, stacks: map[string]*fakeStack{}, instantComplete: true}
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
		f.ecs.addService(name, []ecstypes.Tag{
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

// completeStack flips an in-progress stack to CREATE_COMPLETE and
// registers its service -- simulating a later tick after CloudFormation
// finishes.
func (f *fakeCFN) completeStack(name string) {
	f.stacks[name].status = cftypes.StackStatusCreateComplete
	f.ecs.addService(name, []ecstypes.Tag{
		{Key: aws.String(poolTagKey), Value: aws.String(f.lastParams["PoolId"])},
		{Key: aws.String(tlsServerNameTagKey), Value: aws.String(f.lastParams["TlsServerName"])},
	})
}

func testDriver(cfn cfnAPI, ecsFake ecsAPI) *Driver {
	return &Driver{cfn: cfn, ecs: ecsFake, defaults: LaunchDefaults{
		ClusterARN: "arn:aws:ecs:test:cluster/karst-test", ExecutionRoleARN: "arn:aws:iam::test:role/exec",
		CPU: "256", Memory: "512", LogGroup: "/karst/test", SubnetID: "subnet-test", SecurityGroupIDs: []string{"sg-test"},
	}}
}

const testImage = "ghcr.io/karst-net/karst-estavelle:v0.1.0-rc.49"

func TestCreateLaunchesStackOnceAndFindsExistingOnRetry(t *testing.T) {
	ecsFake := newFakeECS()
	cfn := newFakeCFN(ecsFake)
	d := testDriver(cfn, ecsFake)
	ctx := context.Background()
	req := infraprovision.CreateRequest{ControlAPIBase: "https://control.example", Token: "tok-1", Image: testImage}

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

func TestCreateRequiresAnImage(t *testing.T) {
	ecsFake := newFakeECS()
	cfn := newFakeCFN(ecsFake)
	d := testDriver(cfn, ecsFake)

	if _, err := d.Create(context.Background(), "alloc-0", infraprovision.CreateRequest{ControlAPIBase: "https://control.example", Token: "tok-0"}); err == nil {
		t.Fatal("got nil error with no Image set, want a failure: there is no connection-wide default image")
	}
	if cfn.createCalls != 0 {
		t.Fatalf("got %d CreateStack calls with no image, want 0", cfn.createCalls)
	}
}

func TestTLSServerNameRetriesWhileStackInProgressThenResolves(t *testing.T) {
	ecsFake := newFakeECS()
	cfn := newFakeCFN(ecsFake)
	cfn.instantComplete = false
	d := testDriver(cfn, ecsFake)
	ctx := context.Background()

	created, err := d.Create(ctx, "alloc-2", infraprovision.CreateRequest{ControlAPIBase: "https://control.example", Token: "tok-2", Image: testImage})
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
	ecsFake := newFakeECS()
	cfn := newFakeCFN(ecsFake)
	cfn.instantComplete = false
	d := testDriver(cfn, ecsFake)
	ctx := context.Background()

	created, err := d.Create(ctx, "alloc-3", infraprovision.CreateRequest{ControlAPIBase: "https://control.example", Token: "tok-3", Image: testImage})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	cfn.stacks[created.ID].status = cftypes.StackStatusRollbackComplete

	if _, err := d.TLSServerName(ctx, created.ID); err == nil {
		t.Fatal("got nil error for a ROLLBACK_COMPLETE stack, want a failure surfaced (not a \"retry\" empty string)")
	}
}

func TestDestroyDeletesStackAndReturnsTag(t *testing.T) {
	ecsFake := newFakeECS()
	cfn := newFakeCFN(ecsFake)
	d := testDriver(cfn, ecsFake)
	ctx := context.Background()

	created, err := d.Create(ctx, "alloc-4", infraprovision.CreateRequest{ControlAPIBase: "https://control.example", Token: "tok-4", Image: testImage})
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

func TestDrainScalesTheServiceToZero(t *testing.T) {
	ecsFake := newFakeECS()
	cfn := newFakeCFN(ecsFake)
	d := testDriver(cfn, ecsFake)
	ctx := context.Background()

	created, err := d.Create(ctx, "alloc-5", infraprovision.CreateRequest{ControlAPIBase: "https://control.example", Token: "tok-5", Image: testImage})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := d.Drain(ctx, created.ID); err != nil {
		t.Fatalf("drain: %v", err)
	}
	if ecsFake.services[created.ID].runningCount != 0 {
		t.Fatalf("got running count %d after Drain, want 0", ecsFake.services[created.ID].runningCount)
	}
}

func TestCreatePropagatesACreateStackFailure(t *testing.T) {
	ecsFake := newFakeECS()
	cfn := newFakeCFN(ecsFake)
	cfn.createErr = fmt.Errorf("quota exceeded")
	d := testDriver(cfn, ecsFake)

	if _, err := d.Create(context.Background(), "alloc-6", infraprovision.CreateRequest{ControlAPIBase: "https://control.example", Token: "tok-6", Image: testImage}); err == nil {
		t.Fatal("got nil error, want the underlying CreateStack failure surfaced")
	}
}

// TestCreateUsesTheRequestImageDirectly mirrors issue #560's own zero-
// downtime version replacement test shape, except there is no
// connection-wide default to fall back to here: every Create must name
// its own image explicitly.
func TestCreateUsesTheRequestImageDirectly(t *testing.T) {
	ecsFake := newFakeECS()
	cfn := newFakeCFN(ecsFake)
	d := testDriver(cfn, ecsFake)
	ctx := context.Background()

	if _, err := d.Create(ctx, "alloc-7", infraprovision.CreateRequest{ControlAPIBase: "https://control.example", Token: "tok-7", Image: testImage}); err != nil {
		t.Fatalf("create: %v", err)
	}
	if cfn.lastParams["Image"] != testImage {
		t.Fatalf("got Image %q, want %q", cfn.lastParams["Image"], testImage)
	}

	other := "ghcr.io/karst-net/karst-estavelle:v0.1.0-rc.50"
	if _, err := d.Create(ctx, "alloc-8", infraprovision.CreateRequest{ControlAPIBase: "https://control.example", Token: "tok-8", Image: other}); err != nil {
		t.Fatalf("create: %v", err)
	}
	if cfn.lastParams["Image"] != other {
		t.Fatalf("got Image %q, want %q", cfn.lastParams["Image"], other)
	}
}

func TestCreatePassesThePullCredentialsSecretArnFromLaunchDefaults(t *testing.T) {
	ecsFake := newFakeECS()
	cfn := newFakeCFN(ecsFake)
	d := testDriver(cfn, ecsFake)
	ctx := context.Background()

	// Unset in LaunchDefaults (testDriver's own default): the Parameter is
	// still sent, but empty -- the template's own Condition is what turns
	// that into "no RepositoryCredentials", not an empty string here.
	if _, err := d.Create(ctx, "alloc-9", infraprovision.CreateRequest{ControlAPIBase: "https://control.example", Token: "tok-9", Image: testImage}); err != nil {
		t.Fatalf("create: %v", err)
	}
	if got := cfn.lastParams["PullCredentialsSecretArn"]; got != "" {
		t.Fatalf("got PullCredentialsSecretArn %q, want empty", got)
	}

	d.defaults.PullCredentialsSecretARN = "arn:aws:secretsmanager:test:secret:karst-estavelle-ghcr-pull"
	if _, err := d.Create(ctx, "alloc-10", infraprovision.CreateRequest{ControlAPIBase: "https://control.example", Token: "tok-10", Image: testImage}); err != nil {
		t.Fatalf("create: %v", err)
	}
	if got, want := cfn.lastParams["PullCredentialsSecretArn"], d.defaults.PullCredentialsSecretARN; got != want {
		t.Fatalf("got PullCredentialsSecretArn %q, want %q", got, want)
	}
}

func TestCreateDefaultsComputeTypeToFargateAndPassesEc2ValuesThrough(t *testing.T) {
	ecsFake := newFakeECS()
	cfn := newFakeCFN(ecsFake)
	d := testDriver(cfn, ecsFake)
	ctx := context.Background()

	// Unset in LaunchDefaults (testDriver's own default, and every
	// connection stored before ComputeType existed): the template's own
	// Parameter must see "fargate" explicitly, not an empty string a
	// stray third case could later be confused with.
	if _, err := d.Create(ctx, "alloc-11", infraprovision.CreateRequest{ControlAPIBase: "https://control.example", Token: "tok-11", Image: testImage}); err != nil {
		t.Fatalf("create: %v", err)
	}
	if got := cfn.lastParams["ComputeType"]; got != "fargate" {
		t.Fatalf("got ComputeType %q, want %q", got, "fargate")
	}
	if got := cfn.lastParams["Ec2CapacityProviderName"]; got != "" {
		t.Fatalf("got Ec2CapacityProviderName %q, want empty", got)
	}

	d.defaults.ComputeType = "ec2"
	d.defaults.Ec2CapacityProviderName = "karst-estavelle-launch-defaults-asg"
	if _, err := d.Create(ctx, "alloc-12", infraprovision.CreateRequest{ControlAPIBase: "https://control.example", Token: "tok-12", Image: testImage}); err != nil {
		t.Fatalf("create: %v", err)
	}
	if got := cfn.lastParams["ComputeType"]; got != "ec2" {
		t.Fatalf("got ComputeType %q, want %q", got, "ec2")
	}
	if got, want := cfn.lastParams["Ec2CapacityProviderName"], d.defaults.Ec2CapacityProviderName; got != want {
		t.Fatalf("got Ec2CapacityProviderName %q, want %q", got, want)
	}
}
