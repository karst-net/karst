// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// Package cloudformationdriver is the infraprovision.Driver implementation
// for every AWS infrastructure connection (ADR-0063; ADR-0067) -- the only
// AWS actuation mechanism; there used to be a direct ec2.RunInstances one
// (infraprovision/awsdriver, removed once this replaced it) and a
// per-connection toggle between the two, but CloudFormation is not an
// option among several here, so neither the toggle nor the driver it would
// have selected away from were kept. The admin console's own request for
// an estavelle is unchanged either way: this is purely the actuation
// mechanism behind the same POST /estavelle-allocations call and the same
// in-process allocate worker (estavellealloc's drive_loop.go), never
// something the console or that worker calls the AWS CloudFormation API
// directly itself.
//
// This actuates an estavelle as one ECS Fargate Spot service, not an EC2
// instance: a direct ec2.RunInstances/CloudFormation-EC2-instance approach
// was tried first and dropped before ever shipping, once it became clear
// it needed an operator-baked AMI (karst-relay/karst-estavelle
// preinstalled, enroll wired into its own boot path) that nothing in this
// repo builds -- Fargate needs no AMI at all, since every release already
// publishes a real, signed ghcr.io/karst-net/karst-estavelle:<tag>
// container image (.github/workflows/deliverables.yml) a task pulls
// directly. An allocation's desired_image/running_image is exactly that
// tag for this mechanism, never an AMI id.
//
// Create launches estavelle-instance.yaml (duplicated below as
// instanceTemplate -- see that constant's own doc comment for why) as one
// stack per allocation, named karst-estavelle-<allocationID>, and does not
// wait for it to finish: CreateStack is asynchronous, unlike a direct
// RunTask, so TLSServerName -- already polled every tick by estavellealloc's
// grantStep for every driver, "" meaning "not yet, retry" -- is what
// discovers the stack's own completion, exactly the same retry path a
// provider's ordinary boot-time delay already uses. Both the service this
// launches and the stack itself are tagged karst:pool=<allocationID>.
//
// Unlike an EC2 instance, a Fargate task has no boot script of its own to
// decode a UserData bundle in: enrollment instead happens in-binary, via
// the three KARST_* container environment variables
// kubernetesdriver.go's own doc comment already documents --
// bins/karst-estavelle/src/main.rs's command_run checks for them and
// self-enrolls before serving.
package cloudformationdriver

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	cftypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"

	"github.com/netbirdio/netbird/management/internals/karst/infraprovision"
)

// poolTagKey/tlsServerNameTagKey/tlsServerNameSuffix/stackNamePrefix are
// awsdriver's own constants, duplicated rather than imported: the two
// driver packages must never depend on each other (infraconnections picks
// exactly one per connection), and nothing about tagging is specific to
// either transport, so there's nothing to factor out into without a
// third, "shared AWS driver bits" package neither needs anywhere else.
const (
	poolTagKey          = "karst:pool"
	tlsServerNameTagKey = "karst:tls-server-name"
	tlsServerNameSuffix = "aws.karst.internal"
	stackNamePrefix     = "karst-estavelle-"
)

// drainTimeout/drainPollInterval bound how long Drain waits for the
// service's own running task count to reach zero after UpdateService
// requests DesiredCount=0 -- ECS's own graceful stop (SIGTERM, then its
// task definition's stopTimeout before SIGKILL) is the same
// shutdown_signal -> announce_restart path bins/karstd/src/server.rs
// already handles for the Kubernetes driver's own pod deletion.
const (
	drainTimeout      = 120 * time.Second
	drainPollInterval = 5 * time.Second
)

// instanceTemplate is deploy/aws/scaler/estavelle-instance.yaml, verbatim.
// go:embed cannot reach outside this Go module's own tree (server/go.mod)
// up to deploy/, so the two are kept byte-identical by hand.
const instanceTemplate = `AWSTemplateFormatVersion: "2010-09-09"

Description: >
  One estavelle ECS Fargate Spot service for one estavellealloc allocation
  -- driven only by cloudformationdriver, never deployed by hand.

Parameters:
  ClusterArn:
    Type: String
  ExecutionRoleArn:
    Type: String
  Cpu:
    Type: String
  Memory:
    Type: String
  LogGroup:
    Type: String
  SubnetId:
    Type: AWS::EC2::Subnet::Id
  SecurityGroupIds:
    Type: List<AWS::EC2::SecurityGroup::Id>
  Image:
    Type: String
  PoolId:
    Type: String
  TlsServerName:
    Type: String
  ControlApiBase:
    Type: String
  EnrollToken:
    Type: String
    NoEcho: true
  ControlApiCaPem:
    Type: String
    Default: ""
  PullCredentialsSecretArn:
    Type: String
    Default: ""

Conditions:
  HasPullCredentials: !Not [!Equals [!Ref PullCredentialsSecretArn, ""]]

Resources:
  EstavelleTaskDefinition:
    Type: AWS::ECS::TaskDefinition
    Properties:
      Family: !Sub "karst-estavelle-${PoolId}"
      RequiresCompatibilities: [FARGATE]
      NetworkMode: awsvpc
      Cpu: !Ref Cpu
      Memory: !Ref Memory
      ExecutionRoleArn: !Ref ExecutionRoleArn
      ContainerDefinitions:
        - Name: karst-estavelle
          Image: !Ref Image
          Essential: true
          RepositoryCredentials: !If
            - HasPullCredentials
            - CredentialsParameter: !Ref PullCredentialsSecretArn
            - !Ref "AWS::NoValue"
          PortMappings:
            - ContainerPort: 443
              Protocol: tcp
            - ContainerPort: 443
              Protocol: udp
          Environment:
            - Name: KARST_CONTROL_API_BASE
              Value: !Ref ControlApiBase
            - Name: KARST_ENROLL_TOKEN
              Value: !Ref EnrollToken
            - Name: KARST_TLS_SERVER_NAME
              Value: !Ref TlsServerName
            - Name: KARST_CONTROL_API_CA_PEM
              Value: !Ref ControlApiCaPem
          LogConfiguration:
            LogDriver: awslogs
            Options:
              awslogs-group: !Ref LogGroup
              awslogs-region: !Ref AWS::Region
              awslogs-stream-prefix: estavelle

  EstavelleService:
    Type: AWS::ECS::Service
    Properties:
      Cluster: !Ref ClusterArn
      TaskDefinition: !Ref EstavelleTaskDefinition
      DesiredCount: 1
      CapacityProviderStrategy:
        - CapacityProvider: FARGATE_SPOT
          Weight: 1
      NetworkConfiguration:
        AwsvpcConfiguration:
          Subnets: [!Ref SubnetId]
          SecurityGroups: !Ref SecurityGroupIds
          AssignPublicIp: ENABLED
      EnableECSManagedTags: true
      PropagateTags: SERVICE
      Tags:
        - Key: "karst:pool"
          Value: !Ref PoolId
        - Key: "karst:tls-server-name"
          Value: !Ref TlsServerName

Outputs:
  ServiceArn:
    Value: !Ref EstavelleService
`

// LaunchDefaults is the AWS launch shape this driver actuates every Create
// against; infraconnections converts its own Account fields into this
// directly -- every AWS connection's launch defaults, unconditionally.
// Fargate sizes a task by CPU/Memory rather than an instance type, and
// needs a cluster plus a task execution role; there is no AMI id here --
// an allocation's own desired/running image supplies that instead (see
// Create's own req.Image handling).
type LaunchDefaults struct {
	ClusterARN       string
	ExecutionRoleARN string
	CPU              string
	Memory           string
	LogGroup         string
	SubnetID         string
	SecurityGroupIDs []string
	// PullCredentialsSecretARN is optional: an AWS Secrets Manager secret
	// ARN the task execution role may read to pull a private
	// ghcr.io/karst-net/karst-estavelle image -- empty means an
	// anonymous/public pull, unchanged from before this field existed. See
	// estavelle-launch-defaults.yaml's own header comment for how to
	// create the secret and grant the execution role access to it.
	PullCredentialsSecretARN string
}

// cfnAPI/ecsAPI are the handful of calls this driver makes, narrowed so
// tests supply fakes instead of real SDK clients -- awsdriver's own ec2API
// doc comment explains the pattern.
type cfnAPI interface {
	CreateStack(ctx context.Context, in *cloudformation.CreateStackInput, optFns ...func(*cloudformation.Options)) (*cloudformation.CreateStackOutput, error)
	DescribeStacks(ctx context.Context, in *cloudformation.DescribeStacksInput, optFns ...func(*cloudformation.Options)) (*cloudformation.DescribeStacksOutput, error)
	DeleteStack(ctx context.Context, in *cloudformation.DeleteStackInput, optFns ...func(*cloudformation.Options)) (*cloudformation.DeleteStackOutput, error)
}

type ecsAPI interface {
	DescribeServices(ctx context.Context, in *ecs.DescribeServicesInput, optFns ...func(*ecs.Options)) (*ecs.DescribeServicesOutput, error)
	UpdateService(ctx context.Context, in *ecs.UpdateServiceInput, optFns ...func(*ecs.Options)) (*ecs.UpdateServiceOutput, error)
}

// Driver implements infraprovision.Driver against one CloudFormation
// client, one ECS client (service lookups/drain only -- it never calls
// CreateService/DeleteService itself; CreateStack/DeleteStack do, as part
// of the stack's own resources) and one connection's own launch defaults.
type Driver struct {
	cfn      cfnAPI
	ecs      ecsAPI
	defaults LaunchDefaults
}

// New builds a Driver from ready *cloudformation.Client/*ecs.Client --
// infraconnections owns building both (region, credentials) from its own
// decrypted secret, exactly as it already does for awsdriver.New.
func New(cfn *cloudformation.Client, ecsClient *ecs.Client, defaults LaunchDefaults) *Driver {
	return &Driver{cfn: cfn, ecs: ecsClient, defaults: defaults}
}

var _ infraprovision.Driver = (*Driver)(nil)

// stackNameFor's own service is named identically to the stack itself, so
// resolveInstance never needs a separate tag-scan the way an EC2-based
// driver would need for an instance's own driver-assigned id -- a Fargate
// service's name is deterministic from the allocation id alone.
func stackNameFor(allocationID string) string { return stackNamePrefix + allocationID }

// isFailedStatus reports whether status is a StackStatus CloudFormation
// never recovers from on its own -- anything else (*_IN_PROGRESS or a
// *_COMPLETE that isn't one of these) is either still working or genuinely
// done.
func isFailedStatus(status cftypes.StackStatus) bool {
	switch status {
	case cftypes.StackStatusCreateFailed, cftypes.StackStatusRollbackFailed, cftypes.StackStatusRollbackComplete,
		cftypes.StackStatusDeleteFailed, cftypes.StackStatusUpdateRollbackFailed, cftypes.StackStatusUpdateRollbackComplete:
		return true
	default:
		return false
	}
}

// errStackNotFound is describeStack's own sentinel for "this stack name
// has never existed" -- DescribeStacks has no strongly-typed error for
// this, only a generic validation error whose message names the stack, so
// callers that care (only Create does) match on it via errors.Is.
var errStackNotFound = errors.New("stack not found")

func describeStack(ctx context.Context, client cfnAPI, stackName string) (cftypes.Stack, error) {
	out, err := client.DescribeStacks(ctx, &cloudformation.DescribeStacksInput{StackName: aws.String(stackName)})
	if err != nil {
		if strings.Contains(err.Error(), "does not exist") {
			return cftypes.Stack{}, errStackNotFound
		}
		return cftypes.Stack{}, err
	}
	if len(out.Stacks) == 0 {
		return cftypes.Stack{}, errStackNotFound
	}
	return out.Stacks[0], nil
}

// describeService looks up the stack's own deterministically-named
// service and returns its tls-server-name tag -- "", "", nil when the
// service does not exist yet (CreateService inside the stack hasn't
// completed) or exists but has no tags yet, both of which are
// TLSServerName's existing "not yet" case.
func (d *Driver) describeService(ctx context.Context, stackName string) (serviceArn, tlsServerName string, err error) {
	out, err := d.ecs.DescribeServices(ctx, &ecs.DescribeServicesInput{
		Cluster:  aws.String(d.defaults.ClusterARN),
		Services: []string{stackName},
		Include:  []ecstypes.ServiceField{ecstypes.ServiceFieldTags},
	})
	if err != nil {
		return "", "", fmt.Errorf("describe services: %w", err)
	}
	for _, svc := range out.Services {
		if svc.Status != nil && *svc.Status == "INACTIVE" {
			continue
		}
		for _, tag := range svc.Tags {
			if aws.ToString(tag.Key) == tlsServerNameTagKey {
				return aws.ToString(svc.ServiceArn), aws.ToString(tag.Value), nil
			}
		}
		return aws.ToString(svc.ServiceArn), "", nil
	}
	return "", "", nil
}

// resolveInstance is TLSServerName/Drain/Destroy's shared lookup: the
// stack's own status first (a genuine CloudFormation failure is a real
// error, not a "not yet" retry signal), then the service it created, by
// the stack's own deterministic name. "", "", nil means "stack is still in
// progress, or complete but the service isn't discoverable yet" -- both
// are TLSServerName's existing "not yet" case.
func (d *Driver) resolveInstance(ctx context.Context, stackName string) (serviceArn, tlsServerName string, err error) {
	stack, err := describeStack(ctx, d.cfn, stackName)
	if err != nil {
		if errors.Is(err, errStackNotFound) {
			return "", "", fmt.Errorf("stack %s no longer exists", stackName)
		}
		return "", "", err
	}
	if isFailedStatus(stack.StackStatus) {
		return "", "", fmt.Errorf("stack %s is %s", stackName, stack.StackStatus)
	}
	if stack.StackStatus != cftypes.StackStatusCreateComplete && stack.StackStatus != cftypes.StackStatusUpdateComplete {
		return "", "", nil
	}
	return d.describeService(ctx, stackName)
}

// Create is this driver's CreateStack, called only after confirming no
// stack already exists for allocationID -- CreateStack itself is
// asynchronous, so a stack already CREATE_IN_PROGRESS from a previous tick
// must not be launched a second time. Returns immediately once CreateStack
// is accepted; it does not wait for CREATE_COMPLETE -- TLSServerName's own
// "" retry convention is what the caller already polls for that.
func (d *Driver) Create(ctx context.Context, allocationID string, req infraprovision.CreateRequest) (infraprovision.Instance, error) {
	stackName := stackNameFor(allocationID)
	stack, err := describeStack(ctx, d.cfn, stackName)
	if err != nil && !errors.Is(err, errStackNotFound) {
		return infraprovision.Instance{}, &infraprovision.DriverError{Msg: err.Error()}
	}
	if err == nil {
		if isFailedStatus(stack.StackStatus) {
			return infraprovision.Instance{}, &infraprovision.DriverError{Msg: fmt.Sprintf("stack %s is %s", stackName, stack.StackStatus)}
		}
		// Already launched, or launching, on a previous tick -- TLSServerName
		// picks up its completion; don't call CreateStack a second time.
		return infraprovision.Instance{ID: stackName}, nil
	}

	name := infraprovision.TLSServerNameFor(allocationID, req.Token, tlsServerNameSuffix)
	// req.Image is a ghcr.io/karst-net/karst-estavelle:<tag> reference --
	// there is no connection-wide default to fall back to the way an AMI
	// id would be: every allocation names its own image explicitly
	// (console's "Change version" picker, or Create's own initial image).
	if req.Image == "" {
		return infraprovision.Instance{}, &infraprovision.DriverError{Msg: "an image (ghcr.io/karst-net/karst-estavelle:<tag>) is required"}
	}
	_, err = d.cfn.CreateStack(ctx, &cloudformation.CreateStackInput{
		StackName:    aws.String(stackName),
		TemplateBody: aws.String(instanceTemplate),
		Parameters: []cftypes.Parameter{
			{ParameterKey: aws.String("ClusterArn"), ParameterValue: aws.String(d.defaults.ClusterARN)},
			{ParameterKey: aws.String("ExecutionRoleArn"), ParameterValue: aws.String(d.defaults.ExecutionRoleARN)},
			{ParameterKey: aws.String("Cpu"), ParameterValue: aws.String(d.defaults.CPU)},
			{ParameterKey: aws.String("Memory"), ParameterValue: aws.String(d.defaults.Memory)},
			{ParameterKey: aws.String("LogGroup"), ParameterValue: aws.String(d.defaults.LogGroup)},
			{ParameterKey: aws.String("SubnetId"), ParameterValue: aws.String(d.defaults.SubnetID)},
			{ParameterKey: aws.String("SecurityGroupIds"), ParameterValue: aws.String(strings.Join(d.defaults.SecurityGroupIDs, ","))},
			{ParameterKey: aws.String("Image"), ParameterValue: aws.String(req.Image)},
			{ParameterKey: aws.String("PoolId"), ParameterValue: aws.String(allocationID)},
			{ParameterKey: aws.String("TlsServerName"), ParameterValue: aws.String(name)},
			{ParameterKey: aws.String("ControlApiBase"), ParameterValue: aws.String(req.ControlAPIBase)},
			{ParameterKey: aws.String("EnrollToken"), ParameterValue: aws.String(req.Token)},
			{ParameterKey: aws.String("ControlApiCaPem"), ParameterValue: aws.String(req.ControlAPICACertPEM)},
			{ParameterKey: aws.String("PullCredentialsSecretArn"), ParameterValue: aws.String(d.defaults.PullCredentialsSecretARN)},
		},
		Tags: []cftypes.Tag{{Key: aws.String(poolTagKey), Value: aws.String(allocationID)}},
	})
	if err != nil {
		return infraprovision.Instance{}, &infraprovision.DriverError{Msg: fmt.Sprintf("create stack: %s", err)}
	}
	return infraprovision.Instance{ID: stackName}, nil
}

// TLSServerName re-reads stackName's own correlation label via
// resolveInstance -- "", nil for "not yet" (stack still in progress, or
// complete but the service's tag isn't discoverable yet), a real error
// only for a genuine CloudFormation failure, exactly as the
// infraprovision.Driver interface's own doc comment requires.
func (d *Driver) TLSServerName(ctx context.Context, stackName string) (string, error) {
	_, name, err := d.resolveInstance(ctx, stackName)
	if err != nil {
		return "", &infraprovision.DriverError{Msg: err.Error()}
	}
	return name, nil
}

// Drain requests DesiredCount=0 on the stack's own service, then polls
// until its running task count reaches zero -- ECS's own graceful stop
// (SIGTERM, then its task definition's stopTimeout before SIGKILL) is the
// Fargate analog of an EC2 instance's guest-level ACPI shutdown signal.
func (d *Driver) Drain(ctx context.Context, stackName string) error {
	serviceArn, _, err := d.resolveInstance(ctx, stackName)
	if err != nil {
		return &infraprovision.DriverError{Msg: err.Error()}
	}
	if serviceArn == "" {
		return &infraprovision.DriverError{Msg: fmt.Sprintf("stack %s has no service to drain yet", stackName)}
	}
	zero := int32(0)
	if _, err := d.ecs.UpdateService(ctx, &ecs.UpdateServiceInput{
		Cluster:      aws.String(d.defaults.ClusterARN),
		Service:      aws.String(stackName),
		DesiredCount: &zero,
	}); err != nil {
		return &infraprovision.DriverError{Msg: fmt.Sprintf("update service: %s", err)}
	}
	deadline := time.Now().Add(drainTimeout)
	for {
		running, err := d.runningCount(ctx, stackName)
		if err != nil {
			return &infraprovision.DriverError{Msg: err.Error()}
		}
		if running == 0 {
			return nil
		}
		if time.Now().After(deadline) {
			return &infraprovision.DriverError{Msg: fmt.Sprintf("service %s did not drain to zero tasks within %s", stackName, drainTimeout)}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(drainPollInterval):
		}
	}
}

func (d *Driver) runningCount(ctx context.Context, stackName string) (int32, error) {
	out, err := d.ecs.DescribeServices(ctx, &ecs.DescribeServicesInput{
		Cluster:  aws.String(d.defaults.ClusterARN),
		Services: []string{stackName},
	})
	if err != nil {
		return 0, fmt.Errorf("describe services: %w", err)
	}
	for _, svc := range out.Services {
		return svc.RunningCount, nil
	}
	return 0, nil
}

// Destroy reads the service's own tls-server-name tag back first (best
// effort: a lookup failure here still proceeds to delete the stack, since
// Destroy must be robust/idempotent for cleanup -- a caller that already
// has no use for the name, e.g. a stack an operator deleted by hand, must
// not get stuck undestroyable), then DeleteStack -- which scales the
// service to zero and deletes it as part of tearing down its own stack,
// not something this driver calls UpdateService/DeleteService for itself.
func (d *Driver) Destroy(ctx context.Context, stackName string) (string, error) {
	_, tlsServerName, _ := d.resolveInstance(ctx, stackName)
	if _, err := d.cfn.DeleteStack(ctx, &cloudformation.DeleteStackInput{StackName: aws.String(stackName)}); err != nil {
		return "", &infraprovision.DriverError{Msg: fmt.Sprintf("delete stack: %s", err)}
	}
	return tlsServerName, nil
}
