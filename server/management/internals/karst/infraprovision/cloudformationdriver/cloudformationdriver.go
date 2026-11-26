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
// Create launches estavelle-instance.yaml (duplicated below as
// instanceTemplate -- see that constant's own doc comment for why) as one
// stack per allocation, named karst-estavelle-<allocationID>, and does not
// wait for it to finish: CreateStack is asynchronous, unlike RunInstances,
// so TLSServerName -- already polled every tick by estavellealloc's
// grantStep for every driver, "" meaning "not yet, retry" -- is what
// discovers the stack's own completion, exactly the same retry path a
// provider's ordinary boot-time delay already uses. Both the instance this
// launches and the stack itself are tagged karst:pool=<allocationID>; the
// stack tag is never read back by this driver (the instance's own tag is
// enough), but it keeps a CreateStack caught by
// deploy/aws/scaler/iam-policy.json's tag-conditioned RunInstances
// statement attributable to the same allocation in the AWS console.
package cloudformationdriver

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	cftypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/netbirdio/netbird/management/internals/karst/infraprovision"
)

// poolTagKey/tlsServerNameTagKey/tlsServerNameSuffix are awsdriver's own
// constants, duplicated rather than imported: the two driver packages must
// never depend on each other (infraconnections picks exactly one per
// connection), and nothing about tagging is specific to either transport,
// so there's nothing to factor out into without a third, "shared AWS
// driver bits" package neither needs anywhere else.
const (
	poolTagKey          = "karst:pool"
	tlsServerNameTagKey = "karst:tls-server-name"
	tlsServerNameSuffix = "aws.karst.internal"
	stackNamePrefix     = "karst-estavelle-"
)

// drainTimeout/drainPollInterval match awsdriver's own values -- the
// underlying operation (StepInstances on the stack's own EC2 instance) is
// identical, CloudFormation plays no part in draining.
const (
	drainTimeout      = 120 * time.Second
	drainPollInterval = 5 * time.Second
)

// instanceTemplate is deploy/aws/scaler/estavelle-instance.yaml, verbatim.
// go:embed cannot reach outside this Go module's own tree (server/go.mod)
// up to deploy/, so the two are kept byte-identical by hand -- the same
// relationship awsdriver.go's encodeEnrollBundleTOML already has with
// bins/karst-scaler-aws's Rust bundle.rs, one package over.
const instanceTemplate = `AWSTemplateFormatVersion: "2010-09-09"

Description: >
  One estavelle EC2 instance for one estavellealloc allocation -- driven
  only by cloudformationdriver, never deployed by hand.

Parameters:
  AmiId:
    Type: AWS::EC2::Image::Id
  InstanceType:
    Type: String
  SubnetId:
    Type: AWS::EC2::Subnet::Id
  SecurityGroupIds:
    Type: List<AWS::EC2::SecurityGroup::Id>
  PoolId:
    Type: String
  TlsServerName:
    Type: String
  UserData:
    Type: String
    NoEcho: true

Resources:
  EstavelleInstance:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: !Ref AmiId
      InstanceType: !Ref InstanceType
      SubnetId: !Ref SubnetId
      SecurityGroupIds: !Ref SecurityGroupIds
      UserData: !Ref UserData
      Tags:
        - Key: "karst:pool"
          Value: !Ref PoolId
        - Key: "karst:tls-server-name"
          Value: !Ref TlsServerName

Outputs:
  InstanceId:
    Value: !Ref EstavelleInstance
`

// LaunchDefaults is the AWS launch shape this driver actuates every Create
// against; infraconnections converts its own Account fields into this
// directly -- every AWS connection's launch defaults, unconditionally.
type LaunchDefaults struct {
	AMIID            string
	InstanceType     string
	SubnetID         string
	SecurityGroupIDs []string
}

// cfnAPI/ec2API are the handful of calls this driver makes, narrowed so
// tests supply fakes instead of real SDK clients -- awsdriver's own
// ec2API doc comment explains the pattern.
type cfnAPI interface {
	CreateStack(ctx context.Context, in *cloudformation.CreateStackInput, optFns ...func(*cloudformation.Options)) (*cloudformation.CreateStackOutput, error)
	DescribeStacks(ctx context.Context, in *cloudformation.DescribeStacksInput, optFns ...func(*cloudformation.Options)) (*cloudformation.DescribeStacksOutput, error)
	DeleteStack(ctx context.Context, in *cloudformation.DeleteStackInput, optFns ...func(*cloudformation.Options)) (*cloudformation.DeleteStackOutput, error)
}

type ec2API interface {
	DescribeInstances(ctx context.Context, in *ec2.DescribeInstancesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error)
	StopInstances(ctx context.Context, in *ec2.StopInstancesInput, optFns ...func(*ec2.Options)) (*ec2.StopInstancesOutput, error)
}

// Driver implements infraprovision.Driver against one CloudFormation
// client, one EC2 client (tag-based instance lookups only -- it never
// calls RunInstances/TerminateInstances itself) and one connection's own
// launch defaults.
type Driver struct {
	cfn      cfnAPI
	ec2      ec2API
	defaults LaunchDefaults
}

// New builds a Driver from ready *cloudformation.Client/*ec2.Client --
// infraconnections owns building both (region, credentials) from its own
// decrypted secret, exactly as it already does for awsdriver.New.
func New(cfn *cloudformation.Client, ec2Client *ec2.Client, defaults LaunchDefaults) *Driver {
	return &Driver{cfn: cfn, ec2: ec2Client, defaults: defaults}
}

var _ infraprovision.Driver = (*Driver)(nil)

func stackNameFor(allocationID string) string { return stackNamePrefix + allocationID }

func allocationIDFromStack(stackName string) string {
	return strings.TrimPrefix(stackName, stackNamePrefix)
}

func tagValue(tags []ec2types.Tag, key string) string {
	for _, t := range tags {
		if aws.ToString(t.Key) == key {
			return aws.ToString(t.Value)
		}
	}
	return ""
}

// encodeEnrollBundleTOML is awsdriver's own function, verbatim -- see that
// package's doc comment for why it is hand-rolled rather than a shared
// dependency. Both drivers must keep producing byte-identical UserData for
// karst-relay's own `enroll` boot path to parse either one the same way.
func encodeEnrollBundleTOML(controlAPIBase, token, tlsServerName string) string {
	return fmt.Sprintf("control_api_base = %s\ntoken = %s\ntls_server_name = %s\n",
		strconv.Quote(controlAPIBase), strconv.Quote(token), strconv.Quote(tlsServerName))
}

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

// instanceByPool looks up the one live instance (if any) tagged
// karst:pool=allocationID -- identical in spirit to awsdriver's
// describeLiveInstanceByPool, reused by both Create's own crash-recovery
// check and resolveInstance below, by allocation id rather than by stack
// status, so it finds an instance regardless of which driver a past
// attempt against the same allocation actually used.
func (d *Driver) instanceByPool(ctx context.Context, allocationID string) (instanceID, tlsServerName string, err error) {
	out, err := d.ec2.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
		Filters: []ec2types.Filter{
			{Name: aws.String("tag:" + poolTagKey), Values: []string{allocationID}},
			{Name: aws.String("instance-state-name"), Values: []string{"pending", "running", "stopping", "stopped"}},
		},
	})
	if err != nil {
		return "", "", fmt.Errorf("describe instances: %w", err)
	}
	for _, reservation := range out.Reservations {
		for _, instance := range reservation.Instances {
			return aws.ToString(instance.InstanceId), tagValue(instance.Tags, tlsServerNameTagKey), nil
		}
	}
	return "", "", nil
}

// resolveInstance is TLSServerName/Drain/Destroy's shared lookup: the
// stack's own status first (a genuine CloudFormation failure is a real
// error, not a "not yet" retry signal), then the instance it created, by
// the same karst:pool tag instanceByPool already filters on. "", "", nil
// means "stack is still in progress, or complete but the instance isn't
// discoverable yet" -- both are TLSServerName's existing "not yet" case.
func (d *Driver) resolveInstance(ctx context.Context, stackName string) (instanceID, tlsServerName string, err error) {
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
	return d.instanceByPool(ctx, allocationIDFromStack(stackName))
}

// Create is this driver's CreateStack, called only after confirming nothing
// live already exists for allocationID -- by instance tag first (the same
// crash-recovery guard awsdriver.Create makes, checked this way so it is
// correct regardless of which driver a past attempt against this exact
// allocation used), then by stack existence (CreateStack itself is
// asynchronous, so a stack already CREATE_IN_PROGRESS from a previous tick
// must not be launched a second time). Returns immediately once CreateStack
// is accepted; it does not wait for CREATE_COMPLETE -- TLSServerName's own
// "" retry convention is what the caller already polls for that.
func (d *Driver) Create(ctx context.Context, allocationID string, req infraprovision.CreateRequest) (infraprovision.Instance, error) {
	if id, name, err := d.instanceByPool(ctx, allocationID); err != nil {
		return infraprovision.Instance{}, &infraprovision.DriverError{Msg: err.Error()}
	} else if id != "" {
		return infraprovision.Instance{ID: stackNameFor(allocationID), TLSServerName: name}, nil
	}

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
	userData := base64.StdEncoding.EncodeToString([]byte(encodeEnrollBundleTOML(req.ControlAPIBase, req.Token, name)))
	amiID := d.defaults.AMIID
	if req.Image != "" {
		amiID = req.Image
	}
	_, err = d.cfn.CreateStack(ctx, &cloudformation.CreateStackInput{
		StackName:    aws.String(stackName),
		TemplateBody: aws.String(instanceTemplate),
		Parameters: []cftypes.Parameter{
			{ParameterKey: aws.String("AmiId"), ParameterValue: aws.String(amiID)},
			{ParameterKey: aws.String("InstanceType"), ParameterValue: aws.String(d.defaults.InstanceType)},
			{ParameterKey: aws.String("SubnetId"), ParameterValue: aws.String(d.defaults.SubnetID)},
			{ParameterKey: aws.String("SecurityGroupIds"), ParameterValue: aws.String(strings.Join(d.defaults.SecurityGroupIDs, ","))},
			{ParameterKey: aws.String("PoolId"), ParameterValue: aws.String(allocationID)},
			{ParameterKey: aws.String("TlsServerName"), ParameterValue: aws.String(name)},
			{ParameterKey: aws.String("UserData"), ParameterValue: aws.String(userData)},
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
// complete but the instance's tag isn't discoverable yet), a real error
// only for a genuine CloudFormation failure, exactly as the
// infraprovision.Driver interface's own doc comment requires.
func (d *Driver) TLSServerName(ctx context.Context, stackName string) (string, error) {
	_, name, err := d.resolveInstance(ctx, stackName)
	if err != nil {
		return "", &infraprovision.DriverError{Msg: err.Error()}
	}
	return name, nil
}

// Drain finds the stack's own instance, then StopInstances/polls exactly
// as awsdriver.Drain already does -- CloudFormation plays no part in
// draining, only in how the instance was found.
func (d *Driver) Drain(ctx context.Context, stackName string) error {
	instanceID, _, err := d.resolveInstance(ctx, stackName)
	if err != nil {
		return &infraprovision.DriverError{Msg: err.Error()}
	}
	if instanceID == "" {
		return &infraprovision.DriverError{Msg: fmt.Sprintf("stack %s has no instance to drain yet", stackName)}
	}
	if _, err := d.ec2.StopInstances(ctx, &ec2.StopInstancesInput{InstanceIds: []string{instanceID}}); err != nil {
		return &infraprovision.DriverError{Msg: fmt.Sprintf("stop instances: %s", err)}
	}
	deadline := time.Now().Add(drainTimeout)
	for {
		state, err := d.describeInstanceState(ctx, instanceID)
		if err != nil {
			return &infraprovision.DriverError{Msg: err.Error()}
		}
		if state == ec2types.InstanceStateNameStopped || state == ec2types.InstanceStateNameTerminated {
			return nil
		}
		if time.Now().After(deadline) {
			return &infraprovision.DriverError{Msg: fmt.Sprintf("instance %s did not stop within %s", instanceID, drainTimeout)}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(drainPollInterval):
		}
	}
}

func (d *Driver) describeInstanceState(ctx context.Context, instanceID string) (ec2types.InstanceStateName, error) {
	out, err := d.ec2.DescribeInstances(ctx, &ec2.DescribeInstancesInput{InstanceIds: []string{instanceID}})
	if err != nil {
		return "", fmt.Errorf("describe instances: %w", err)
	}
	for _, reservation := range out.Reservations {
		for _, instance := range reservation.Instances {
			if instance.State != nil {
				return instance.State.Name, nil
			}
		}
	}
	return "", nil
}

// Destroy reads the instance's own tls-server-name tag back first (best
// effort: a lookup failure here still proceeds to delete the stack, since
// Destroy must be robust/idempotent for cleanup -- a caller that already
// has no use for the name, e.g. a stack an operator deleted by hand, must
// not get stuck undestroyable), then DeleteStack -- which terminates the
// EC2 instance as part of tearing down its own stack, instead of this
// driver calling TerminateInstances itself the way awsdriver.Destroy does.
func (d *Driver) Destroy(ctx context.Context, stackName string) (string, error) {
	_, tlsServerName, _ := d.resolveInstance(ctx, stackName)
	if _, err := d.cfn.DeleteStack(ctx, &cloudformation.DeleteStackInput{StackName: aws.String(stackName)}); err != nil {
		return "", &infraprovision.DriverError{Msg: fmt.Sprintf("delete stack: %s", err)}
	}
	return tlsServerName, nil
}
