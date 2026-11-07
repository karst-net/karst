// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// Package awsdriver is the infraprovision.Driver implementation backing
// an AWS infrastructure connection (ADR-0063; ADR-0067) -- a direct port
// of relayalloc's pre-ADR-0067 awsdrive.go, itself a hand-ported copy of
// bins/karst-scaler-aws/src/driver.rs and bundle.rs's own logic: this
// package cannot depend on a Rust crate, and that crate stays exactly as
// it was, still the actuator bins/karst-scaler's own drive_loop.rs
// (unrelated continuous pool autoscaling, ADR-0045 proper) uses.
package awsdriver

import (
	"context"
	"encoding/base64"
	"fmt"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/netbirdio/netbird/management/internals/karst/infraprovision"
)

// poolTagKey/tlsServerNameTagKey are driver.rs's POOL_TAG_KEY/
// TLS_SERVER_NAME_TAG_KEY, unchanged: both drivers tag instances
// identically on purpose, so deploy/aws/scaler/iam-policy.json's
// tag-conditioned statements (written against these exact keys) bound
// this actuator the same way they already bound the Rust one, and so an
// operator running both an allocation and a pool against the same
// account sees one consistent tagging convention.
const (
	poolTagKey          = "karst:pool"
	tlsServerNameTagKey = "karst:tls-server-name"
	tlsServerNameSuffix = "aws.karst.internal"
)

// drainTimeout/drainPollInterval match AwsDriver::drain's own values
// (driver.rs) -- stopping a whole EC2 guest OS is slower than a pod
// eviction, the same reasoning that constant's doc comment gives.
const (
	drainTimeout      = 120 * time.Second
	drainPollInterval = 5 * time.Second
)

// LaunchDefaults is the AWS launch shape this driver actuates every
// Create against. infraconnections converts its own Account fields into
// this before constructing a Driver, so this package never imports
// infraconnections (it holds credentials; this package must not).
type LaunchDefaults struct {
	AMIID            string
	InstanceType     string
	SubnetID         string
	SecurityGroupIDs []string
}

// ec2API is the handful of EC2 calls this driver makes, narrowed so tests
// can supply a fake instead of a real *ec2.Client -- the same "narrow
// interface, fake it" pattern relayalloc's own enrollMinter/relayFinder/
// etc. (awsdrive_loop.go, pre-ADR-0067) already use. *ec2.Client satisfies
// this directly.
type ec2API interface {
	RunInstances(ctx context.Context, in *ec2.RunInstancesInput, optFns ...func(*ec2.Options)) (*ec2.RunInstancesOutput, error)
	DescribeInstances(ctx context.Context, in *ec2.DescribeInstancesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error)
	StopInstances(ctx context.Context, in *ec2.StopInstancesInput, optFns ...func(*ec2.Options)) (*ec2.StopInstancesOutput, error)
	TerminateInstances(ctx context.Context, in *ec2.TerminateInstancesInput, optFns ...func(*ec2.Options)) (*ec2.TerminateInstancesOutput, error)
}

// Driver implements infraprovision.Driver against one EC2 client and one
// connection's own launch defaults.
type Driver struct {
	client   ec2API
	defaults LaunchDefaults
}

// New builds a Driver from a ready *ec2.Client -- infraconnections owns
// building that client (region, credentials) from its own decrypted
// secret; this package only ever actuates against one already configured.
func New(client *ec2.Client, defaults LaunchDefaults) *Driver {
	return &Driver{client: client, defaults: defaults}
}

var _ infraprovision.Driver = (*Driver)(nil)

func tagValue(tags []ec2types.Tag, key string) string {
	for _, t := range tags {
		if aws.ToString(t.Key) == key {
			return aws.ToString(t.Value)
		}
	}
	return ""
}

// encodeEnrollBundleTOML renders the exact TOML shape
// bins/karst-scaler-aws's EnrollBundle (bundle.rs) serializes via
// toml::to_string_pretty -- karst-relay's own `enroll` boot path parses
// this by key, not position, so field order here does not matter, but
// the three key names and basic-string quoting must match exactly.
// address is always omitted: an EC2 instance's own IP is unknown until
// RunInstances returns -- karst-relay enroll resolves it itself via IMDS
// after boot.
//
// Hand-rolled rather than a new TOML dependency: every value passed
// through here is one of three narrow, server-controlled shapes (a
// configured URL, a minted token, a label this package itself derives),
// never free-form user input.
func encodeEnrollBundleTOML(controlAPIBase, token, tlsServerName string) string {
	return fmt.Sprintf("control_api_base = %s\ntoken = %s\ntls_server_name = %s\n",
		strconv.Quote(controlAPIBase), strconv.Quote(token), strconv.Quote(tlsServerName))
}

// describeLiveInstanceByPool looks up the one live instance (if any)
// already tagged with allocationID's own karst:pool value -- a tick that
// crashes or restarts between a successful RunInstances and the caller's
// own record of it must not launch a second instance for the same
// allocation on retry.
func describeLiveInstanceByPool(ctx context.Context, client ec2API, allocationID string) (instanceID, tlsServerName string, err error) {
	out, err := client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
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

// Create is AwsDriver::create for exactly one instance, called only after
// describeLiveInstanceByPool has confirmed nothing live exists for
// allocationID. One RunInstances call, MinCount=MaxCount=1, tagged
// karst:pool=allocationID and karst:tls-server-name=<derived label> --
// AMI/instance type/subnet/security groups come only from the
// connection's own stored launch defaults, never from req, which does not
// and cannot carry them (ADR-0045's 2026-11-04 addendum, compensating
// control #1).
func (d *Driver) Create(ctx context.Context, allocationID string, req infraprovision.CreateRequest) (infraprovision.Instance, error) {
	instanceID, tlsServerName, err := describeLiveInstanceByPool(ctx, d.client, allocationID)
	if err != nil {
		return infraprovision.Instance{}, &infraprovision.DriverError{Msg: err.Error()}
	}
	if instanceID != "" {
		return infraprovision.Instance{ID: instanceID, TLSServerName: tlsServerName}, nil
	}
	name := infraprovision.TLSServerNameFor(allocationID, req.Token, tlsServerNameSuffix)
	userData := base64.StdEncoding.EncodeToString([]byte(encodeEnrollBundleTOML(req.ControlAPIBase, req.Token, name)))
	out, err := d.client.RunInstances(ctx, &ec2.RunInstancesInput{
		ImageId:          aws.String(d.defaults.AMIID),
		InstanceType:     ec2types.InstanceType(d.defaults.InstanceType),
		MinCount:         aws.Int32(1),
		MaxCount:         aws.Int32(1),
		UserData:         aws.String(userData),
		SubnetId:         aws.String(d.defaults.SubnetID),
		SecurityGroupIds: d.defaults.SecurityGroupIDs,
		TagSpecifications: []ec2types.TagSpecification{{
			ResourceType: ec2types.ResourceTypeInstance,
			Tags: []ec2types.Tag{
				{Key: aws.String(poolTagKey), Value: aws.String(allocationID)},
				{Key: aws.String(tlsServerNameTagKey), Value: aws.String(name)},
			},
		}},
	})
	if err != nil {
		return infraprovision.Instance{}, &infraprovision.DriverError{Msg: fmt.Sprintf("run instances: %s", err)}
	}
	if len(out.Instances) == 0 || out.Instances[0].InstanceId == nil {
		return infraprovision.Instance{}, &infraprovision.DriverError{Msg: fmt.Sprintf("allocation %s: RunInstances returned no instance", allocationID)}
	}
	return infraprovision.Instance{ID: aws.ToString(out.Instances[0].InstanceId), TLSServerName: name}, nil
}

func (d *Driver) describeInstanceState(ctx context.Context, instanceID string) (ec2types.InstanceStateName, error) {
	out, err := d.client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{InstanceIds: []string{instanceID}})
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

// TLSServerName reads back one instance's own tlsServerNameTagKey tag --
// nothing in this process persists it itself (the token it was derived
// from is discarded right after Create returns), so AWS, via this tag, is
// the only durable store for it, surviving a control-server restart.
func (d *Driver) TLSServerName(ctx context.Context, instanceID string) (string, error) {
	out, err := d.client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{InstanceIds: []string{instanceID}})
	if err != nil {
		return "", &infraprovision.DriverError{Msg: fmt.Sprintf("describe instances: %s", err)}
	}
	for _, reservation := range out.Reservations {
		for _, instance := range reservation.Instances {
			if name := tagValue(instance.Tags, tlsServerNameTagKey); name != "" {
				return name, nil
			}
		}
	}
	return "", nil
}

// Drain: StopInstances then poll until stopped/terminated or drainTimeout
// elapses. Not independently verified against a real EC2 instance in this
// environment -- same caveat this logic carried before this port.
func (d *Driver) Drain(ctx context.Context, instanceID string) error {
	if _, err := d.client.StopInstances(ctx, &ec2.StopInstancesInput{InstanceIds: []string{instanceID}}); err != nil {
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

// Destroy reads the tls-server-name tag back while the instance still
// fully exists, *then* terminates -- AWS's own retention window for
// terminated-instance data is real but undocumented, so reading first
// avoids depending on it at all.
func (d *Driver) Destroy(ctx context.Context, instanceID string) (string, error) {
	out, err := d.client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{InstanceIds: []string{instanceID}})
	if err != nil {
		return "", &infraprovision.DriverError{Msg: fmt.Sprintf("describe instances: %s", err)}
	}
	var tlsServerName string
	for _, reservation := range out.Reservations {
		for _, instance := range reservation.Instances {
			tlsServerName = tagValue(instance.Tags, tlsServerNameTagKey)
		}
	}
	if _, err := d.client.TerminateInstances(ctx, &ec2.TerminateInstancesInput{InstanceIds: []string{instanceID}}); err != nil {
		return "", &infraprovision.DriverError{Msg: fmt.Sprintf("terminate instances: %s", err)}
	}
	return tlsServerName, nil
}
