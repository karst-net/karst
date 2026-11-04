// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// EC2 actuation for ADR-0063's admin-triggered relay allocation,
// in-process -- a direct Go port of bins/karst-scaler-aws/src/driver.rs
// and bundle.rs's own logic, not a reuse of those files: this package
// cannot depend on a Rust crate, and that crate stays exactly as it was,
// still the actuator bins/karst-scaler's own drive_loop.rs (unrelated
// continuous pool autoscaling, ADR-0045 proper) uses. See ADR-0045's
// 2026-11-04 addendum and ADR-0063's own addendum for why this exists
// in-process at all, rather than as a second external binary.
package relayalloc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/netbirdio/netbird/management/internals/karst/infraconnections"
)

// poolTagKey/tlsServerNameTagKey are driver.rs's POOL_TAG_KEY/
// TLS_SERVER_NAME_TAG_KEY, unchanged: both drivers tag instances
// identically on purpose, so `deploy/aws/scaler/iam-policy.json`'s
// tag-conditioned statements (written against these exact keys) bound
// this actuator the same way they already bound the Rust one, and so an
// operator running both an allocation and a pool against the same
// account sees one consistent tagging convention.
const (
	poolTagKey          = "karst:pool"
	tlsServerNameTagKey = "karst:tls-server-name"
)

// drainTimeout/drainPollInterval match AwsDriver::drain's own values
// (driver.rs) -- stopping a whole EC2 guest OS is slower than a pod
// eviction, the same reasoning that constant's doc comment gives.
const (
	drainTimeout      = 120 * time.Second
	drainPollInterval = 5 * time.Second
)

// tlsServerNameFor is bundle::tls_server_name, unchanged: a stable,
// unique, whitespace-free ASCII label derived from the enrollment token
// by hashing, not embedded verbatim -- the raw token is single-use and
// this label ends up in a registry entry other peers can see. Must stay
// byte-for-byte identical to the Rust derivation (SHA-256, first 6 bytes,
// lowercase hex) since both actuators' instances are looked up by this
// same tag value.
func tlsServerNameFor(allocationID, token string) string {
	digest := sha256.Sum256([]byte(token))
	return fmt.Sprintf("%s-%s.aws.karst.internal", allocationID, hex.EncodeToString(digest[:6]))
}

// encodeEnrollBundleTOML renders the exact TOML shape
// bins/karst-scaler-aws's EnrollBundle (bundle.rs) serializes via
// toml::to_string_pretty -- karst-relay's own `enroll` boot path parses
// this by key, not position, so field order here does not matter, but
// the three key names and basic-string quoting must match exactly.
// address is always omitted: an EC2 instance's own IP is unknown until
// RunInstances returns, exactly as bundle.rs's own crate doc explains --
// karst-relay enroll resolves it itself via IMDS after boot, the same as
// the Rust-actuated pool path.
//
// Hand-rolled rather than a new TOML dependency: every value passed
// through here is one of three narrow, server-controlled shapes (a
// configured URL, a minted token, a label this package itself derives),
// never free-form user input -- the same reasoning the LXD connection
// type's hand-rolled HTTP client gives (ADR-0045's 2026-10-24 addendum)
// for skipping a dependency over a narrow, known shape.
func encodeEnrollBundleTOML(controlAPIBase, token, tlsServerName string) string {
	return fmt.Sprintf("control_api_base = %s\ntoken = %s\ntls_server_name = %s\n",
		strconv.Quote(controlAPIBase), strconv.Quote(token), strconv.Quote(tlsServerName))
}

func tagValue(tags []ec2types.Tag, key string) string {
	for _, t := range tags {
		if aws.ToString(t.Key) == key {
			return aws.ToString(t.Value)
		}
	}
	return ""
}

// describeLiveInstanceByPool looks up the one live instance (if any)
// already tagged with allocationID's own karst:pool value -- driver.rs's
// pool_filters, reused here as provisionStep's own list-before-create
// guard (allocate_loop.rs::provision's identical reasoning): a tick that
// crashes or restarts between a successful launchInstance and the
// Transition call that records it must not launch a second instance for
// the same allocation on retry.
func describeLiveInstanceByPool(ctx context.Context, client *ec2.Client, allocationID string) (instanceID, tlsServerName string, err error) {
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

// describeTLSServerName reads back one instance's own
// tlsServerNameTagKey tag -- driver.rs's describe_tls_server_name/list,
// reused here by grantStep on every tick it runs: nothing in this
// process persists tls_server_name itself (the token it was derived from
// is discarded right after launchInstance returns), so AWS, via this
// tag, is the only durable store for it, surviving a control-server
// restart the same way it already had to survive a `karst-scaler drive`
// restart for the Rust actuator.
func describeTLSServerName(ctx context.Context, client *ec2.Client, instanceID string) (string, error) {
	out, err := client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{InstanceIds: []string{instanceID}})
	if err != nil {
		return "", fmt.Errorf("describe instances: %w", err)
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

// launchInstance is AwsDriver::create for exactly one instance (n is
// always 1 here -- a named allocation is never a batch), called only
// after describeLiveInstanceByPool has already confirmed nothing live
// exists for allocationID. One RunInstances call, MinCount=MaxCount=1,
// tagged karst:pool=allocationID and karst:tls-server-name=<derived
// label> -- defaults' AMI/instance type/subnet/security groups come only
// from the infrastructure connection's own stored launch defaults
// (infraconnections.Store.AWSActuationClient), never from this
// allocation's own request fields, which do not and cannot carry them
// (ADR-0045's 2026-11-04 addendum, compensating control #1).
func launchInstance(ctx context.Context, client *ec2.Client, defaults infraconnections.LaunchDefaults, allocationID, controlAPIBase, token string) (instanceID, tlsServerName string, err error) {
	name := tlsServerNameFor(allocationID, token)
	userData := base64.StdEncoding.EncodeToString([]byte(encodeEnrollBundleTOML(controlAPIBase, token, name)))
	out, err := client.RunInstances(ctx, &ec2.RunInstancesInput{
		ImageId:          aws.String(defaults.AMIID),
		InstanceType:     ec2types.InstanceType(defaults.InstanceType),
		MinCount:         aws.Int32(1),
		MaxCount:         aws.Int32(1),
		UserData:         aws.String(userData),
		SubnetId:         aws.String(defaults.SubnetID),
		SecurityGroupIds: defaults.SecurityGroupIDs,
		TagSpecifications: []ec2types.TagSpecification{{
			ResourceType: ec2types.ResourceTypeInstance,
			Tags: []ec2types.Tag{
				{Key: aws.String(poolTagKey), Value: aws.String(allocationID)},
				{Key: aws.String(tlsServerNameTagKey), Value: aws.String(name)},
			},
		}},
	})
	if err != nil {
		return "", "", fmt.Errorf("run instances: %w", err)
	}
	if len(out.Instances) == 0 || out.Instances[0].InstanceId == nil {
		return "", "", fmt.Errorf("allocation %s: RunInstances returned no instance", allocationID)
	}
	return aws.ToString(out.Instances[0].InstanceId), name, nil
}

// drainInstance is AwsDriver::drain, unchanged in behavior: StopInstances
// then poll until stopped/terminated or drainTimeout elapses. Not
// independently verified against a real EC2 instance in this
// environment, same caveat driver.rs's own doc comment already carries.
func drainInstance(ctx context.Context, client *ec2.Client, instanceID string) error {
	if _, err := client.StopInstances(ctx, &ec2.StopInstancesInput{InstanceIds: []string{instanceID}}); err != nil {
		return fmt.Errorf("stop instances: %w", err)
	}
	deadline := time.Now().Add(drainTimeout)
	for {
		state, err := describeInstanceState(ctx, client, instanceID)
		if err != nil {
			return err
		}
		if state == ec2types.InstanceStateNameStopped || state == ec2types.InstanceStateNameTerminated {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("instance %s did not stop within %s", instanceID, drainTimeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(drainPollInterval):
		}
	}
}

func describeInstanceState(ctx context.Context, client *ec2.Client, instanceID string) (ec2types.InstanceStateName, error) {
	out, err := client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{InstanceIds: []string{instanceID}})
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

// destroyInstance is AwsDriver::destroy: read the tls-server-name tag
// back while the instance still fully exists, *then* terminate -- AWS's
// own retention window for terminated-instance data is real but
// undocumented, so reading first avoids depending on it at all, the same
// ordering driver.rs's own doc comment gives for issue #329. An instance
// with no such tag (none should exist -- launchInstance always sets it,
// unlike a pre-#329 Rust-actuated one) returns an empty tlsServerName
// rather than an error; the caller treats that as "nothing to deenroll."
func destroyInstance(ctx context.Context, client *ec2.Client, instanceID string) (tlsServerName string, err error) {
	out, err := client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{InstanceIds: []string{instanceID}})
	if err != nil {
		return "", fmt.Errorf("describe instances: %w", err)
	}
	for _, reservation := range out.Reservations {
		for _, instance := range reservation.Instances {
			tlsServerName = tagValue(instance.Tags, tlsServerNameTagKey)
		}
	}
	if _, err := client.TerminateInstances(ctx, &ec2.TerminateInstancesInput{InstanceIds: []string{instanceID}}); err != nil {
		return "", fmt.Errorf("terminate instances: %w", err)
	}
	return tlsServerName, nil
}
