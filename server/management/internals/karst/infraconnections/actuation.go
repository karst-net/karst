// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package infraconnections

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	"github.com/aws/aws-sdk-go-v2/service/ecs"

	"github.com/netbirdio/netbird/management/internals/karst/infraprovision"
	"github.com/netbirdio/netbird/management/internals/karst/infraprovision/cloudformationdriver"
	"github.com/netbirdio/netbird/management/internals/karst/infraprovision/kubernetesdriver"
	"github.com/netbirdio/netbird/management/internals/karst/infraprovision/nomaddriver"
)

// ActuationDriver returns a ready infraprovision.Driver for connection id,
// for estavellealloc's reconciliation loop (ADR-0063; ADR-0067) -- replacing
// the pre-ADR-0067 AWS-only AWSActuationClient. Built fresh on every call,
// deliberately never cached: a rotated or edited secret, or changed launch
// defaults, takes effect on the very next call, matching every other
// actuating caller in this package.
//
// Returns ErrUnsupportedType for any connection whose Type has no driver
// registered (see Type.SupportsActuation) -- Azure, GCP, and LXD today.
func (s *Store) ActuationDriver(ctx context.Context, id string) (infraprovision.Driver, error) {
	record, err := s.get(ctx, id)
	if err != nil {
		return nil, err
	}
	if record.Mode != ModeReadWrite {
		return nil, fmt.Errorf("%w: connection is not read-write", ErrInvalid)
	}
	if !record.Type.SupportsActuation() {
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedType, record.Type)
	}
	switch record.Type {
	case TypeAWS:
		return s.awsActuationDriver(ctx, record)
	case TypeNomad:
		return s.nomadActuationDriver(record)
	case TypeKubernetes:
		return s.kubernetesActuationDriver(record)
	default:
		// Unreachable: SupportsActuation's case list and this switch's
		// case list must stay in lockstep -- a mismatch here is a bug in
		// this package, not a user-facing condition, so it fails loudly
		// rather than falling through to ErrUnsupportedType a second time.
		return nil, fmt.Errorf("infraconnections: actuation driver: type %q reported supported but has no case", record.Type)
	}
}

// awsActuationDriver builds cloudformationdriver (ADR-0067's CloudFormation
// actuation path, deploy/aws/scaler/estavelle-instance.yaml) -- the only AWS
// actuation mechanism; there is no per-connection choice to make, so
// nothing here reads anything off record beyond the launch defaults every
// AWS connection already needs.
func (s *Store) awsActuationDriver(ctx context.Context, record *Account) (infraprovision.Driver, error) {
	if record.LaunchRegion == "" || record.LaunchClusterARN == "" || record.LaunchExecutionRoleARN == "" ||
		record.LaunchCPU == "" || record.LaunchMemory == "" || record.LaunchLogGroup == "" ||
		record.LaunchSubnetID == "" || len(record.LaunchSecurityGroupIDs) == 0 {
		return nil, fmt.Errorf("%w: configure launch defaults for this connection before allocating a relay against it", ErrInvalid)
	}
	// AWS Fargate is not supported in Local Zones at all, so ec2 names a
	// real capacity provider to use instead -- a connection with
	// ComputeType=ec2 and no provider name would otherwise fail much
	// later, as an opaque CloudFormation parameter error, rather than
	// here with a clear reason.
	if record.LaunchComputeType == "ec2" && record.LaunchEc2CapacityProvider == "" {
		return nil, fmt.Errorf("%w: compute_type is ec2 but ec2_capacity_provider is not set", ErrInvalid)
	}
	cfg, err := awsConfig(ctx, record.Secret, record.LaunchRegion)
	if err != nil {
		return nil, fmt.Errorf("aws: configure client: %w", err)
	}
	defaults := cloudformationdriver.LaunchDefaults{
		ClusterARN:               record.LaunchClusterARN,
		ExecutionRoleARN:         record.LaunchExecutionRoleARN,
		CPU:                      record.LaunchCPU,
		Memory:                   record.LaunchMemory,
		LogGroup:                 record.LaunchLogGroup,
		SubnetID:                 record.LaunchSubnetID,
		SecurityGroupIDs:         record.LaunchSecurityGroupIDs,
		PullCredentialsSecretARN: record.LaunchPullCredentialsSecretARN,
		ComputeType:              record.LaunchComputeType,
		Ec2CapacityProviderName:  record.LaunchEc2CapacityProvider,
	}
	return cloudformationdriver.New(cloudformation.NewFromConfig(cfg), ecs.NewFromConfig(cfg), defaults), nil
}

func (s *Store) nomadActuationDriver(record *Account) (infraprovision.Driver, error) {
	if record.LaunchNomadJobID == "" {
		return nil, fmt.Errorf("%w: configure launch defaults for this connection before allocating a relay against it", ErrInvalid)
	}
	client, _, err := nomadClient(record.Secret)
	if err != nil {
		return nil, fmt.Errorf("nomad: configure client: %w", err)
	}
	return nomaddriver.New(client, record.LaunchNomadJobID, record.LaunchNomadDatacenter), nil
}

func (s *Store) kubernetesActuationDriver(record *Account) (infraprovision.Driver, error) {
	defaults := kubernetesdriver.LaunchDefaults{
		Image: record.LaunchKubernetesImage, CPU: record.LaunchKubernetesCPU,
		Memory: record.LaunchKubernetesMemory, ServiceAccount: record.LaunchKubernetesServiceAccount,
	}
	if record.LaunchKubernetesNamespace == "" || defaults.Image == "" {
		return nil, fmt.Errorf("%w: configure launch defaults for this connection before allocating a relay against it", ErrInvalid)
	}
	clientset, err := kubernetesClient(record.Secret)
	if err != nil {
		return nil, fmt.Errorf("kubernetes: configure client: %w", err)
	}
	return kubernetesdriver.New(clientset, record.LaunchKubernetesNamespace, defaults), nil
}
