// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package infraconnections

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/ec2"

	"github.com/netbirdio/netbird/management/internals/karst/infraprovision"
	"github.com/netbirdio/netbird/management/internals/karst/infraprovision/awsdriver"
	"github.com/netbirdio/netbird/management/internals/karst/infraprovision/kubernetesdriver"
	"github.com/netbirdio/netbird/management/internals/karst/infraprovision/nomaddriver"
)

// ActuationDriver returns a ready infraprovision.Driver for connection id,
// for relayalloc's reconciliation loop (ADR-0063; ADR-0067) -- replacing
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

func (s *Store) awsActuationDriver(ctx context.Context, record *Account) (infraprovision.Driver, error) {
	defaults := awsdriver.LaunchDefaults{
		AMIID:            record.LaunchAMIID,
		InstanceType:     record.LaunchInstanceType,
		SubnetID:         record.LaunchSubnetID,
		SecurityGroupIDs: record.LaunchSecurityGroupIDs,
	}
	if record.LaunchRegion == "" || defaults.AMIID == "" || defaults.InstanceType == "" || defaults.SubnetID == "" || len(defaults.SecurityGroupIDs) == 0 {
		return nil, fmt.Errorf("%w: configure launch defaults for this connection before allocating a relay against it", ErrInvalid)
	}
	cfg, err := awsConfig(ctx, record.Secret, record.LaunchRegion)
	if err != nil {
		return nil, fmt.Errorf("aws: configure client: %w", err)
	}
	return awsdriver.New(ec2.NewFromConfig(cfg), defaults), nil
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
