// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package cloudaccounts

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/netbirdio/netbird/management/internals/karst/cloudcatalog"
)

// awsSecret is the admin-entered credential shape for Provider "aws".
// SessionToken is optional, for a temporary/STS-issued credential.
type awsSecret struct {
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	SessionToken    string `json:"session_token,omitempty"`
}

func validateAWSSecret(raw []byte) error {
	var s awsSecret
	if err := json.Unmarshal(raw, &s); err != nil {
		return fmt.Errorf("aws secret: %w", err)
	}
	if s.AccessKeyID == "" || s.SecretAccessKey == "" {
		return fmt.Errorf("aws secret: access_key_id and secret_access_key are required")
	}
	return nil
}

// bootstrapRegion is only used to resolve the EC2 endpoint for the first
// DescribeRegions call -- it does not scope which regions are returned
// (DescribeRegions with no filter reports every region enabled for the
// account, by AWS's own default).
const awsBootstrapRegion = "us-east-1"

func awsConfig(ctx context.Context, rawSecret, region string) (aws.Config, error) {
	var s awsSecret
	if err := json.Unmarshal([]byte(rawSecret), &s); err != nil {
		return aws.Config{}, fmt.Errorf("aws secret: %w", err)
	}
	return config.LoadDefaultConfig(ctx,
		config.WithRegion(region),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(s.AccessKeyID, s.SecretAccessKey, s.SessionToken)),
	)
}

func discoverAWS(ctx context.Context, rawSecret string) ([]DiscoveredRegion, error) {
	cfg, err := awsConfig(ctx, rawSecret, awsBootstrapRegion)
	if err != nil {
		return nil, fmt.Errorf("aws: configure client: %w", err)
	}
	client := ec2.NewFromConfig(cfg)
	regionsOut, err := client.DescribeRegions(ctx, &ec2.DescribeRegionsInput{})
	if err != nil {
		return nil, fmt.Errorf("aws: describe regions: %w", err)
	}

	var out []DiscoveredRegion
	for _, region := range regionsOut.Regions {
		code := aws.ToString(region.RegionName)
		if code == "" {
			continue
		}
		out = append(out, enrich(ProviderAWS, code, code, cloudcatalog.KindRegion))

		// Local zones are a per-region resource -- each enabled region needs
		// its own AZ client to list its opted-in local zones.
		zones, err := discoverAWSLocalZones(ctx, rawSecret, code)
		if err != nil {
			// A single region's local-zone lookup failing (e.g. the
			// credential lacks ec2:DescribeAvailabilityZones in that region)
			// should not blank out every other region's result.
			continue
		}
		out = append(out, zones...)
	}
	return out, nil
}

func discoverAWSLocalZones(ctx context.Context, rawSecret, region string) ([]DiscoveredRegion, error) {
	cfg, err := awsConfig(ctx, rawSecret, region)
	if err != nil {
		return nil, fmt.Errorf("aws: configure regional client: %w", err)
	}
	client := ec2.NewFromConfig(cfg)
	azOut, err := client.DescribeAvailabilityZones(ctx, &ec2.DescribeAvailabilityZonesInput{
		AllAvailabilityZones: aws.Bool(true),
		Filters: []ec2types.Filter{
			{Name: aws.String("zone-type"), Values: []string{"local-zone"}},
			{Name: aws.String("opt-in-status"), Values: []string{"opted-in"}},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("aws: describe availability zones for %s: %w", region, err)
	}
	var out []DiscoveredRegion
	for _, zone := range azOut.AvailabilityZones {
		code := aws.ToString(zone.ZoneName)
		if code == "" {
			continue
		}
		out = append(out, enrich(ProviderAWS, code, code, cloudcatalog.KindLocalZone))
	}
	return out, nil
}
