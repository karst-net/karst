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

func discoverAWS(ctx context.Context, rawSecret string, mode Mode) ([]DiscoveredRegion, error) {
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
		out = append(out, enrich(ProviderAWS, code, code, cloudcatalog.KindRegion, true))

		// Local zones are a per-region resource -- each enabled region needs
		// its own AZ client to list its local zones.
		zones, err := discoverAWSLocalZones(ctx, rawSecret, code, mode)
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

// discoverAWSLocalZones lists a region's Local Zones. A ModeReadOnly
// credential sees only already-opted-in ones, matching ADR-0045 §6's first
// addendum ("listing an account's enabled regions and opted-in local
// zones"); ModeReadWrite additionally sees a zone that exists but is not
// yet opted in (Enabled false), so the console can offer EnableLocalZone
// for it instead of the zone simply never appearing.
func discoverAWSLocalZones(ctx context.Context, rawSecret, region string, mode Mode) ([]DiscoveredRegion, error) {
	cfg, err := awsConfig(ctx, rawSecret, region)
	if err != nil {
		return nil, fmt.Errorf("aws: configure regional client: %w", err)
	}
	client := ec2.NewFromConfig(cfg)
	filters := []ec2types.Filter{{Name: aws.String("zone-type"), Values: []string{"local-zone"}}}
	if mode != ModeReadWrite {
		filters = append(filters, ec2types.Filter{Name: aws.String("opt-in-status"), Values: []string{"opted-in"}})
	}
	// AllAvailabilityZones is required to see a zone this account has not
	// opted into at all -- without it AWS reports only zones it has already
	// opted into, regardless of the opt-in-status filter above.
	azOut, err := client.DescribeAvailabilityZones(ctx, &ec2.DescribeAvailabilityZonesInput{
		AllAvailabilityZones: aws.Bool(true),
		Filters:              filters,
	})
	if err != nil {
		return nil, fmt.Errorf("aws: describe availability zones for %s: %w", region, err)
	}
	return localZonesFromAWS(azOut.AvailabilityZones), nil
}

// localZonesFromAWS is the pure part of discoverAWSLocalZones, kept
// separate so it is unit-testable without a mocked AWS client.
//
// AWS reports one entry per Availability-Zone letter inside a Local Zone
// (ZoneName: "us-east-1-bos-1a", possibly also "...1b"), but the Local
// Zone *group* (GroupName: "us-east-1-bos-1") is the actual location --
// it is what cloudcatalog's codes are keyed by, and the only name
// ModifyAvailabilityZoneGroup (EnableLocalZone) accepts to opt in. Using
// ZoneName instead of GroupName here, as this package previously did, means
// cloudcatalog.Lookup can never match a real AWS response: every Local
// Zone comes back with no coordinates, and no location can be associated
// with it. Dedupe by group; report it enabled if any of its AZ-letter
// entries already is (a group opts in atomically as a whole, so a split
// state is not expected, but OR-ing is cheap insurance against treating
// an actually-enabled group as not).
func localZonesFromAWS(zones []ec2types.AvailabilityZone) []DiscoveredRegion {
	enabledByGroup := map[string]bool{}
	var order []string
	for _, zone := range zones {
		group := aws.ToString(zone.GroupName)
		if group == "" {
			continue
		}
		if _, seen := enabledByGroup[group]; !seen {
			order = append(order, group)
		}
		enabledByGroup[group] = enabledByGroup[group] || zone.OptInStatus == ec2types.AvailabilityZoneOptInStatusOptedIn
	}
	out := make([]DiscoveredRegion, 0, len(order))
	for _, group := range order {
		out = append(out, enrich(ProviderAWS, group, group, cloudcatalog.KindLocalZone, enabledByGroup[group]))
	}
	return out
}

// enableAWSLocalZone is EnableLocalZone's AWS-specific call -- see that
// method's doc comment for the one-way-door warning. parentRegion selects
// which regional EC2 endpoint to call against; AWS has no global endpoint
// for this operation.
func enableAWSLocalZone(ctx context.Context, rawSecret, parentRegion, groupName string) error {
	if parentRegion == "" {
		return fmt.Errorf("aws: enable local zone %s: no parent region given", groupName)
	}
	cfg, err := awsConfig(ctx, rawSecret, parentRegion)
	if err != nil {
		return fmt.Errorf("aws: configure regional client: %w", err)
	}
	client := ec2.NewFromConfig(cfg)
	if _, err := client.ModifyAvailabilityZoneGroup(ctx, &ec2.ModifyAvailabilityZoneGroupInput{
		GroupName:   aws.String(groupName),
		OptInStatus: ec2types.ModifyAvailabilityZoneOptInStatusOptedIn,
	}); err != nil {
		return fmt.Errorf("aws: opt in to local zone group %s: %w", groupName, err)
	}
	return nil
}
