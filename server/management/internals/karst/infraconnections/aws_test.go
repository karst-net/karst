// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package infraconnections

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// Regression coverage for the bug this fixes: AWS reports one entry per
// Availability-Zone letter inside a Local Zone (ZoneName), but
// cloudcatalog's codes -- and EnableLocalZone's GroupName argument -- are
// keyed by the zone *group*, which has no trailing letter. Using ZoneName
// meant cloudcatalog.Lookup could never match a real AWS response: every
// discovered local zone came back with no coordinates, so none could be
// associated with a location.
func TestLocalZonesFromAWSUsesGroupNameNotZoneName(t *testing.T) {
	zones := []ec2types.AvailabilityZone{
		{ZoneName: aws.String("us-east-1-bos-1a"), GroupName: aws.String("us-east-1-bos-1"), OptInStatus: ec2types.AvailabilityZoneOptInStatusOptedIn},
	}
	got := localZonesFromAWS(zones)
	if len(got) != 1 {
		t.Fatalf("got %d regions, want exactly 1", len(got))
	}
	if got[0].Code != "us-east-1-bos-1" {
		t.Fatalf("got code %q, want the group name us-east-1-bos-1, not the lettered zone name", got[0].Code)
	}
	if got[0].Lat == nil {
		t.Fatal("want coordinates: the group name is cloudcatalog's actual key")
	}
}

func TestLocalZonesFromAWSDedupesByGroup(t *testing.T) {
	zones := []ec2types.AvailabilityZone{
		{ZoneName: aws.String("us-east-1-bos-1a"), GroupName: aws.String("us-east-1-bos-1"), OptInStatus: ec2types.AvailabilityZoneOptInStatusOptedIn},
		{ZoneName: aws.String("us-east-1-bos-1b"), GroupName: aws.String("us-east-1-bos-1"), OptInStatus: ec2types.AvailabilityZoneOptInStatusOptedIn},
	}
	got := localZonesFromAWS(zones)
	if len(got) != 1 {
		t.Fatalf("got %d regions, want the two AZ-letter entries collapsed to one group", len(got))
	}
}

func TestLocalZonesFromAWSReportsNotOptedIn(t *testing.T) {
	zones := []ec2types.AvailabilityZone{
		{ZoneName: aws.String("us-west-2-lax-1a"), GroupName: aws.String("us-west-2-lax-1"), OptInStatus: ec2types.AvailabilityZoneOptInStatusNotOptedIn},
	}
	got := localZonesFromAWS(zones)
	if len(got) != 1 {
		t.Fatalf("got %d regions, want 1", len(got))
	}
	if got[0].Enabled {
		t.Fatal("want Enabled false for a zone group AWS reports as not-opted-in")
	}
}

func TestLocalZonesFromAWSOrEnabledAcrossGroupLetters(t *testing.T) {
	zones := []ec2types.AvailabilityZone{
		{ZoneName: aws.String("us-east-1-bos-1a"), GroupName: aws.String("us-east-1-bos-1"), OptInStatus: ec2types.AvailabilityZoneOptInStatusNotOptedIn},
		{ZoneName: aws.String("us-east-1-bos-1b"), GroupName: aws.String("us-east-1-bos-1"), OptInStatus: ec2types.AvailabilityZoneOptInStatusOptedIn},
	}
	got := localZonesFromAWS(zones)
	if len(got) != 1 || !got[0].Enabled {
		t.Fatalf("got %+v, want the group reported enabled since at least one letter is opted in", got)
	}
}

func TestEnableLocalZoneRequiresReadWrite(t *testing.T) {
	s := newTestStore(t, newTestEncryptor(t))
	ctx := WithAccount(context.Background(), "acct-a")
	created, err := s.Create(ctx, awsRequest(t, ModeReadOnly))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := s.EnableLocalZone(ctx, created.ID, "us-east-1-bos-1", "us-east-1"); err == nil {
		t.Fatal("want an error enabling a local zone with a read-only credential")
	}
}

func TestEnableLocalZoneRequiresAWS(t *testing.T) {
	s := newTestStore(t, newTestEncryptor(t))
	ctx := WithAccount(context.Background(), "acct-a")
	secret, err := json.Marshal(gcpSecret{ProjectID: "proj", ServiceAccountKey: json.RawMessage(`{"type":"service_account"}`)})
	if err != nil {
		t.Fatalf("marshal secret: %v", err)
	}
	created, err := s.Create(ctx, CreateRequest{Type: TypeGCP, Mode: ModeReadWrite, Secret: secret})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := s.EnableLocalZone(ctx, created.ID, "us-east-1-bos-1", "us-east-1"); err == nil {
		t.Fatal("want an error enabling a local zone on a non-AWS credential")
	}
}

func TestEnableLocalZoneIsAccountScoped(t *testing.T) {
	s := newTestStore(t, newTestEncryptor(t))
	created, err := s.Create(WithAccount(context.Background(), "acct-a"), awsRequest(t, ModeReadWrite))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := s.EnableLocalZone(WithAccount(context.Background(), "acct-b"), created.ID, "us-east-1-bos-1", "us-east-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound for another account's credential", err)
	}
}
