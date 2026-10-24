// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package control

import (
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"

	wire "github.com/netbirdio/netbird/shared/management/proto"
)

func TestNewGatewayReportDecodesWithLegacyControlSchema(t *testing.T) {
	// Recreate the actual six-field #422 schema rather than using the new
	// generated type to stand in for an older control reader.
	message := protodesc.ToDescriptorProto((&wire.KarstRouteObservation{}).ProtoReflect().Descriptor())
	message.Field = message.Field[:6]
	file, err := protodesc.NewFile(&descriptorpb.FileDescriptorProto{
		Name: proto.String("legacy_gateway.proto"), Syntax: proto.String("proto3"), MessageType: []*descriptorpb.DescriptorProto{message},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, active := range []bool{false, true} {
		payload, err := proto.Marshal(&wire.KarstRouteObservation{RouteId: "office", Bytes: 42, ForwardingActive: active, ForwardingReadinessReported: true})
		if err != nil {
			t.Fatal(err)
		}
		old := dynamicpb.NewMessage(file.Messages().Get(0))
		if err := proto.Unmarshal(payload, old); err != nil {
			t.Fatal(err)
		}
		if old.Get(old.Descriptor().Fields().ByNumber(1)).String() != "office" || old.Get(old.Descriptor().Fields().ByNumber(2)).Uint() != 42 || old.Get(old.Descriptor().Fields().ByNumber(6)).Bool() != active {
			t.Fatalf("legacy control lost known fields: %v", old)
		}
	}
}
