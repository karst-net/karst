package dns

import (
	"net/netip"
	"testing"
)

func TestDoTNameServerTypeRoundTripsThroughItsString(t *testing.T) {
	if got := DoTNameServerType.String(); got != DoTNameServerTypeString {
		t.Fatalf("DoTNameServerType.String() = %q, want %q", got, DoTNameServerTypeString)
	}
	if got := ToNameServerType(DoTNameServerTypeString); got != DoTNameServerType {
		t.Fatalf("ToNameServerType(%q) = %v, want DoTNameServerType", DoTNameServerTypeString, got)
	}
}

func TestNameServerCopyDeepCopiesTheSPKIPin(t *testing.T) {
	original := &NameServer{
		IP:            netip.MustParseAddr("1.1.1.1"),
		NSType:        DoTNameServerType,
		Port:          853,
		TLSServerName: "cloudflare-dns.com",
		SPKIPin:       []byte{1, 2, 3, 4},
	}
	copied := original.Copy()
	if !original.IsEqual(copied) {
		t.Fatalf("copy is not equal to the original: %#v vs %#v", original, copied)
	}
	copied.SPKIPin[0] = 0xff
	if original.SPKIPin[0] == 0xff {
		t.Fatal("mutating the copy's SPKIPin mutated the original's — Copy() aliased the slice")
	}
}

func TestNameServerIsEqualComparesTheNewFields(t *testing.T) {
	base := NameServer{
		IP:            netip.MustParseAddr("1.1.1.1"),
		NSType:        DoTNameServerType,
		Port:          853,
		TLSServerName: "cloudflare-dns.com",
		SPKIPin:       []byte{1, 2, 3},
	}
	differentName := base
	differentName.TLSServerName = "dns.quad9.net"
	if base.IsEqual(&differentName) {
		t.Fatal("entries with different TLS server names compared equal")
	}

	differentPin := base
	differentPin.SPKIPin = []byte{9, 9, 9}
	if base.IsEqual(&differentPin) {
		t.Fatal("entries with different SPKI pins compared equal")
	}

	same := base
	same.SPKIPin = append([]byte(nil), base.SPKIPin...)
	if !base.IsEqual(&same) {
		t.Fatal("otherwise-identical entries compared unequal")
	}
}

func TestNameServerGroupCopyDeepCopiesEachNameServer(t *testing.T) {
	group := &NameServerGroup{
		NameServers: []NameServer{{
			IP:      netip.MustParseAddr("1.1.1.1"),
			NSType:  DoTNameServerType,
			Port:    853,
			SPKIPin: []byte{1, 2, 3},
		}},
	}
	copied := group.Copy()
	copied.NameServers[0].SPKIPin[0] = 0xff
	if group.NameServers[0].SPKIPin[0] == 0xff {
		t.Fatal("NameServerGroup.Copy() aliased a NameServer's SPKIPin")
	}
}
