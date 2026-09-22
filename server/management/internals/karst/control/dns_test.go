// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package control

import (
	"context"
	"net/netip"
	"testing"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/proto"
)

type dnsAccounts struct{ account *types.Account }

func (f dnsAccounts) GetAccount(context.Context, string) (*types.Account, error) {
	return f.account, nil
}

func TestDNSProjectionOmitsDisabledGroups(t *testing.T) {
	resolver := nbdns.NameServer{IP: netip.MustParseAddr("100.64.0.53"), Port: 53}
	account := &types.Account{
		Groups: map[string]*types.Group{"members": {ID: "members", Peers: []string{"peer-id"}}},
		NameServerGroups: map[string]*nbdns.NameServerGroup{
			"enabled": {
				ID: "enabled", Enabled: true, Primary: true, Groups: []string{"members"},
				NameServers: []nbdns.NameServer{resolver},
			},
			"disabled": {
				ID: "disabled", Enabled: false, Primary: true, Groups: []string{"members"},
				NameServers: []nbdns.NameServer{{IP: netip.MustParseAddr("203.0.113.53"), Port: 53}},
			},
		},
	}
	h := NetmapHandler{DNSZone: "aquifer.karst", DNS: dnsAccounts{account}}
	config, err := h.dnsConfig(context.Background(), "account", "peer-id")
	if err != nil {
		t.Fatalf("project DNS: %v", err)
	}
	if got, want := config.GetNameservers(), []string{"100.64.0.53:53"}; len(got) != 1 || got[0] != want[0] {
		t.Fatalf("enabled resolver projection = %v, want %v", got, want)
	}
	if config.GetMagicDns() != true || config.GetZone() != "aquifer.karst" {
		t.Fatalf("mesh DNS config = %#v", config)
	}
	before := NetmapVersion(&proto.KarstNetmapResponse{DnsConfig: config})
	account.NameServerGroups["disabled"].Enabled = true
	changed, err := h.dnsConfig(context.Background(), "account", "peer-id")
	if err != nil {
		t.Fatalf("project enabled DNS: %v", err)
	}
	if NetmapVersion(&proto.KarstNetmapResponse{DnsConfig: changed}) == before {
		t.Fatal("enabling a nameserver group did not move netmap version")
	}
}

// A DoT-typed nameserver must reach the wire only as a structured
// KarstDNSUpstream, never as a plain "ip:port" string — ADR-0034. Projecting
// it into Nameservers/Resolvers too would let any reader that only
// understands the string list query it in cleartext, silently defeating the
// point of choosing DoT for it.
func TestDNSProjectionPutsDoTOnlyInUpstreams(t *testing.T) {
	dot := nbdns.NameServer{
		IP: netip.MustParseAddr("1.1.1.1"), NSType: nbdns.DoTNameServerType, Port: 853,
		TLSServerName: "cloudflare-dns.com", SPKIPin: []byte{0xab, 0xcd},
	}
	account := &types.Account{
		Groups: map[string]*types.Group{"members": {ID: "members", Peers: []string{"peer-id"}}},
		NameServerGroups: map[string]*nbdns.NameServerGroup{
			"primary-dot": {
				ID: "primary-dot", Enabled: true, Primary: true, Groups: []string{"members"},
				NameServers: []nbdns.NameServer{dot},
			},
		},
	}
	h := NetmapHandler{DNSZone: "aquifer.karst", DNS: dnsAccounts{account}}
	config, err := h.dnsConfig(context.Background(), "account", "peer-id")
	if err != nil {
		t.Fatalf("project DNS: %v", err)
	}
	if len(config.GetNameservers()) != 0 {
		t.Fatalf("DoT nameserver leaked into the plain string list: %v", config.GetNameservers())
	}
	upstreams := config.GetUpstreams()
	if len(upstreams) != 1 {
		t.Fatalf("got %d upstreams, want 1", len(upstreams))
	}
	if upstreams[0].GetAddress() != "1.1.1.1:853" ||
		upstreams[0].GetTransport() != proto.KarstDNSTransport_KARST_DNS_TRANSPORT_DOT ||
		upstreams[0].GetTlsServerName() != "cloudflare-dns.com" ||
		string(upstreams[0].GetSpkiPin()) != string([]byte{0xab, 0xcd}) {
		t.Fatalf("unexpected upstream projection: %#v", upstreams[0])
	}
}

// The non-primary/route path mirrors the primary one: a DoT entry's route
// carries Upstreams, never Resolvers.
func TestDNSProjectionPutsRouteDoTOnlyInUpstreams(t *testing.T) {
	dot := nbdns.NameServer{
		IP: netip.MustParseAddr("100.64.0.53"), NSType: nbdns.DoTNameServerType, Port: 853,
		TLSServerName: "resolver.internal",
	}
	account := &types.Account{
		Groups: map[string]*types.Group{"members": {ID: "members", Peers: []string{"peer-id"}}},
		NameServerGroups: map[string]*nbdns.NameServerGroup{
			"route-dot": {
				ID: "route-dot", Enabled: true, Primary: false, Groups: []string{"members"},
				Domains:     []string{"internal.example"},
				NameServers: []nbdns.NameServer{dot},
			},
		},
	}
	h := NetmapHandler{DNSZone: "aquifer.karst", DNS: dnsAccounts{account}}
	config, err := h.dnsConfig(context.Background(), "account", "peer-id")
	if err != nil {
		t.Fatalf("project DNS: %v", err)
	}
	routes := config.GetRoutes()
	if len(routes) != 1 {
		t.Fatalf("got %d routes, want 1", len(routes))
	}
	if len(routes[0].GetResolvers()) != 0 {
		t.Fatalf("DoT nameserver leaked into the route's plain resolver list: %v", routes[0].GetResolvers())
	}
	if len(routes[0].GetUpstreams()) != 1 || routes[0].GetUpstreams()[0].GetAddress() != "100.64.0.53:853" {
		t.Fatalf("unexpected route upstreams: %#v", routes[0].GetUpstreams())
	}
}

// A group with one UDP and one DoT nameserver produces both a plain string
// resolver and a structured upstream, each carrying only its own entry.
func TestDNSProjectionMixesUDPAndDoTInOneGroup(t *testing.T) {
	udp := nbdns.NameServer{IP: netip.MustParseAddr("9.9.9.9"), NSType: nbdns.UDPNameServerType, Port: 53}
	dot := nbdns.NameServer{
		IP: netip.MustParseAddr("1.1.1.1"), NSType: nbdns.DoTNameServerType, Port: 853,
		TLSServerName: "cloudflare-dns.com",
	}
	account := &types.Account{
		Groups: map[string]*types.Group{"members": {ID: "members", Peers: []string{"peer-id"}}},
		NameServerGroups: map[string]*nbdns.NameServerGroup{
			"mixed": {
				ID: "mixed", Enabled: true, Primary: true, Groups: []string{"members"},
				NameServers: []nbdns.NameServer{udp, dot},
			},
		},
	}
	h := NetmapHandler{DNSZone: "aquifer.karst", DNS: dnsAccounts{account}}
	config, err := h.dnsConfig(context.Background(), "account", "peer-id")
	if err != nil {
		t.Fatalf("project DNS: %v", err)
	}
	if got, want := config.GetNameservers(), []string{"9.9.9.9:53"}; len(got) != 1 || got[0] != want[0] {
		t.Fatalf("plain resolver projection = %v, want %v", got, want)
	}
	if len(config.GetUpstreams()) != 1 || config.GetUpstreams()[0].GetAddress() != "1.1.1.1:853" {
		t.Fatalf("unexpected upstreams: %#v", config.GetUpstreams())
	}
}

func TestDNSProjectionUsesAccountNetworkZoneByDefault(t *testing.T) {
	account := &types.Account{
		Network:          &types.Network{Dns: "aquifer.karst"},
		Groups:           map[string]*types.Group{},
		NameServerGroups: map[string]*nbdns.NameServerGroup{},
	}
	config, err := (&NetmapHandler{DNS: dnsAccounts{account}}).dnsConfig(context.Background(), "account", "peer-id")
	if err != nil {
		t.Fatalf("project DNS: %v", err)
	}
	if config.GetZone() != "aquifer.karst" || !config.GetMagicDns() {
		t.Fatalf("network DNS zone projection = %#v", config)
	}
}
