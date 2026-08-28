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
