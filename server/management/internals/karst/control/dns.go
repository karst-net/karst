// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package control

import (
	"context"
	"fmt"
	"sort"

	"github.com/netbirdio/netbird/shared/management/proto"
)

// dnsConfig projects the management DNS model into the authenticated Karst
// resolver contract. A group reaches a peer only when it is enabled and the
// peer belongs to one of its target groups; disabled groups are deliberately
// filtered here, before both delivery and version hashing.
func (h *NetmapHandler) dnsConfig(ctx context.Context, accountID, peerID string) (*proto.KarstDNSConfig, error) {
	config := &proto.KarstDNSConfig{Zone: h.DNSZone, MagicDns: h.DNSZone != ""}
	if h.DNS == nil {
		return config, nil
	}

	account, err := h.DNS.GetAccount(ctx, accountID)
	if err != nil {
		return nil, err
	}
	// Existing accounts already carry the authoritative DNS suffix on their
	// overlay network. DNSZone remains an explicit Karst override for tests and
	// deployments that do not use the fork's account-network field, but a blank
	// override must not silently turn MagicDNS off for every ordinary account.
	if config.Zone == "" && account.Network != nil {
		config.Zone = account.Network.Dns
		config.MagicDns = config.Zone != ""
	}
	peerGroups := account.GetPeerGroups(peerID)
	groupIDs := make([]string, 0, len(account.NameServerGroups))
	for id := range account.NameServerGroups {
		groupIDs = append(groupIDs, id)
	}
	sort.Strings(groupIDs)

	for _, id := range groupIDs {
		group := account.NameServerGroups[id]
		if group == nil || !group.Enabled || !appliesToPeer(group.Groups, peerGroups) {
			continue
		}
		resolvers := make([]string, 0, len(group.NameServers))
		for _, nameserver := range group.NameServers {
			if !nameserver.IP.IsValid() || nameserver.Port <= 0 || nameserver.Port > 65535 {
				return nil, fmt.Errorf("nameserver group %q has invalid resolver", id)
			}
			resolvers = append(resolvers, nameserver.AddrPort().String())
		}
		if len(resolvers) == 0 {
			continue
		}
		if group.Primary {
			config.Nameservers = append(config.Nameservers, resolvers...)
		} else {
			for _, domain := range group.Domains {
				config.Routes = append(config.Routes, &proto.KarstDNSRoute{
					MatchDomain: domain,
					Resolvers:   append([]string(nil), resolvers...),
				})
			}
		}
		if group.SearchDomainsEnabled {
			config.SearchDomains = append(config.SearchDomains, group.Domains...)
		}
	}
	return config, nil
}

func appliesToPeer(groups []string, peerGroups map[string]struct{}) bool {
	for _, group := range groups {
		if _, ok := peerGroups[group]; ok {
			return true
		}
	}
	return false
}
