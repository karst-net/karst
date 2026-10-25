// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"github.com/netbirdio/netbird/management/internals/karst/policy"
	"github.com/netbirdio/netbird/management/server/types"
)

type registryAccountReader interface {
	GetAccount(context.Context, string) (*types.Account, error)
}

func (h *handler) registryAccount(ctx context.Context, accountID string) (*types.Account, error) {
	source, ok := h.accounts.(registryAccountReader)
	if !ok {
		return nil, fmt.Errorf("account group source is unavailable")
	}
	account, err := source.GetAccount(ctx, accountID)
	if err != nil {
		return nil, err
	}
	if account == nil || account.Id != accountID {
		return nil, fmt.Errorf("account group source returned the wrong account")
	}
	return account, nil
}

func (h *handler) validateRegistryGrants(ctx context.Context, accountID, document string) error {
	doc, err := policy.Parse([]byte(document))
	if err != nil {
		return err
	}
	if h.policy != nil {
		current, readErr := h.policy.Current(ctx)
		if readErr == nil {
			var old policy.Document
			if err := json.Unmarshal([]byte(current.Document), &old); err != nil {
				return err
			}
			managed := func(grants []policy.Grant) map[string]policy.Grant {
				out := map[string]policy.Grant{}
				for _, g := range grants {
					if strings.HasPrefix(g.ID, "relay-exit-") {
						out[g.ID] = g
					}
				}
				return out
			}
			if !reflect.DeepEqual(managed(old.Grants), managed(doc.Grants)) {
				return fmt.Errorf("edit resource-managed internet access through its Relay service")
			}
		} else if readErr != policy.ErrNoVersion {
			return readErr
		} else {
			for _, g := range doc.Grants {
				if strings.HasPrefix(g.ID, "relay-exit-") {
					return fmt.Errorf("resource-managed grant IDs are reserved")
				}
			}
		}
	}
	if !doc.UsesRegistryGroups() {
		return nil
	}
	account, err := h.registryAccount(ctx, accountID)
	if err != nil {
		return err
	}
	for _, id := range doc.RegistryGroupIDs() {
		if account.Groups[id] == nil {
			return fmt.Errorf("a selected group is unavailable in this account; reload groups")
		}
	}
	handles := map[string]bool{}
	for _, p := range account.Peers {
		handles[p.Key] = true
	}
	for _, g := range doc.Grants {
		for _, id := range g.TargetNodes {
			if !handles[id] {
				return fmt.Errorf("a selected machine is unavailable in this account")
			}
		}
	}
	return nil
}

func (h *handler) addRegistryMembership(ctx context.Context, accountID string, nodes []policy.Node) error {
	account, err := h.registryAccount(ctx, accountID)
	if err != nil {
		return err
	}
	byHandle := map[string][]string{}
	inactive := map[string]bool{}
	for _, p := range account.Peers {
		if p.UserID != "" {
			owner := account.Users[p.UserID]
			inactive[p.Key] = owner == nil || owner.Blocked || owner.PendingApproval
		}
		for id := range account.GetPeerGroups(p.ID) {
			byHandle[p.Key] = append(byHandle[p.Key], id)
		}
	}
	for i := range nodes {
		nodes[i].GroupIDs = byHandle[nodes[i].Handle]
		nodes[i].Inactive = inactive[nodes[i].Handle]
	}
	return nil
}
