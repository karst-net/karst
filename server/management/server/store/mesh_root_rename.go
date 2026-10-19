// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/netbirdio/netbird/management/internals/modules/meshdomain"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

// RootRename previews or commits a root rename under the account/root lock.
// Authorization is repeated inside the transaction using its own store. Naming
// writers acquire this same lock before reading the active suffix or placement.
func (s *SqlStore) RootRename(ctx context.Context, accountID, suffix, expected string, commit bool, authorize func(Store) error) (*meshdomain.RenamePreview, error) {
	canonical, err := meshdomain.CanonicalSuffix(suffix)
	if err != nil {
		return nil, status.Errorf(status.InvalidArgument, "%s", err)
	}
	var preview *meshdomain.RenamePreview
	err = s.ExecuteInTransaction(ctx, func(transaction Store) error {
		root, err := transaction.GetAccountRootDomain(ctx, LockingStrengthUpdate, accountID)
		if err != nil {
			return err
		}
		if root == nil {
			return status.Errorf(status.PreconditionFailed, "account root must be migrated before rename")
		}
		if err := authorize(transaction); err != nil {
			return err
		}
		if canonical == root.DNSSuffix && !commit {
			return status.Errorf(status.InvalidArgument, "the requested suffix is already active")
		}
		groups, err := transaction.GetAccountNameServerGroups(ctx, LockingStrengthNone, accountID)
		if err != nil {
			return err
		}
		for _, group := range groups {
			if !group.Enabled || group.Primary {
				continue
			}
			for _, domain := range group.Domains {
				match := strings.ToLower(strings.TrimSuffix(domain, "."))
				if canonical == match || strings.HasSuffix(canonical, "."+match) {
					return status.Errorf(status.InvalidArgument, "root suffix conflicts with split DNS group %s (%s)", group.ID, domain)
				}
			}
		}
		network, err := transaction.GetAccountNetwork(ctx, LockingStrengthNone, accountID)
		if err != nil {
			return err
		}
		domains, err := transaction.GetAccountDomains(ctx, LockingStrengthNone, accountID)
		if err != nil {
			return err
		}
		peers, err := transaction.GetAccountPeers(ctx, LockingStrengthNone, accountID, "", "")
		if err != nil {
			return err
		}
		preview, err = rootRenamePreview(root, network.Serial, domains, peers, canonical)
		if err != nil {
			return err
		}
		if !commit {
			return nil
		}
		if expected == "" || expected != preview.Revision {
			return status.Errorf(status.PreconditionFailed, "naming state changed; preview the rename again")
		}
		if canonical == root.DNSSuffix {
			return status.Errorf(status.InvalidArgument, "the requested suffix is already active")
		}
		tx := transaction.(*SqlStore).db.WithContext(ctx)
		if err := tx.Model(&meshdomain.Domain{}).Where("account_id = ? AND id = ?", accountID, root.ID).Updates(map[string]any{"dns_suffix": canonical, "naming_revision": root.NamingRevision + 1}).Error; err != nil {
			return err
		}
		if err := tx.Model(&types.Account{}).Where("id = ?", accountID).Updates(map[string]any{"settings_dns_domain": canonical, "network_dns": canonical}).Error; err != nil {
			return err
		}
		if err := transaction.IncrementNetworkSerial(ctx, accountID); err != nil {
			return err
		}
		preview.NamingRevision++
		preview.Committed = true
		return nil
	})
	return preview, err
}

func rootRenamePreview(root *meshdomain.Domain, serial uint64, domains []*meshdomain.Domain, peers []*nbpeer.Peer, suffix string) (*meshdomain.RenamePreview, error) {
	// Explicit ordering makes the token stable across query plans and engines.
	sort.Slice(domains, func(i, j int) bool { return domains[i].ID < domains[j].ID })
	sort.Slice(peers, func(i, j int) bool { return peers[i].ID < peers[j].ID })
	preview := &meshdomain.RenamePreview{RootID: root.ID, OldSuffix: root.DNSSuffix, NewSuffix: suffix, NamingRevision: root.NamingRevision, DeviceCount: len(peers), DomainCount: len(domains), Examples: []meshdomain.RenameExample{}, Convergence: "unobserved"}
	for _, d := range domains {
		if !d.IsRoot() {
			if err := meshdomain.ValidatePeerName("x."+d.Path, suffix); err != nil {
				return nil, status.Errorf(status.InvalidArgument, "domain %s: %s", d.ID, err)
			}
		}
	}
	// Hash only naming-relevant state, excluding volatile connection/telemetry
	// fields. The serial also invalidates a preview after placement changes that
	// were subsequently undone, without making every client poll invalidate it.
	type peerName struct {
		ID, DomainID, Label string
		Extra               []string
	}
	names := make([]peerName, 0, len(peers))
	for _, p := range peers {
		for _, label := range append([]string{p.DNSLabel}, p.ExtraDNSLabels...) {
			if err := meshdomain.ValidatePeerName(label, suffix); err != nil {
				return nil, status.Errorf(status.InvalidArgument, "device %s: %s", p.ID, err)
			}
			if len(preview.Examples) < 10 {
				preview.Examples = append(preview.Examples, meshdomain.RenameExample{Before: label + "." + root.DNSSuffix, After: label + "." + suffix})
			}
		}
		names = append(names, peerName{p.ID, p.DomainID, p.DNSLabel, p.ExtraDNSLabels})
	}
	encoded, err := json.Marshal(struct {
		AccountID, RootID, Old, New string
		NamingRevision, Serial      uint64
		Domains                     []*meshdomain.Domain
		Peers                       []peerName
	}{root.AccountID, root.ID, root.DNSSuffix, suffix, root.NamingRevision, serial, domains, names})
	if err != nil {
		return nil, fmt.Errorf("encode naming revision: %w", err)
	}
	hash := sha256.Sum256(encoded)
	preview.Revision = hex.EncodeToString(hash[:])
	return preview, nil
}
