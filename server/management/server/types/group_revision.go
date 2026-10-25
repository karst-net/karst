// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package types

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

type groupRevisionKey struct{}

// GroupRevision identifies the write-relevant group snapshot. Membership and
// resources are sets: storage order must not produce spurious conflicts.
func GroupRevision(group *Group) string {
	peers := append([]string{}, group.Peers...)
	slices.Sort(peers)
	peers = slices.Compact(peers)
	resources := append([]Resource{}, group.Resources...)
	slices.SortFunc(resources, func(a, b Resource) int {
		if a.Type != b.Type {
			return strings.Compare(string(a.Type), string(b.Type))
		}
		return strings.Compare(a.ID, b.ID)
	})
	resources = slices.Compact(resources)
	value := struct {
		Account, ID, Name, Issued, Integration string
		Peers                                  []string
		Resources                              []Resource
	}{group.AccountID, group.ID, group.Name, group.Issued, group.IntegrationReference.String(), peers, resources}
	// All fields are concrete strings/slices, so encoding cannot fail.
	data, _ := json.Marshal(value)
	return fmt.Sprintf(`"group-%x"`, sha256.Sum256(data))
}

func ValidGroupRevision(value string) bool {
	if len(value) != 72 || !strings.HasPrefix(value, `"group-`) || !strings.HasSuffix(value, `"`) {
		return false
	}
	_, err := hex.DecodeString(value[7:71])
	return err == nil
}
func WithGroupRevision(ctx context.Context, revision string) context.Context {
	return context.WithValue(ctx, groupRevisionKey{}, revision)
}
func ExpectedGroupRevision(ctx context.Context) string {
	value, _ := ctx.Value(groupRevisionKey{}).(string)
	return value
}
