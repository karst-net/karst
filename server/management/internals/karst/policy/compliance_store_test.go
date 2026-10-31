// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package policy_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/netbirdio/netbird/management/internals/karst/compliance"
	"github.com/netbirdio/netbird/management/internals/karst/policy"
)

func openComplianceDraftStore(t *testing.T) *policy.ComplianceDraftStore {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:compliance-draft-%s?mode=memory&cache=shared", t.Name())), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	store, err := policy.NewComplianceDraftStore(db)
	require.NoError(t, err)
	return store
}

func sampleDraft(tenantID string) policy.ComplianceDraft {
	return policy.ComplianceDraft{
		TenantID: tenantID,
		RequirementSets: map[string][]compliance.Requirement{
			"min-version": {{ID: "min-version", Kind: compliance.MinimumClientVersion, MinimumVersion: "1.0.0", Provenance: compliance.SelfReported}},
		},
		Guardrails: []policy.ComplianceGuardrail{
			{ID: "prod-db", Resource: policy.ComplianceResource{Selector: "10.0.0.0/24", Protocol: "tcp", Ports: policy.PortRange{First: 5432, Last: 5432}}, RequirementSets: []string{"min-version"}},
		},
	}
}

func TestComplianceDraftVersionsAreAccountScoped(t *testing.T) {
	store := openComplianceDraftStore(t)
	first, err := store.Write(policy.WithAccount(context.Background(), "account-a"), sampleDraft("account-a"), "admin-a", 0)
	require.NoError(t, err)
	require.Equal(t, uint64(1), first.Version)

	second, err := store.Write(policy.WithAccount(context.Background(), "account-b"), sampleDraft("account-b"), "admin-b", 0)
	require.NoError(t, err)
	require.Equal(t, uint64(1), second.Version)

	versionA, err := store.Current(policy.WithAccount(context.Background(), "account-a"))
	require.NoError(t, err)
	require.Equal(t, "admin-a", versionA.Author)
	draftA, err := versionA.Draft()
	require.NoError(t, err)
	require.Equal(t, "account-a", draftA.TenantID)

	_, err = store.Current(policy.WithAccount(context.Background(), "account-c"))
	require.ErrorIs(t, err, policy.ErrNoVersion)
}

func TestComplianceDraftWriteRejectsStaleExpectedVersion(t *testing.T) {
	store := openComplianceDraftStore(t)
	ctx := policy.WithAccount(context.Background(), "account-a")
	_, err := store.Write(ctx, sampleDraft("account-a"), "admin-a", 0)
	require.NoError(t, err)

	_, err = store.Write(ctx, sampleDraft("account-a"), "admin-a", 0)
	require.ErrorIs(t, err, policy.ErrVersionConflict)

	second, err := store.Write(ctx, sampleDraft("account-a"), "admin-a", 1)
	require.NoError(t, err)
	require.Equal(t, uint64(2), second.Version)
}

func TestComplianceDraftWriteRejectsTenantMismatch(t *testing.T) {
	store := openComplianceDraftStore(t)
	ctx := policy.WithAccount(context.Background(), "account-a")
	_, err := store.Write(ctx, sampleDraft("account-b"), "admin-a", 0)
	require.Error(t, err)
}

func TestComplianceDraftWriteRequiresAccountScope(t *testing.T) {
	store := openComplianceDraftStore(t)
	_, err := store.Write(context.Background(), sampleDraft("account-a"), "admin-a", 0)
	require.ErrorIs(t, err, policy.ErrNoAccount)
}

func TestCurrentDraftReturnsUnconfiguredBeforeAnyWrite(t *testing.T) {
	store := openComplianceDraftStore(t)
	draft, revision, err := store.CurrentDraft(context.Background(), "account-a")
	require.NoError(t, err)
	require.Equal(t, "", revision)
	require.Equal(t, policy.ComplianceDraft{}, draft)
}

func TestCurrentDraftReflectsLatestWrittenVersion(t *testing.T) {
	store := openComplianceDraftStore(t)
	ctx := policy.WithAccount(context.Background(), "account-a")
	written, err := store.Write(ctx, sampleDraft("account-a"), "admin-a", 0)
	require.NoError(t, err)

	draft, revision, err := store.CurrentDraft(context.Background(), "account-a")
	require.NoError(t, err)
	require.Equal(t, fmt.Sprint(written.Version), revision)
	require.Equal(t, "account-a", draft.TenantID)
	require.Len(t, draft.Guardrails, 1)
}

func TestComplianceDraftVersionRoundTripsThroughJSON(t *testing.T) {
	store := openComplianceDraftStore(t)
	ctx := policy.WithAccount(context.Background(), "account-a")
	draft := sampleDraft("account-a")
	draft.Remediation = []policy.ComplianceResource{{Selector: "10.0.1.0/24", Protocol: "*", Ports: policy.PortRange{First: 0, Last: 65535}}}
	_, err := store.Write(ctx, draft, "admin-a", 0)
	require.NoError(t, err)

	version, err := store.Current(ctx)
	require.NoError(t, err)
	roundTripped, err := version.Draft()
	require.NoError(t, err)
	require.Equal(t, draft, roundTripped)
}

func TestComplianceDraftGetUnknownVersionIsNoVersion(t *testing.T) {
	store := openComplianceDraftStore(t)
	ctx := policy.WithAccount(context.Background(), "account-a")
	_, err := store.Write(ctx, sampleDraft("account-a"), "admin-a", 0)
	require.NoError(t, err)

	_, err = store.Get(ctx, 99)
	require.True(t, errors.Is(err, policy.ErrNoVersion))
}
