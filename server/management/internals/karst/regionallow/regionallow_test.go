// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package regionallow_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/netbirdio/netbird/management/internals/karst/regionallow"
)

func newStore(t *testing.T) *regionallow.Store {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:regionallow-store-%s?mode=memory&cache=shared", t.Name())), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	store, err := regionallow.NewStore(db)
	require.NoError(t, err)
	return store
}

func TestNoReconcileMeansNoAllowedRegions(t *testing.T) {
	store := newStore(t)
	doc, err := store.AllowedRegions(context.Background())
	require.NoError(t, err)
	require.Empty(t, doc)
}

func TestReconcileAllowsListedRegions(t *testing.T) {
	store := newStore(t)
	ctx := context.Background()

	require.NoError(t, store.Reconcile(ctx, regionallow.Document{
		"aws":   {"us-east-1", "us-west-2"},
		"azure": {"eastus"},
	}))

	doc, err := store.AllowedRegions(ctx)
	require.NoError(t, err)
	require.Equal(t, regionallow.Document{
		"aws":   {"us-east-1", "us-west-2"},
		"azure": {"eastus"},
	}, doc)
}

func TestReconcileIsDeclarativeNotAdditive(t *testing.T) {
	store := newStore(t)
	ctx := context.Background()

	require.NoError(t, store.Reconcile(ctx, regionallow.Document{
		"aws": {"us-east-1", "us-west-2"},
	}))
	// A second reconcile with a smaller set revokes what dropped out, and
	// does not merge with the first — the file is the whole truth, not an
	// incremental patch.
	require.NoError(t, store.Reconcile(ctx, regionallow.Document{
		"aws": {"us-west-2"},
	}))

	doc, err := store.AllowedRegions(ctx)
	require.NoError(t, err)
	require.Equal(t, regionallow.Document{"aws": {"us-west-2"}}, doc)
}

func TestReconcileWithNilClearsAnyPreviousAllowlist(t *testing.T) {
	store := newStore(t)
	ctx := context.Background()

	require.NoError(t, store.Reconcile(ctx, regionallow.Document{"aws": {"us-east-1"}}))
	// KARST_ALLOWED_REGIONS_FILE unset on a later boot is nil, which must
	// clear a previous run's allowlist -- §4c's fail-closed default, not a
	// special case this package has to opt into.
	require.NoError(t, store.Reconcile(ctx, nil))

	doc, err := store.AllowedRegions(ctx)
	require.NoError(t, err)
	require.Empty(t, doc)
}

func TestParseRejectsUnknownFields(t *testing.T) {
	_, err := regionallow.Parse([]byte(`{"allowed_regions":{"aws":["us-east-1"]},"oops":true}`))
	require.Error(t, err)
}

func TestParseRejectsEmptyProviderKey(t *testing.T) {
	_, err := regionallow.Parse([]byte(`{"allowed_regions":{"":["us-east-1"]}}`))
	require.Error(t, err)
}

func TestParseRejectsEmptyRegion(t *testing.T) {
	_, err := regionallow.Parse([]byte(`{"allowed_regions":{"aws":[""]}}`))
	require.Error(t, err)
}

func TestParseValidDocument(t *testing.T) {
	doc, err := regionallow.Parse([]byte(`{"allowed_regions":{"aws":["us-east-1"],"aws-gov-cloud":["us-gov-west-1"]}}`))
	require.NoError(t, err)
	require.Equal(t, regionallow.Document{
		"aws":           {"us-east-1"},
		"aws-gov-cloud": {"us-gov-west-1"},
	}, doc)
}

func TestParseEmptyDocumentIsAllowedRegionsNil(t *testing.T) {
	doc, err := regionallow.Parse([]byte(`{}`))
	require.NoError(t, err)
	require.Empty(t, doc)
}
