// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package manager

import (
	"context"

	"github.com/netbirdio/netbird/management/internals/modules/meshdomain"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

type rootNamingStore interface {
	RootRename(context.Context, string, string, string, bool, func(store.Store) error) (*meshdomain.RenamePreview, error)
}

func (m *managerImpl) PreviewRootRename(ctx context.Context, accountID, userID, suffix string) (*meshdomain.RenamePreview, error) {
	return m.rootRename(ctx, accountID, userID, suffix, "", false)
}

func (m *managerImpl) CommitRootRename(ctx context.Context, accountID, userID, suffix, revision string) (*meshdomain.RenamePreview, error) {
	return m.rootRename(ctx, accountID, userID, suffix, revision, true)
}

func (m *managerImpl) rootRename(ctx context.Context, accountID, userID, suffix, revision string, commit bool) (*meshdomain.RenamePreview, error) {
	authorize := func(s store.Store) error {
		if userID != activity.SystemInitiator {
			if _, err := s.GetUserByUserID(ctx, store.LockingStrengthUpdate, userID); err != nil {
				return status.NewPermissionValidationError(err)
			}
		}
		// A delegation, including one on the root, never grants suffix rename.
		allowed, _, err := permissions.NewManager(s).ValidateUserPermissions(ctx, accountID, userID, modules.Domains, operations.Update)
		if err != nil {
			return status.NewPermissionValidationError(err)
		}
		if !allowed {
			return status.NewPermissionDeniedError()
		}
		return nil
	}
	if err := authorize(m.store); err != nil {
		return nil, err
	}
	naming, ok := m.store.(rootNamingStore)
	if !ok {
		return nil, status.Errorf(status.PreconditionFailed, "root rename is unavailable for this store")
	}
	preview, err := naming.RootRename(ctx, accountID, suffix, revision, commit, authorize)
	if err != nil {
		return nil, err
	}
	if commit {
		m.accountManager.StoreEvent(ctx, userID, preview.RootID, accountID, activity.MeshRootRenamed, map[string]any{"old_suffix": preview.OldSuffix, "new_suffix": preview.NewSuffix, "naming_revision": preview.NamingRevision})
		// This accelerates existing management streams. Karst clients also poll
		// persisted DNS state independently, so restart or a lost notification
		// cannot strand a committed suffix in process-local publication state.
		m.accountManager.UpdateAccountPeers(ctx, accountID, types.UpdateReason{Resource: types.UpdateResourceDNSSettings, Operation: types.UpdateOperationUpdate})
	}
	return preview, nil
}
