// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package bootstrap

import (
	"context"
	"time"

	"github.com/netbirdio/netbird/management/internals/karst/node"
)

// sessionRecorder adapts the node store to control.SessionRecorder.
//
// It exists so the control package does not import the store, and so the
// store's methods stay free of a context they have no use for: the adapter is
// the only place that knows both shapes.
type sessionRecorder struct{ nodes *node.Store }

func (r sessionRecorder) Opened(_ context.Context, handle, clientAddr string) (uint64, error) {
	return r.nodes.OpenSession(handle, clientAddr, time.Now())
}

func (r sessionRecorder) Touched(_ context.Context, id uint64) error {
	return r.nodes.TouchSession(id, time.Now())
}

func (r sessionRecorder) Closed(_ context.Context, id uint64) error {
	return r.nodes.CloseSession(id, time.Now())
}
