// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package server

import (
	"errors"

	"github.com/gorilla/mux"
)

// APIExtension contributes routes to the authenticated management API router.
// Extensions run after NewAPIHandler has registered the built-in routes and
// middleware, before the router is first served.
type APIExtension struct {
	Register func(router *mux.Router)
}

// RegisterAPIExtension registers an API extension. It must be called before
// APIHandler is first built, normally by a server constructor hook. Returning
// an error instead of silently dropping a late route makes that lifecycle
// requirement enforceable for every extension.
func (s *BaseServer) RegisterAPIExtension(ext APIExtension) error {
	if ext.Register == nil {
		return errors.New("server: API extension has no register function")
	}
	s.apiExtensionMu.Lock()
	defer s.apiExtensionMu.Unlock()
	if s.apiHandlerBuilt {
		return errors.New("server: API handler has already been built")
	}
	s.apiExtensions = append(s.apiExtensions, ext)
	return nil
}
