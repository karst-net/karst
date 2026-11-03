// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package api

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/netbirdio/netbird/management/internals/karst/buildinfo"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/http/util"
)

type componentVersion struct {
	Version  string   `json:"version,omitempty"`
	Revision string   `json:"revision,omitempty"`
	Name     string   `json:"name"`
	Image    string   `json:"image"`
	ImageID  string   `json:"image_id"`
	Tags     []string `json:"tags"`
	State    string   `json:"state"`
}
type deploymentVersions struct {
	ObservedAt time.Time          `json:"observed_at"`
	Components []componentVersion `json:"components"`
}
type versionsResponse struct {
	ObservedAt       time.Time           `json:"observed_at"`
	Control          buildinfo.Info      `json:"control"`
	Deployment       *deploymentVersions `json:"deployment,omitempty"`
	DeploymentStatus string              `json:"deployment_status"`
}

func (h *handler) versions(w http.ResponseWriter, r *http.Request) {
	if _, err := nbcontext.GetUserAuthFromContext(r.Context()); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	role, ok := nbcontext.RoleFromContext(r.Context())
	if !ok || (types.UserRole(role) != types.UserRoleOwner && types.UserRole(role) != types.UserRoleAdmin) {
		util.WriteErrorResponse("Software versions require the admin or owner role", http.StatusForbidden, w)
		return
	}
	result := versionsResponse{ObservedAt: time.Now().UTC(), Control: buildinfo.Current()}
	result.Deployment, result.DeploymentStatus = loadDeploymentSnapshot()
	w.Header().Set("Cache-Control", "no-store")
	util.WriteJSONObject(r.Context(), w, result)
}

// loadDeploymentSnapshot reads the operator-maintained deployment-versions
// snapshot (scripts/compose-versions.py's output, via
// KARST_COMPONENT_VERSIONS_FILE) once per call -- shared by handler.versions
// above and the rollout API's mark-applied handler, which reconciles a
// component's claimed ObservedDigest against it (ADR-0066).
func loadDeploymentSnapshot() (*deploymentVersions, string) {
	path := os.Getenv("KARST_COMPONENT_VERSIONS_FILE")
	if path == "" {
		return nil, "not_configured"
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, "unavailable"
	}
	defer file.Close()
	var snapshot deploymentVersions
	// Decode a fixed schema; never expose arbitrary host metadata or secrets.
	if err := json.NewDecoder(io.LimitReader(file, 1<<20)).Decode(&snapshot); err != nil || snapshot.ObservedAt.IsZero() || snapshot.Components == nil {
		return nil, "unavailable"
	}
	return &snapshot, "available"
}
