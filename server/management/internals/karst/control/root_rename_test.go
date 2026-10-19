// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package control_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/netbirdio/netbird/management/internals/modules/meshdomain"
	"github.com/stretchr/testify/require"
)

func TestConsoleRootRenameConfirmationAndRollback(t *testing.T) {
	router := consoleRouter(t)
	request := func(path, body string) (int, []byte) {
		r := consoleRequest(t, router, consoleAdminID, consoleCase{method: http.MethodPost, path: "/karst/v1/domains/root/rename/" + path, body: body})
		return r.Code, r.Body.Bytes()
	}
	code, data := request("preview", `{"dns_suffix":"CORP.Example."}`)
	require.Equal(t, http.StatusOK, code, string(data))
	var preview meshdomain.RenamePreview
	require.NoError(t, json.Unmarshal(data, &preview))
	require.Equal(t, "corp.example", preview.NewSuffix)
	body, err := json.Marshal(map[string]any{"dns_suffix": preview.NewSuffix, "revision": preview.Revision})
	require.NoError(t, err)
	code, data = request("commit", string(body))
	require.Equal(t, http.StatusUnprocessableEntity, code, string(data))
	body, err = json.Marshal(map[string]any{"dns_suffix": preview.NewSuffix, "revision": preview.Revision, "confirm_no_aliases": true})
	require.NoError(t, err)
	code, data = request("commit", string(body))
	require.Equal(t, http.StatusOK, code, string(data))
	var result meshdomain.RenamePreview
	require.NoError(t, json.Unmarshal(data, &result))
	require.True(t, result.Committed)
	require.Equal(t, "unobserved", result.Convergence)
	require.Equal(t, uint64(1), result.NamingRevision)
	code, data = request("preview", `{"dns_suffix":"karst"}`)
	require.Equal(t, http.StatusOK, code, string(data))
	require.NoError(t, json.Unmarshal(data, &preview))
	require.Equal(t, "corp.example", preview.OldSuffix)
	body, err = json.Marshal(map[string]any{"dns_suffix": preview.NewSuffix, "revision": preview.Revision, "confirm_no_aliases": true})
	require.NoError(t, err)
	code, data = request("commit", string(body))
	require.Equal(t, http.StatusOK, code, string(data))
	require.NoError(t, json.Unmarshal(data, &result))
	require.Equal(t, uint64(2), result.NamingRevision)
}
