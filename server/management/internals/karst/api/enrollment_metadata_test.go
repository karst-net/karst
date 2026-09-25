// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"

	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/shared/auth"
)

func enrollmentMetadata(t *testing.T, relayCA string) map[string]any {
	t.Helper()
	router := mux.NewRouter()
	RegisterEnrollmentMetadata(router, []byte{0x01}, []byte{0x02}, relayCA)
	req := httptest.NewRequest(http.MethodGet, "/karst/v1/me/enrollment", nil)
	req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{AccountId: "account-a", UserId: "user-a"})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, req)
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	var body map[string]any
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &body))
	return body
}

// Invitations spread this response into their payload, so a configured relay
// CA reaches every enrolled node's relay_ca_file.
func TestEnrollmentMetadataCarriesConfiguredRelayCA(t *testing.T) {
	const pem = "-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----\n"
	body := enrollmentMetadata(t, pem)
	require.Equal(t, pem, body["relay_ca"])
	require.Equal(t, "01", body["server_kem_pin"])
}

// Absent, not empty: karstd from before relay_ca rejects an invitation that
// names the field at all, so an unconfigured deployment must not emit it.
func TestEnrollmentMetadataOmitsRelayCAWhenUnset(t *testing.T) {
	body := enrollmentMetadata(t, "")
	_, present := body["relay_ca"]
	require.False(t, present, "relay_ca present with no CA configured: %v", body)
}
