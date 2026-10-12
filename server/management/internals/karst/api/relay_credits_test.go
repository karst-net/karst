// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/netbirdio/netbird/management/internals/karst/billing"
	"github.com/netbirdio/netbird/management/internals/karst/identity"
	"github.com/netbirdio/netbird/management/internals/karst/relayusage"
	"github.com/netbirdio/netbird/management/internals/karst/usage"
)

func TestRelayCreditEndpointIssuesOnlySignedAuthorizedRequests(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "relay-credits.db")), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { _ = sqlDB.Close() })
	require.NoError(t, usage.Migrate(db))
	relays, err := relayusage.NewStore(db)
	require.NoError(t, err)
	billingStore, err := billing.NewStore(db)
	require.NoError(t, err)

	now := time.Now().UTC()
	start := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	end := start.AddDate(0, 1, 0)
	accountCtx := billing.WithAccount(context.Background(), "account-1")
	schedule := billing.PilotRateSchedule()
	require.NoError(t, billingStore.PutSchedule(accountCtx, schedule))
	require.NoError(t, billingStore.AssignSchedule(accountCtx, start, end, schedule.Version))
	_, err = billingStore.SetRelaySpendingCap(accountCtx, start, end, 200, true, "owner-1")
	require.NoError(t, err)

	mapping, err := usage.PersistRelayMapping(context.Background(), db, "deployment-a", "aquifer-a", "account-1")
	require.NoError(t, err)
	key, err := identity.FromSeed(bytes.Repeat([]byte{55}, identity.SeedSize))
	require.NoError(t, err)
	relayID, err := relays.AuthorizeProducer(context.Background(), key.Public(), "deployment-a")
	require.NoError(t, err)
	require.NoError(t, relays.AllowMapping(context.Background(), relayID, mapping.DeploymentID, mapping.Version))
	request := relayusage.CreditRequest{RelayID: relayID, DeploymentID: "deployment-a", MappingVersion: mapping.Version,
		Generation: "0102030405060708090a0b0c0d0e0f10", RequestID: "1112131415161718191a1b1c1d1e1f20", RequestedBytes: "3000000000"}
	input, err := request.SigningInput()
	require.NoError(t, err)
	signature, err := key.Sign([]byte(identity.RelayCreditRequestContext), input)
	require.NoError(t, err)
	request.Signature = base64.StdEncoding.EncodeToString(signature)
	body, err := json.Marshal(request)
	require.NoError(t, err)

	router := mux.NewRouter()
	RegisterRelayCreditEndpoint(router, relays, billingStore)
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, relayusage.CreditRequestPath, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, req)
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	require.Equal(t, "no-store", response.Header().Get("Cache-Control"))
	var grant billing.RelayCreditGrant
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &grant))
	require.Equal(t, "account-1", grant.AccountID)
	require.Equal(t, "3000000000", grant.GrantedBytes)

	request.RequestedBytes = "3000000001"
	body, err = json.Marshal(request) // The original signature no longer authenticates this body.
	require.NoError(t, err)
	response = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, relayusage.CreditRequestPath, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, req)
	require.Equal(t, http.StatusForbidden, response.Code, response.Body.String())
}
