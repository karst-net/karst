// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package relayusage

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/karst/identity"
)

func TestUploadEndpointPersistsAndAcknowledgesBatch(t *testing.T) {
	db, store, key, relayID, mapping := ingestionFixture(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	windowStart := uint64(now.UnixMicro() / int64(minuteMicros) * int64(minuteMicros))
	body := makeSignedBatch(t, key, [16]byte{1}, 0, mappingPayloadAt(mapping, 42, windowStart))
	auth := makeUploadAuth(t, key, relayID, body, now, [32]byte{7})
	header := makeAuthHeader(auth)
	router := mux.NewRouter()
	RegisterUploadEndpoint(router, store)
	request := httptest.NewRequest(http.MethodPost, UploadPath, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set("Authorization", header)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	require.Equal(t, http.StatusNoContent, response.Code)
	require.Equal(t, "no-store", response.Header().Get("Cache-Control"))
	var count int64
	require.NoError(t, db.Model(&receivedBatch{}).Count(&count).Error)
	require.EqualValues(t, 1, count)

	// A retry preserves the signed batch but carries a newly signed request.
	retryAuth := makeUploadAuth(t, key, relayID, body, now, [32]byte{9})
	retry := httptest.NewRequest(http.MethodPost, UploadPath, bytes.NewReader(body))
	retry.Header.Set("Content-Type", "application/octet-stream")
	retry.Header.Set("Authorization", makeAuthHeader(retryAuth))
	retryResponse := httptest.NewRecorder()
	router.ServeHTTP(retryResponse, retry)
	require.Equal(t, http.StatusNoContent, retryResponse.Code)
	count = 0
	require.NoError(t, db.Model(&receivedBatch{}).Count(&count).Error)
	require.EqualValues(t, 1, count, "an acknowledged retry must not add a second batch")

	badRoute := httptest.NewRequest(http.MethodPost, UploadPath+"?unused=1", bytes.NewReader(body))
	badRoute.Header.Set("Content-Type", "application/octet-stream")
	badRoute.Header.Set("Authorization", makeAuthHeader(makeUploadAuth(t, key, relayID, body, now, [32]byte{8})))
	badResponse := httptest.NewRecorder()
	router.ServeHTTP(badResponse, badRoute)
	require.Equal(t, http.StatusBadRequest, badResponse.Code)
}

func TestUploadEndpointBoundsBodyBeforeParsing(t *testing.T) {
	_, store, _, _, _ := ingestionFixture(t)
	router := mux.NewRouter()
	RegisterUploadEndpoint(router, store)
	var relayID [32]byte
	for i := range relayID {
		relayID[i] = byte(i)
	}
	var nonce [32]byte
	nonce[0] = 1
	// The handler decodes auth framing before reading the body, but does not
	// perform expensive ML-DSA verification until after its hard body bound.
	header := "KarstUsage " + base64.RawURLEncoding.EncodeToString(relayID[:]) + ".1." + hex.EncodeToString(nonce[:]) + "." + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, identity.SignatureSize))
	request := httptest.NewRequest(http.MethodPost, UploadPath, bytes.NewReader(make([]byte, maxEncodedSize+1)))
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set("Authorization", header)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	require.Equal(t, http.StatusRequestEntityTooLarge, response.Code)
}

func makeAuthHeader(auth UploadAuthorization) string {
	return "KarstUsage " + auth.RelayID + "." + strconv.FormatUint(auth.TimestampMicros, 10) + "." + hex.EncodeToString(auth.Nonce[:]) + "." + base64.StdEncoding.EncodeToString(auth.Signature)
}
