// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package externalturn

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/netbirdio/netbird/util/crypt"
)

func newTestEncryptor(t *testing.T) *crypt.FieldEncrypt {
	t.Helper()
	key, err := crypt.GenerateKey()
	require.NoError(t, err)
	enc, err := crypt.NewFieldEncrypt(key)
	require.NoError(t, err)
	return enc
}

func newTestStore(t *testing.T, enc *crypt.FieldEncrypt) *Store {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	store, err := NewStore(db, enc)
	require.NoError(t, err)
	return store
}

func validRequest() CreateRequest {
	return CreateRequest{URI: "turns:turn.example:5349", Username: "node", Credential: "s3cret"}
}

func TestCreateRequiresEncryption(t *testing.T) {
	s := newTestStore(t, nil)
	ctx := WithAccount(context.Background(), "acct-a")
	_, err := s.Create(ctx, validRequest())
	require.ErrorIs(t, err, ErrEncryptionRequired)
}

func TestCreateRejectsPlainTurnScheme(t *testing.T) {
	s := newTestStore(t, newTestEncryptor(t))
	ctx := WithAccount(context.Background(), "acct-a")
	req := validRequest()
	req.URI = "turn:turn.example:3478"
	_, err := s.Create(ctx, req)
	require.ErrorIs(t, err, ErrInvalid)
}

func TestCreateRejectsEmptyUsernameOrCredential(t *testing.T) {
	s := newTestStore(t, newTestEncryptor(t))
	ctx := WithAccount(context.Background(), "acct-a")
	noUsername := validRequest()
	noUsername.Username = ""
	_, err := s.Create(ctx, noUsername)
	require.ErrorIs(t, err, ErrInvalid)

	noCredential := validRequest()
	noCredential.Credential = ""
	_, err = s.Create(ctx, noCredential)
	require.ErrorIs(t, err, ErrInvalid)
}

// Create/List round-trips without the credential ever appearing in the
// console-facing projection -- the core guarantee this package exists for.
func TestCreateThenListNeverExposesTheCredential(t *testing.T) {
	s := newTestStore(t, newTestEncryptor(t))
	ctx := WithAccount(context.Background(), "acct-a")
	created, err := s.Create(ctx, validRequest())
	require.NoError(t, err)
	require.NotEqual(t, "s3cret", created.Credential, "stored value must be encrypted, not the plaintext")

	rows, err := s.List(ctx)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	response := rows[0].ToResponse()
	require.Equal(t, "turns:turn.example:5349", response.URI)
	require.Equal(t, "node", response.Username)

	// Response has no credential field at all -- assert it structurally,
	// not just "didn't check for it": marshal and confirm absence.
	raw, err := json.Marshal(response)
	require.NoError(t, err)
	require.NotContains(t, string(raw), "s3cret")
	require.NotContains(t, string(raw), "credential")
}

func TestNetmapServersDecryptsTheCredential(t *testing.T) {
	s := newTestStore(t, newTestEncryptor(t))
	ctx := WithAccount(context.Background(), "acct-a")
	_, err := s.Create(ctx, validRequest())
	require.NoError(t, err)

	rows, err := s.NetmapServers(context.Background(), "acct-a")
	require.NoError(t, err)
	require.Len(t, rows, 1)
	require.Equal(t, "s3cret", rows[0].Credential, "the node-facing read is the one place the plaintext is meant to flow")
}

func TestNetmapServersIsScopedToOneAccount(t *testing.T) {
	s := newTestStore(t, newTestEncryptor(t))
	_, err := s.Create(WithAccount(context.Background(), "acct-a"), validRequest())
	require.NoError(t, err)
	_, err = s.Create(WithAccount(context.Background(), "acct-b"), validRequest())
	require.NoError(t, err)

	rows, err := s.NetmapServers(context.Background(), "acct-a")
	require.NoError(t, err)
	require.Len(t, rows, 1)
}

func TestUpdateReplacesUriAndUsernameButLeavesCredentialAloneWhenNil(t *testing.T) {
	s := newTestStore(t, newTestEncryptor(t))
	ctx := WithAccount(context.Background(), "acct-a")
	created, err := s.Create(ctx, validRequest())
	require.NoError(t, err)

	updated, err := s.Update(ctx, created.ID, UpdateRequest{URI: "turns:new.example:5349", Username: "renamed"})
	require.NoError(t, err)
	require.Equal(t, "turns:new.example:5349", updated.URI)
	require.Equal(t, "renamed", updated.Username)

	rows, err := s.NetmapServers(context.Background(), "acct-a")
	require.NoError(t, err)
	require.Equal(t, "s3cret", rows[0].Credential, "nil Credential on Update must not touch the stored one")
}

func TestUpdateReplacesCredentialWhenProvided(t *testing.T) {
	s := newTestStore(t, newTestEncryptor(t))
	ctx := WithAccount(context.Background(), "acct-a")
	created, err := s.Create(ctx, validRequest())
	require.NoError(t, err)

	replacement := "new-secret"
	_, err = s.Update(ctx, created.ID, UpdateRequest{URI: created.URI, Username: created.Username, Credential: &replacement})
	require.NoError(t, err)

	rows, err := s.NetmapServers(context.Background(), "acct-a")
	require.NoError(t, err)
	require.Equal(t, "new-secret", rows[0].Credential)
}

func TestUpdateRejectsExplicitlyEmptyCredential(t *testing.T) {
	s := newTestStore(t, newTestEncryptor(t))
	ctx := WithAccount(context.Background(), "acct-a")
	created, err := s.Create(ctx, validRequest())
	require.NoError(t, err)

	empty := ""
	_, err = s.Update(ctx, created.ID, UpdateRequest{URI: created.URI, Username: created.Username, Credential: &empty})
	require.ErrorIs(t, err, ErrInvalid)
}

func TestDeleteClosesTheGapInPosition(t *testing.T) {
	s := newTestStore(t, newTestEncryptor(t))
	ctx := WithAccount(context.Background(), "acct-a")
	first, err := s.Create(ctx, validRequest())
	require.NoError(t, err)
	_, err = s.Create(ctx, validRequest())
	require.NoError(t, err)
	third, err := s.Create(ctx, validRequest())
	require.NoError(t, err)
	require.Equal(t, 2, third.Position)

	require.NoError(t, s.Delete(ctx, first.ID))

	rows, err := s.List(ctx)
	require.NoError(t, err)
	require.Len(t, rows, 2)
	require.Equal(t, 0, rows[0].Position)
	require.Equal(t, 1, rows[1].Position)
}

func TestDeleteOfUnknownIdFailsExplicitly(t *testing.T) {
	s := newTestStore(t, newTestEncryptor(t))
	ctx := WithAccount(context.Background(), "acct-a")
	require.ErrorIs(t, s.Delete(ctx, "does-not-exist"), ErrNotFound)
}

func TestReorderAppliesTheGivenOrder(t *testing.T) {
	s := newTestStore(t, newTestEncryptor(t))
	ctx := WithAccount(context.Background(), "acct-a")
	a, err := s.Create(ctx, validRequest())
	require.NoError(t, err)
	b, err := s.Create(ctx, validRequest())
	require.NoError(t, err)

	require.NoError(t, s.Reorder(ctx, []string{b.ID, a.ID}))

	rows, err := s.List(ctx)
	require.NoError(t, err)
	require.Len(t, rows, 2)
	require.Equal(t, b.ID, rows[0].ID)
	require.Equal(t, a.ID, rows[1].ID)

	// NetmapServers must reflect the new admin order too -- a node tries
	// entries in list order, so this is the field the feature exists for.
	netmapRows, err := s.NetmapServers(context.Background(), "acct-a")
	require.NoError(t, err)
	require.Equal(t, b.ID, netmapRows[0].ID)
}

func TestReorderRejectsAPartialOrForeignSet(t *testing.T) {
	s := newTestStore(t, newTestEncryptor(t))
	ctx := WithAccount(context.Background(), "acct-a")
	a, err := s.Create(ctx, validRequest())
	require.NoError(t, err)
	_, err = s.Create(ctx, validRequest())
	require.NoError(t, err)

	require.ErrorIs(t, s.Reorder(ctx, []string{a.ID}), ErrInvalid, "a partial set (missing the second id) must be rejected")
	require.ErrorIs(t, s.Reorder(ctx, []string{a.ID, a.ID}), ErrInvalid, "a duplicate id must be rejected")
	require.ErrorIs(t, s.Reorder(ctx, []string{a.ID, "not-this-accounts-id"}), ErrInvalid, "a foreign id must be rejected")
}

func TestEverythingIsScopedByAccount(t *testing.T) {
	s := newTestStore(t, newTestEncryptor(t))
	a, err := s.Create(WithAccount(context.Background(), "acct-a"), validRequest())
	require.NoError(t, err)

	_, err = s.Update(WithAccount(context.Background(), "acct-b"), a.ID, UpdateRequest{URI: a.URI, Username: a.Username})
	require.ErrorIs(t, err, ErrNotFound)
	require.ErrorIs(t, s.Delete(WithAccount(context.Background(), "acct-b"), a.ID), ErrNotFound)

	rows, err := s.List(WithAccount(context.Background(), "acct-b"))
	require.NoError(t, err)
	require.Empty(t, rows)
}

func TestMethodsRequireAccountScope(t *testing.T) {
	s := newTestStore(t, newTestEncryptor(t))
	ctx := context.Background()
	_, err := s.Create(ctx, validRequest())
	require.ErrorIs(t, err, ErrNoAccount)
	_, err = s.List(ctx)
	require.ErrorIs(t, err, ErrNoAccount)
	require.ErrorIs(t, s.Delete(ctx, "x"), ErrNoAccount)
	require.ErrorIs(t, s.Reorder(ctx, nil), ErrNoAccount)
	_, err = s.NetmapServers(ctx, "")
	require.True(t, errors.Is(err, ErrNoAccount))
}
