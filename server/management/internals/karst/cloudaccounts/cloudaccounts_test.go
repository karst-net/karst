// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package cloudaccounts

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/netbirdio/netbird/util/crypt"
)

func newTestEncryptor(t *testing.T) *crypt.FieldEncrypt {
	t.Helper()
	key, err := crypt.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	enc, err := crypt.NewFieldEncrypt(key)
	if err != nil {
		t.Fatalf("new field encrypt: %v", err)
	}
	return enc
}

func newTestStore(t *testing.T, enc *crypt.FieldEncrypt) *Store {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("db: %v", err)
	}
	store, err := NewStore(db, enc)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	return store
}

func awsRequest(t *testing.T, mode Mode) CreateRequest {
	t.Helper()
	secret, err := json.Marshal(awsSecret{AccessKeyID: "AKIAEXAMPLE", SecretAccessKey: "shh"})
	if err != nil {
		t.Fatalf("marshal secret: %v", err)
	}
	return CreateRequest{Provider: ProviderAWS, Mode: mode, Label: "prod", Secret: secret}
}

func TestCreateRequiresEncryption(t *testing.T) {
	s := newTestStore(t, nil)
	_, err := s.Create(WithAccount(context.Background(), "acct-a"), awsRequest(t, ModeReadOnly))
	if !errors.Is(err, ErrEncryptionRequired) {
		t.Fatalf("got %v, want ErrEncryptionRequired", err)
	}
}

func TestCreateListDeleteRoundTrip(t *testing.T) {
	s := newTestStore(t, newTestEncryptor(t))
	ctx := WithAccount(context.Background(), "acct-a")

	created, err := s.Create(ctx, awsRequest(t, ModeReadWrite))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if created.Secret == "" || created.Secret == `{"access_key_id":"AKIAEXAMPLE","secret_access_key":"shh"}` {
		t.Fatal("want the stored secret to be encrypted, not plaintext")
	}

	rows, err := s.List(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 1 || rows[0].ID != created.ID {
		t.Fatalf("got %+v, want exactly the created row", rows)
	}
	resp := rows[0].ToResponse()
	if resp.Label != "prod" || resp.Mode != ModeReadWrite {
		t.Fatalf("got %+v, want label=prod mode=read_write", resp)
	}

	if err := s.Delete(ctx, created.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	rows, err = s.List(ctx)
	if err != nil {
		t.Fatalf("list after delete: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("got %d rows, want none after delete", len(rows))
	}
}

func TestResponseNeverIncludesSecret(t *testing.T) {
	s := newTestStore(t, newTestEncryptor(t))
	created, err := s.Create(WithAccount(context.Background(), "acct-a"), awsRequest(t, ModeReadOnly))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	encoded, err := json.Marshal(created.ToResponse())
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if _, present := decoded["secret"]; present {
		t.Fatal("Response must never carry the secret field")
	}
	if _, present := decoded["Secret"]; present {
		t.Fatal("Response must never carry the secret field")
	}
}

func TestDeleteIsAccountScoped(t *testing.T) {
	s := newTestStore(t, newTestEncryptor(t))
	created, err := s.Create(WithAccount(context.Background(), "acct-a"), awsRequest(t, ModeReadOnly))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := s.Delete(WithAccount(context.Background(), "acct-b"), created.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound when deleting another account's row", err)
	}
}

func TestListIsAccountScoped(t *testing.T) {
	s := newTestStore(t, newTestEncryptor(t))
	if _, err := s.Create(WithAccount(context.Background(), "acct-a"), awsRequest(t, ModeReadOnly)); err != nil {
		t.Fatalf("create: %v", err)
	}
	rows, err := s.List(WithAccount(context.Background(), "acct-b"))
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("got %d rows, want none for a different account", len(rows))
	}
}

func TestCreateValidatesProviderAndMode(t *testing.T) {
	s := newTestStore(t, newTestEncryptor(t))
	ctx := WithAccount(context.Background(), "acct-a")
	secret, _ := json.Marshal(awsSecret{AccessKeyID: "a", SecretAccessKey: "b"})

	if _, err := s.Create(ctx, CreateRequest{Provider: "not-a-provider", Mode: ModeReadOnly, Secret: secret}); err == nil {
		t.Fatal("want an error for an unknown provider")
	}
	if _, err := s.Create(ctx, CreateRequest{Provider: ProviderAWS, Mode: "not-a-mode", Secret: secret}); err == nil {
		t.Fatal("want an error for an unknown mode")
	}
}

func TestCreateValidatesSecretShapePerProvider(t *testing.T) {
	s := newTestStore(t, newTestEncryptor(t))
	ctx := WithAccount(context.Background(), "acct-a")

	cases := []struct {
		name     string
		provider Provider
		secret   string
	}{
		{"aws missing secret key", ProviderAWS, `{"access_key_id":"x"}`},
		{"azure missing fields", ProviderAzure, `{"tenant_id":"x"}`},
		{"gcp missing project", ProviderGCP, `{"service_account_key":{}}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := s.Create(ctx, CreateRequest{Provider: c.provider, Mode: ModeReadOnly, Secret: json.RawMessage(c.secret)})
			if err == nil {
				t.Fatalf("want a validation error for %s", c.name)
			}
		})
	}
}

func TestEnrichFallsBackWhenCatalogHasNoEntry(t *testing.T) {
	got := enrich(ProviderAWS, "aws-region-nobody-has-heard-of", "Mystery Region", "region", true)
	if got.Lat != nil || got.Lon != nil {
		t.Fatalf("got %+v, want no coordinates for an uncataloged region", got)
	}
	if got.Name != "Mystery Region" {
		t.Fatalf("got name %q, want the fallback name preserved", got.Name)
	}
	if !got.Enabled {
		t.Fatal("want Enabled to pass through even when the catalog has no entry")
	}
}

func TestEnrichUsesCatalogWhenPresent(t *testing.T) {
	got := enrich(ProviderAWS, "us-east-1", "fallback", "region", true)
	if got.Lat == nil || got.Lon == nil {
		t.Fatal("want coordinates for a cataloged region")
	}
}

func TestEnrichPassesThroughEnabledFalse(t *testing.T) {
	got := enrich(ProviderAWS, "us-east-1-bos-1", "Boston Local Zone", "local_zone", false)
	if got.Enabled {
		t.Fatal("want Enabled false to survive enrich, not be forced true by a catalog hit")
	}
	if got.Lat == nil {
		t.Fatal("want this cataloged local zone to still get coordinates even though it is not enabled")
	}
}
