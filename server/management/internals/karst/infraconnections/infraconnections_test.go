// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package infraconnections

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

func newTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("db: %v", err)
	}
	return db
}

func newTestStore(t *testing.T, enc *crypt.FieldEncrypt) *Store {
	t.Helper()
	store, err := NewStore(newTestDB(t), enc)
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
	return CreateRequest{Type: TypeAWS, Mode: mode, Label: "prod", Secret: secret}
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

func TestCreateValidatesTypeAndMode(t *testing.T) {
	s := newTestStore(t, newTestEncryptor(t))
	ctx := WithAccount(context.Background(), "acct-a")
	secret, _ := json.Marshal(awsSecret{AccessKeyID: "a", SecretAccessKey: "b"})

	if _, err := s.Create(ctx, CreateRequest{Type: "not-a-type", Mode: ModeReadOnly, Secret: secret}); err == nil {
		t.Fatal("want an error for an unknown type")
	}
	if _, err := s.Create(ctx, CreateRequest{Type: TypeAWS, Mode: "not-a-mode", Secret: secret}); err == nil {
		t.Fatal("want an error for an unknown mode")
	}
}

func TestCreateValidatesSecretShapePerType(t *testing.T) {
	s := newTestStore(t, newTestEncryptor(t))
	ctx := WithAccount(context.Background(), "acct-a")

	cases := []struct {
		name   string
		typ    Type
		secret string
	}{
		{"aws missing secret key", TypeAWS, `{"access_key_id":"x"}`},
		{"azure missing fields", TypeAzure, `{"tenant_id":"x"}`},
		{"gcp missing project", TypeGCP, `{"service_account_key":{}}`},
		{"kubernetes missing kubeconfig", TypeKubernetes, `{}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := s.Create(ctx, CreateRequest{Type: c.typ, Mode: ModeReadOnly, Secret: json.RawMessage(c.secret)})
			if err == nil {
				t.Fatalf("want a validation error for %s", c.name)
			}
		})
	}
}

func TestCreateRequestValidatesDeclaredLocation(t *testing.T) {
	s := newTestStore(t, newTestEncryptor(t))
	ctx := WithAccount(context.Background(), "acct-a")
	secret, _ := json.Marshal(kubernetesSecret{Kubeconfig: validTestKubeconfig})
	lat, lon := 51.5, -0.1
	badLat := 500.0

	if _, err := s.Create(ctx, CreateRequest{Type: TypeKubernetes, Mode: ModeReadOnly, Secret: secret, Lat: &lat}); err == nil {
		t.Fatal("want an error when lat is set without lon")
	}
	if _, err := s.Create(ctx, CreateRequest{Type: TypeKubernetes, Mode: ModeReadOnly, Secret: secret, Lat: &badLat, Lon: &lon}); err == nil {
		t.Fatal("want an error for an out-of-range lat")
	}
	created, err := s.Create(ctx, CreateRequest{Type: TypeKubernetes, Mode: ModeReadOnly, Secret: secret, Lat: &lat, Lon: &lon, LocationLabel: "homelab"})
	if err != nil {
		t.Fatalf("create with a valid declared location: %v", err)
	}
	if created.Lat == nil || *created.Lat != lat || created.Lon == nil || *created.Lon != lon || created.LocationLabel != "homelab" {
		t.Fatalf("got %+v, want the declared location persisted", created)
	}
}

func TestLegacyCreateRequestRejectsKubernetes(t *testing.T) {
	secret, _ := json.Marshal(kubernetesSecret{Kubeconfig: validTestKubeconfig})
	if _, err := (LegacyCreateRequest{Provider: TypeKubernetes, Mode: ModeReadOnly, Secret: secret}).toCreateRequest(); err == nil {
		t.Fatal("want an error converting a kubernetes-typed legacy request")
	}
}

func TestDiscoverLegacyRefusesKubernetesRow(t *testing.T) {
	s := newTestStore(t, newTestEncryptor(t))
	ctx := WithAccount(context.Background(), "acct-a")
	secret, _ := json.Marshal(kubernetesSecret{Kubeconfig: validTestKubeconfig})
	created, err := s.Create(ctx, CreateRequest{Type: TypeKubernetes, Mode: ModeReadOnly, Secret: secret})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := s.DiscoverLegacy(ctx, created.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound for a kubernetes row via the legacy discover path", err)
	}
}

func TestEnrichFallsBackWhenCatalogHasNoEntry(t *testing.T) {
	got := enrich(TypeAWS, "aws-region-nobody-has-heard-of", "Mystery Region", "region", true)
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
	got := enrich(TypeAWS, "us-east-1", "fallback", "region", true)
	if got.Lat == nil || got.Lon == nil {
		t.Fatal("want coordinates for a cataloged region")
	}
}

func TestEnrichPassesThroughEnabledFalse(t *testing.T) {
	got := enrich(TypeAWS, "us-east-1-bos-1", "Boston Local Zone", "local_zone", false)
	if got.Enabled {
		t.Fatal("want Enabled false to survive enrich, not be forced true by a catalog hit")
	}
	if got.Lat == nil {
		t.Fatal("want this cataloged local zone to still get coordinates even though it is not enabled")
	}
}

// TestMigrationPreservesExistingColumnOnRename guards the one thing a fresh
// AutoMigrate against an empty DB cannot prove: that Account.Type's
// `gorm:"column:provider"` tag really does make AutoMigrate read/write the
// pre-rename "provider" column rather than creating an orphaned new one and
// silently dropping every existing row's type on first read.
func TestMigrationPreservesExistingColumnOnRename(t *testing.T) {
	db := newTestDB(t)
	if err := db.Exec(`CREATE TABLE karst_cloud_accounts (
		id TEXT PRIMARY KEY,
		account_id TEXT,
		provider TEXT,
		mode TEXT,
		label TEXT,
		secret TEXT,
		created_at DATETIME
	)`).Error; err != nil {
		t.Fatalf("create pre-rename table: %v", err)
	}
	if err := db.Exec(`INSERT INTO karst_cloud_accounts (id, account_id, provider, mode, label, secret, created_at)
		VALUES ('pre-rename-id', 'acct-a', 'aws', 'read_only', 'legacy row', 'ciphertext', datetime('now'))`).Error; err != nil {
		t.Fatalf("insert pre-rename row: %v", err)
	}

	store, err := NewStore(db, newTestEncryptor(t))
	if err != nil {
		t.Fatalf("store (post-rename AutoMigrate): %v", err)
	}
	rows, err := store.List(WithAccount(context.Background(), "acct-a"))
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want the pre-existing row to survive AutoMigrate", len(rows))
	}
	if rows[0].Type != TypeAWS || rows[0].Label != "legacy row" {
		t.Fatalf("got %+v, want Type=aws (round-tripped through the preserved provider column) and the original label", rows[0])
	}
}

// validTestKubeconfig is syntactically valid (parses, has a current-context)
// but points nowhere reachable -- it only needs to pass validateKubernetesSecret;
// discoverKubernetes's live cluster calls are not exercised by these tests.
const validTestKubeconfig = `
apiVersion: v1
kind: Config
current-context: test
clusters:
- name: test-cluster
  cluster:
    server: https://127.0.0.1:1
    insecure-skip-tls-verify: true
users:
- name: test-user
  user:
    token: fake-token
contexts:
- name: test
  context:
    cluster: test-cluster
    user: test-user
`
