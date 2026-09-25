// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func selfSignedPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "relay.test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"relay.test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func writeCA(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "relay-ca.pem")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadRelayCA(t *testing.T) {
	cert := selfSignedPEM(t)

	t.Run("unset", func(t *testing.T) {
		got, err := loadRelayCA("")
		if err != nil || got != "" {
			t.Fatalf("unset: got %q, %v; want empty, nil", got, err)
		}
	})

	t.Run("a chain of certificates", func(t *testing.T) {
		got, err := loadRelayCA(writeCA(t, cert+cert))
		if err != nil || got != cert+cert {
			t.Fatalf("got %q, %v", got, err)
		}
	})

	// Every invitation would carry it, and karstd refuses one without a
	// usable certificate, so each of these must stop the server instead.
	for name, content := range map[string]string{
		"empty":            "",
		"not PEM":          "hello",
		"a private key":    "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
		"garbage DER":      "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
		"trailing garbage": cert + "not a certificate\n",
		"oversized":        cert + strings.Repeat("\n", maxRelayCABytes),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadRelayCA(writeCA(t, content)); err == nil {
				t.Fatalf("accepted %s", name)
			}
		})
	}

	t.Run("missing file", func(t *testing.T) {
		if _, err := loadRelayCA(filepath.Join(t.TempDir(), "absent.pem")); err == nil {
			t.Fatal("accepted a missing file")
		}
	})
}
