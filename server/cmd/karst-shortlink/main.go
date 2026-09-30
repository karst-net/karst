// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// Command karst-shortlink is the internal "go/foo" style link redirect
// service described in ADR-0042 (#213).
//
// It is a small, self-contained HTTP service: deploy it on one enrolled
// mesh device (conventionally named "go", so KarstDNS's existing
// peer-hostname resolution makes it reachable as "go.<zone>" with no
// protocol change at all), and it serves keyword -> URL redirects to every
// other peer on that account's mesh. It is not part of karst-control and
// touches no account-manager or netmap code.
package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/netbirdio/netbird/shortlink"
)

const (
	// envDB is the path to the SQLite database file holding the keyword
	// table. Defaults to a file in the current directory so the binary runs
	// out of the box for local testing; a real deployment should point it
	// somewhere durable.
	envDB = "KARST_SHORTLINK_DB"
	// envListen is the address the HTTP server binds. Bind it to the mesh
	// device's own address (or 0.0.0.0, on a host with no other public
	// listener) — ADR-0042's "why mesh-only reachability needs no new
	// mechanism".
	envListen = "KARST_SHORTLINK_LISTEN"
	// envAdminToken gates /api/links. Unset disables the CRUD API (the
	// redirect surface still serves whatever is already in the database).
	envAdminToken = "KARST_SHORTLINK_ADMIN_TOKEN" // #nosec G101 -- env var name, not a credential
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	dbPath := envOr(envDB, "karst-shortlink.db")
	listen := envOr(envListen, ":8080")
	adminToken := os.Getenv(envAdminToken)
	if adminToken == "" {
		log.Warn("KARST_SHORTLINK_ADMIN_TOKEN is unset: the CRUD API is disabled, only existing links will serve")
	}

	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		return fmt.Errorf("open database %q: %w", dbPath, err)
	}

	store, err := shortlink.NewStore(db)
	if err != nil {
		return fmt.Errorf("init store: %w", err)
	}

	handler := shortlink.NewHandler(store, adminToken)
	server := &http.Server{
		Addr:              listen,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		log.Infof("karst-shortlink listening on %s (db=%s)", listen, dbPath)
		errCh <- server.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("serve: %w", err)
		}
		return nil
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return server.Shutdown(shutdownCtx)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
