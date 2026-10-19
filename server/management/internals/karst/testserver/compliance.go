// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package main

import (
	"context"
	"encoding/json"
	"github.com/netbirdio/netbird/management/internals/karst/compliance"
	"github.com/netbirdio/netbird/management/internals/karst/control"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"net/http"
	"os"
	"sync/atomic"
	"time"
)

// Opt-in wire-test fixture. Uses the production handler/store and mirrors the
// fixture's enrollments into the authoritative SQL table checked by ingestion.
type complianceFixture struct {
	delayFirst atomic.Bool
	db         *gorm.DB
	store      *compliance.Store
	handler    *control.ComplianceHandler
	refuse     bool
}
type compliancePeer struct {
	ID        string `gorm:"primaryKey"`
	AccountID string
	Key       string
}

func (compliancePeer) TableName() string { return "peers" }
func installComplianceFixture(r *router, db *gorm.DB) error {
	enabled, refuse, delay := false, false, false
	for _, arg := range os.Args[1:] {
		if arg == "--compliance-delay-first" {
			delay = true
		}
		if arg == "--compliance" {
			enabled = true
		}
		if arg == "--compliance-refuse" {
			refuse = true
		}
	}
	if !enabled {
		return nil
	}
	if err := db.AutoMigrate(&compliancePeer{}); err != nil {
		return err
	}
	store, err := compliance.NewStore(db)
	if err != nil {
		return err
	}
	r.compliance = &complianceFixture{db: db, store: store, handler: &control.ComplianceHandler{Store: store, Peers: r.account}, refuse: refuse}
	r.compliance.delayFirst.Store(delay)
	for _, p := range r.account.peers {
		if err := r.compliance.enroll(p); err != nil {
			return err
		}
	}
	r.netmap.ComplianceIngestion = true
	return nil
}
func (f *complianceFixture) enroll(p *nbpeer.Peer) error {
	return f.db.Clauses(clause.OnConflict{UpdateAll: true}).Create(&compliancePeer{ID: p.ID, AccountID: p.AccountID, Key: p.Key}).Error
}
func (f *complianceFixture) handle(ctx context.Context, nodeID, identity, body []byte) ([]byte, error) {
	if f.delayFirst.CompareAndSwap(true, false) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(6 * time.Second):
		}
	}
	if f.refuse {
		return nil, status.Error(codes.Unavailable, "test compliance refusal")
	}
	return f.handler.Handle(ctx, nodeID, identity, body)
}

// Explicitly enabled fixture control listener only, never a production API.
func (f *complianceFixture) serve(r *router, w http.ResponseWriter, req *http.Request) {
	handle := req.URL.Query().Get("handle")
	p, err := r.account.GetPeerByPeerPubKey(req.Context(), handle)
	if err != nil {
		http.Error(w, "missing enrollment", 404)
		return
	}
	latest, err := f.store.Latest(req.Context(), compliance.Subject{TenantID: p.AccountID, DeviceID: p.ID}, handle, time.Now().UTC())
	if err != nil {
		http.Error(w, "no evidence", 404)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(latest)
}
