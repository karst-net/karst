// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// Package infraprovision defines the provider-agnostic interface
// relayalloc's reconciliation loop (ADR-0063) drives a named relay
// allocation through, so the loop itself never names a cloud SDK call --
// see docs/adr/0067-unified-relay-provisioning-workflow.md. It holds only
// the interface and the few provider-agnostic helpers both concrete
// drivers (infraprovision/awsdriver, infraprovision/nomaddriver) need
// identically. It has no dependency on infraconnections or relayalloc, so
// neither forms an import cycle through it: infraconnections constructs a
// Driver (it alone holds the decrypted credential), relayalloc only ever
// calls one.
//
// This is not karst_scaler_driver.Driver (crates/karst-scaler-driver)
// reused: that trait is Rust, pool-scoped (list/create(n)/drain/destroy
// against a pool_id), for the separate continuous pool autoscaler.
// relayalloc drives exactly one named instance at a time, with no pool
// and no count -- ADR-0067's "Alternatives rejected" explains why forcing
// pool shape onto this a second time was rejected.
package infraprovision

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// Instance is one provider-specific thing a Driver created, as it exists
// right now -- Create's own return value.
type Instance struct {
	// ID is the provider's own handle: an EC2 instance id for awsdriver, a
	// dispatched Nomad job id for nomaddriver. Opaque to relayalloc, which
	// only ever stores and replays it back into TLSServerName/Drain/Destroy.
	ID string
	// TLSServerName is the correlation label a relay registers itself
	// under (relayreg.StoredRelay.TLSServerName) -- "" if not yet
	// discoverable, which callers must treat as "retry later," not a
	// failure.
	TLSServerName string
}

// CreateRequest is everything a Driver needs to boot one relay and let it
// enroll itself.
type CreateRequest struct {
	// ControlAPIBase is the management server's own externally-reachable
	// API base URL, so the newly created instance's own `karst-relay
	// enroll` boot path knows where to call back.
	ControlAPIBase string
	// Token is a single-use, narrowly-scoped relay-enroll credential,
	// minted by the caller (relayalloc's own enrollMinter) immediately
	// before calling Create -- a Driver never mints its own.
	Token string
}

// DriverError is a Driver operation's own failure -- deliberately one
// message-carrying type rather than a set of named variants, mirroring
// karst_scaler_driver::DriverError's own reasoning: a real driver's
// failure modes (quota, a transient API error, a job template that does
// not exist, ...) are not yet a well-enough-understood set to name as
// distinct variants without guessing which ones callers will actually
// need to branch on.
type DriverError struct {
	Msg string
}

func (e *DriverError) Error() string { return e.Msg }

// Driver is what relayalloc's reconciliation loop drives a named
// allocation through, once per tick, regardless of which infrastructure
// connection backs it -- see the package doc comment for why this is not
// the Rust pool Driver trait reused.
type Driver interface {
	// Create provisions one instance correlated to allocationID, or
	// returns one already live under that same correlation if a previous
	// call already succeeded but the caller crashed or timed out before
	// recording it -- callers may call this again after such a crash;
	// implementations must look before they create.
	Create(ctx context.Context, allocationID string, req CreateRequest) (Instance, error)
	// TLSServerName re-reads instanceID's own correlation label, once
	// discoverable. "", nil means "not yet" -- the instance's own boot
	// window hasn't finished -- and must be retried, not treated as a
	// failure.
	TLSServerName(ctx context.Context, instanceID string) (string, error)
	// Drain stops instanceID from taking new work and returns once it has
	// drained or the Driver's own bounded wait for that has elapsed. A
	// caller may call Destroy immediately after a successful return.
	Drain(ctx context.Context, instanceID string) error
	// Destroy removes instanceID for good and returns its TLSServerName
	// if still discoverable (so the caller can deenroll the matching
	// relayreg row), "" if not.
	Destroy(ctx context.Context, instanceID string) (string, error)
}

// TLSServerNameFor derives the stable, unique, whitespace-free ASCII
// correlation label a Driver implementation uses -- SHA-256(token), first
// 6 bytes, lowercase hex, dotted with suffix so two drivers' labels (or a
// BYO-registered relay's own address-derived one) never collide. The raw
// token is single-use and this label ends up in a relayreg entry other
// peers can see, so it is derived by hashing, never embedded verbatim.
//
// awsdriver must call this with suffix "aws.karst.internal" -- byte-for-
// byte identical to bins/karst-scaler-aws's own derivation (bundle.rs),
// since both actuators' instances are looked up by this same tag value.
// nomaddriver has no such cross-process compatibility constraint and uses
// its own suffix, "nomad.karst.internal", only to keep the two drivers'
// labels visibly distinct from each other.
func TLSServerNameFor(allocationID, token, suffix string) string {
	digest := sha256.Sum256([]byte(token))
	return fmt.Sprintf("%s-%s.%s", allocationID, hex.EncodeToString(digest[:6]), suffix)
}
