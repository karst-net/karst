<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Invitation enrollment implementation evidence

The target is [enrollment-process.md](../../enrollment-process.md). This audit
records the implementation and local acceptance evidence; release checks also run
on the published branch.

## Requirement audit

| Requirement | Implementation and evidence |
| --- | --- |
| Administrator chooses account and fixed groups | The authenticated account scopes the invitation endpoints. `CreateDeviceInvitation` checks SetupKeys permissions and issuer eligibility, validates groups, and rejects subsequent scope changes. Real account-manager and console-route tests cover administrator/member authorization. |
| No recipient account or IdP interaction | Invitations carry an issuer marker separately from recipient ownership; the enrolled device has no recipient user requirement. `TestDeviceInvitationNeedsNoRecipientAccount` exercises real issuance, redemption, and group assignment. |
| One paste includes authenticated server trust | The versioned `karst-invite-v1:` envelope carries address, both public pins, protocol floor, and grant. The console obtains metadata over authenticated HTTPS; the client verifies the pinned server before registration. Browser tests validate the envelope; Rust–Go tests reject wrong pins before publishing configuration. |
| Single use, expiry, revocation, bounded issuance and redemption | Invitations last 24 hours and authorize one identity. Real-store tests exercise simultaneous redemption, expiry, revocation, immutable scope, and the 20-per-15-minute issuance bound even after revocation. Revocation also succeeds after a referenced group is removed. Existing control admission limits and atomic peer/grant transaction remain in force. |
| Lifecycle visibility and credential-safe audit | The GUI lists pending/redeemed/expired/revoked states. List responses omit credentials; creation is no-store and returns the credential once. Invitation audit metadata excludes credential prefixes. Deletion cannot erase issuance history. |
| Automatic local setup and service start | The installed Linux desktop launcher accepts a hidden-text paste and invokes a fixed privileged helper through stdin using native polkit authentication. The helper publishes configuration and enables/starts systemd. The fresh-package GUI acceptance test exercises these installed paths. |
| Private local identity, safe files, no credential retention | Existing enrollment locks, private key files, atomic no-overwrite publication, and durable identity receipt are shared by the invitation entry point. Unit tests cover concurrent setup, symlinks, and malformed-secret errors. Package acceptance checks credential-free configuration and absence of staging files after success. |
| Safe interrupted enrollment and retry | Real HTTP-to-control enrollment injects an identity-persistence failure after the grant transaction and recovers with the same identity. Wrong-pin interop retries without regenerating local keys. Packaged tests force service-start failure, retry without another invitation, and compare identity hashes. |
| Restart independent of cache/grant | Rust–Go tests reconnect without either cache or grant. Packaged acceptance removes the topology cache, restarts using the saved identity, and verifies permitted tunnel traffic again. Enrollment receipts prevent silent re-enrollment after device revocation. |
| Accurate readiness and separate Bedrock approval | Setup reads the daemon's own authenticated-session status rather than opening a competing session. Missing or cache-only status cannot report Connected. The pending-approval package test asserts no tunnel before countersignature, inspects the pending dialog, approves the device, clicks Retry, and inspects Connected afterward. |
| Usable connectivity | Two packaged devices establish encrypted sessions and carry a permitted TCP request through the tunnel. The request also succeeds after forced-start recovery and cacheless restart. This checks data traffic beyond registration or an interface existing. |

## Local validation

- Affected Rust unit tests: 392 passed; formatting and Clippy with warnings denied
  passed.
- Rust–Go control integration: all 23 tests passed, including pasted invitation,
  wrong server trust, identity-only restart, policy enforcement, and Bedrock.
- Console: production build and all 52 browser tests passed. Browser assertions
  include envelope pins, selected groups, absence from persistent browser storage,
  dismissal, status reload, revocation, and accessibility.
- Real-store invitation lifecycle, concurrency, expiry, issuance limits, and
  administrator/member console mutation tests passed. The migration regression
  preserves administrator invitations while invalidating legacy grants.
- The full Karst Go race suite and the expanded enrollment/upstream-fixture CI
  gate passed. A broader run of the entire upstream server package reached its
  five-minute suite timeout while still progressing; it is not reported as a pass.
- Fresh Ubuntu 24.04 package acceptance passed both ordinary and Bedrock-pending
  enrollment, OS authorization, service enable/start, real tunnel traffic,
  failed-start recovery, cacheless restart, and unchanged local identity.
- Both final desktop dialogs were visually inspected: pending with Retry/Close,
  then Connected. Documentation and shell syntax checks passed.

## Reproducing packaged acceptance

Build the Go control fixture and provide the client package and relay binary from
the same checkout. Run both scenarios:

```sh walkthrough=none reason="isolated desktop acceptance requires built packages and a Go fixture"
./scripts/enrollment-desktop-verify.sh CLIENT.deb target/karst-testserver /tmp/enrollment-connected RELAY_BIN
KARST_ACCEPTANCE_PENDING=1 ./scripts/enrollment-desktop-verify.sh CLIENT.deb target/karst-testserver /tmp/enrollment-pending RELAY_BIN
```

Artifacts include `setup-result.png`, `setup-pending.png` for the pending case,
service logs, both devices' status, identity hashes, and recovery results. The
harness removes both disposable containers. It uses real GUI, polkit, systemd,
client, control wire handlers, relay, and tunnel traffic. The control account is a
test fixture; authorization and grant consumption use separate real-store tests.
The test-only approval endpoint is not part of the production server.

The deliverables workflow runs both scenarios against its packaged client and
relay and retains their artifacts. Release artifact generation depends on these
checks as well as the existing distribution installation and systemd checks.

The desktop implementation is for Linux with systemd and an interactive desktop.
Local package binaries were built on Ubuntu 24.04; that does not establish the
release binary's glibc floor or other distribution dependency availability. The
existing Rocky 9 release build and Debian/Ubuntu/Fedora/UBI installation matrix
provide those separate release gates. The alternative Unix bundle command remains
available; this audit does not claim a native macOS setup application.
