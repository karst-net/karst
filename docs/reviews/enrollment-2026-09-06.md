<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# New-client enrollment review and proposed changes

Reviewed 2026-09-06 at `b3efb69`. Scope: source-level walkthrough of a new
member, administrator-issued enrollment, and first-server bootstrap. This is
a review and implementation proposal, not a claim of a completed live browser
or clean-machine walkthrough. No production behavior was changed.

Implementation and verification results are recorded in
[the implementation follow-up](enrollment-implementation-2026-09-06.md). The
findings below preserve the pre-fix review.

GitHub issues remain the implementation backlog (see `plans/README.md`). This
document is review evidence and a proposed breakdown, not a replacement backlog.
No issues were published as part of this review.

## What a new client encounters

1. Open `/portal`. The app immediately requests `/api/karst/v1/me/devices`.
   `web/portal/src/api.ts` sends no Authorization header and
   `web/portal/src/main.tsx` has no sign-in bootstrap. The management middleware
   requires JWT/PAT authorization. The checked-in pentest Caddy configuration
   simply proxies the API; it does not exchange a browser session for a token.
   **The stock path stops at an authorization error.** Signing into the console
   does not share its in-memory access token with the portal.
2. Even if authentication is supplied externally, “Add a device” calls
   `meenroll` in `server/management/internals/karst/api/nodes.go:552`. This calls
   `CreateSetupKey` as the member. `server/management/server/setupkey.go:59`
   requires SetupKeys/Create, which the ordinary User role does not grant
   (`server/management/server/permissions/roles/user.go`). **The default member
   path is denied again.** Do not solve this by granting members administrative
   setup-key permissions.
3. An authorized issuer receives a nominally one-use, 15-minute key. The portal
   tells the user to paste it into `/etc/karst/karstd.toml` and start the daemon.
   It supplies neither a complete configuration nor server pins. The Linux
   package installs binaries, a unit, and directories, but no configuration
   (`packaging/nfpm/karst-client-linux.yaml`). A new user must discover server
   identity, generate the separate data-plane key, configure identity/cache
   paths, and perform privileged service setup. The setup timer starts before
   these prerequisites are complete.
4. The console setup view has the same gap: placeholder pins and an incomplete
   `[control]` fragment (`web/console/src/views/setup.tsx:41`). The CLI has no
   enrollment command (`bins/karst-cli/src/main.rs`). Current UI no longer prints
   `karst up`; the getting-started guide's claim that it does is stale.
5. With a correct full configuration, `karstd` creates its control identity,
   verifies the pinned server, proves possession of its identity, and sends a
   login containing the setup key and data-plane public key. Successful
   enrollment must still be distinguished from Bedrock approval, netmap
   acceptance, ACL authorization, and an established peer path.

## Security findings

### P0: portal ownership bypasses credential validation

`control/login.go:99` resolves the key's owner from `karst_enrollment_owners`
and supplies that owner as `PeerLogin.UserID`. `peer.go:875` interprets any
nonempty user ID as authenticated-user enrollment. Both
`processPeerAddAuth` (`peer.go:781`) and the transaction (`peer.go:1032`)
select `addedByUser` before `addedBySetupKey`.

Consequently, a portal key with an owner binding does not take the setup-key
validity or usage-increment branches. The owner binding contains no expiry or
revocation check. An expired or revoked key whose binding remains can reach
user enrollment. After successful enrollment, `ConsumeEnrollmentKey` deletes
the binding, but the underlying setup key has not been consumed: while still
valid it can subsequently enter the ordinary setup-key path for another
identity. Concurrent attempts can resolve the same owner before deletion.
These are source-derived consequences; an end-to-end exploit was not run.

The rule must be: identifying the intended owner is not authentication as that
owner. A credential must be validated and consumed regardless of ownership.

### P1: enrollment is split across non-atomic writes

Issuance creates a setup key and then binds its owner. Redemption commits the
business peer, deletes ownership, then registers the Karst identity. Failures
between these operations can leave inconsistent state. The remedy needs both
atomic authorization/consumption and recovery for a lost response; merely
moving the deletion earlier trades replay for failed legitimate enrollments.

### P1: trust and bootstrap lifecycle are left to manual operation

Both control pins are required and checked; preserve that protection. The UI
does not deliver them through a defined authenticated onboarding mechanism.
Users must copy long values from deployment instructions and server output.
The guide also retains obsolete algorithm/length examples despite ADR-0018.

Bootstrap defaults to a reusable, unlimited, non-expiring key
(`bootstrap/enroll.go`); deleting its output file causes another key to be
minted without revoking the first. Clients retain setup keys in TOML and the
client retains its configured copy after login. File mode 0600 helps protect
storage but does not bound a copied credential's authority.

### Lifecycle gap requiring targeted verification

The client's registered node ID starts empty and is restored from its netmap
cache (`bins/karstd/src/control.rs:411,477`). Without a usable cache it takes
the registration/login path again. Existing-peer login may recover correctly;
this review does **not** assert that every restart fails. Enrollment state
should nevertheless be explicit and independent of a disposable topology
cache, with coverage for missing cache, expired grants, revoked nodes, and
lost enrollment responses.

## Intended secure user journey

1. The administrator establishes the deployment's HTTPS origin and control
   identity and configures membership and enrollment policy. First-admin
   establishment is a separate, explicit local bootstrap operation.
2. The user installs the client and starts a guided enrollment operation.
   The client generates and securely stores its own keys; private keys never
   pass through the browser or server. Ordinary CLI operations use the
   protected daemon IPC boundary for privileged changes.
3. The client obtains deployment metadata through an authenticated channel:
   server URL, both control pins, protocol floor, and required Bedrock trust.
   An administrator-provisioned bundle is the initial deliverable. HTTPS
   discovery is an optional explicit Web-PKI trust mode; it must not silently
   replace independently provisioned pins or fetch trust over plaintext HTTP.
   Pin changes require an authenticated rotation mechanism or explicit repair.
4. The user signs in and approves the specific device, account, and requested
   access. Use native authorization code with PKCE for local-browser login,
   and a reviewed device-authorization flow for headless clients. Bind the
   enrollment authorization to the device's proven control-key fingerprint.
   Show device/account details to reduce approval of an attacker's device.
5. The server issues a narrowly scoped, short-lived, one-device grant after
   checking membership, blocked/pending status, and enrollment policy. Bind it
   to account, user, device key, target server/audience, and allowed groups.
   Administrative unattended credentials are a separate explicit policy.
6. Redemption verifies proof of possession and atomically checks expiry,
   revocation, ownership, quota and scope; consumes the grant; and records the
   peer and identity. A retry for the same committed identity returns the same
   result without granting another device access. Another identity is refused.
7. Persist the enrollment receipt and identity securely; discard the grant.
   Reconnect with device identity, not the enrollment credential. Present
   distinct states: awaiting sign-in, awaiting approval, enrolled, awaiting
   Bedrock signature, connected, and denied/revoked. Enrollment never relaxes
   ACLs or network-lock verification. Route/exit-node consent stays separate.

For headless authorization, RFC 8628 specifies TLS, bounded grant lifetimes,
polling behavior and brute-force protections; it also calls out remote
phishing. Device-key binding above is an additional Karst design requirement,
not something RFC 8628 supplies automatically:
https://www.rfc-editor.org/rfc/rfc8628.html

## Ordered implementation plan and acceptance gates

| Order | Change | Acceptance |
|---|---|---|
| 1 — security fix | Introduce an explicit enrollment authorization type. Keep owner metadata separate from authenticated JWT identity. Validate and consume member grants transactionally with peer creation; preserve a consumed record bound to the resulting identity. Unify identity persistence or implement an idempotent durable completion protocol. | Real-store tests deny expired/revoked grants, reject a second identity, and admit exactly one identity under concurrent redemption. Crash/retry tests leave no unauthorized peer and recover the same enrollment after a lost response. |
| 2 — member boundary | Add a dedicated self-enrollment issuer governed by member/account policy, with atomic ownership binding. Do not reuse unrestricted administrative setup-key creation. Recheck user eligibility at redemption. | A normal member can enroll self but cannot create general setup keys, choose another owner/account, or grant privileged groups. Pending, blocked and deprovisioned users fail. |
| 3 — working browser | Share a tested OIDC/PKCE authentication implementation between portal and console, including `/portal` callback routing, renewal, logout, and bearer request handling. Add actionable authorization errors. | Clean browser signs in as a normal member against the real middleware; reload/expiry/logout work. No manually injected JWT and no auth-bypassing test proxy. |
| 4 — complete setup | Add a supported `karst enroll` operation and deployment bundle format. Validate trust/config before issuing a short-lived grant. Write keys/config/receipt atomically with restrictive permissions; use OS-specific service integration. Initially accept one-time grants via protected input/file rather than command-line arguments. | Fresh Linux package installs and enrolls using only the portal's instructions. Wrong pins fail closed; secrets are absent from argv, logs and support bundles. No service or usable config is reported as ready before validation succeeds. |
| 5 — interactive enrollment | Implement the browser/headless authorization journey and device-key-bound grants atop the same redemption service. Add cancellation, expiry, approval and rate-limit states. | Cross-device/key substitution, wrong audience, replay, polling abuse and cancelled approval fail; the intended device completes without copying bearer secrets. |
| 6 — bootstrap and recovery | Replace indefinite default bootstrap enrollment with explicit bounded issuance and a documented renewal/revocation command. Persist enrollment independently of cache. Define first-admin claim, bootstrap-owner collision prevention, account migration and pin rotation. | Reboot/cache deletion does not duplicate a node; revocation cannot silently trigger new enrollment; deleting a bootstrap file cannot accumulate live credentials. |
| 7 — release gate | Update portal/console/docs together, remove stale command and pin examples, expose enrollment vs network-access states. Execute a fresh member walkthrough against packaged artifacts and enforcing Bedrock. | An unaided tester installs, signs in, enrolls, obtains required approval, connects under an ACL, restarts, and observes revocation without manual database edits or token injection. |

Rate-limit both issuance and redemption (account/user plus trustworthy source
limits, with shared enforcement where required); keep secrets out of audit
records while recording issuer, account, device fingerprint and outcome.
Review existing backlog references #88 (enrollment limiting), #85 (first
administrator), #107 (outsider walkthrough), and #128 (console surfaces)
before creating implementation issues. Their current remote status was not
checked in this review.

## Validation and limits

The source trace covers portal, console, package contents, daemon login/cache,
control login, enrollment-owner storage, real account-manager authorization,
role definitions, and bootstrap defaults. The test
`TestMemberEnrollmentIssuesShortLivedSingleUseKey` uses a fake issuer and
checks issuance parameters; it cannot establish real permission enforcement
or redemption semantics.

Attempted focused Go tests for API, control and permissions. They did not run:
the available toolchain is Go 1.22.2, while `server/go.mod` requires Go 1.27
and selects `go1.27rc3`. No runtime exploit, real-browser test or clean-machine
enrollment is represented as completed. Those are explicit acceptance work
above, and implementation should start with the P0 regression cases.
