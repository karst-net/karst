<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Enrollment repair: implementation and verification

This follows the [source review](enrollment-2026-09-06.md). The repaired
new-client path is: install the Linux package, sign into the HTTPS portal,
download a complete enrollment bundle, run `karst enroll --bundle FILE`, then
start the installed daemon and check its status.

## Implemented changes

- Member enrollment uses a dedicated issuer. It does not grant members
  administrative setup-key permissions. Account and owner are stored with the
  one-use, fifteen-minute key in one transaction. Issuance is bounded to five
  requests per member per fifteen minutes.
- Key ownership is separate from JWT authentication. Expiry, revocation and
  usage are checked even when a JWT or legacy owner metadata accompanies the
  credential. Peer creation and key consumption share a transaction; blocked,
  pending, missing, cross-account and changed-membership owners are refused.
- Identity persistence after peer creation is recoverable. A retry by the
  same proven device repairs a failed identity write without consuming another
  grant. A second identity cannot redeem the consumed grant.
- Portal and console share OIDC Authorization Code with PKCE, bearer request
  handling and an explicitly in-memory user store. The portal has its own
  callback and silent-renew paths. Production portal startup fails closed
  when authentication is not configured.
- The authenticated metadata endpoint supplies both control pins and the
  protocol floor. The HTTPS portal downloads them with the one-use credential
  as a complete TOML bundle. This explicitly trusts the browser's HTTPS
  deployment; independently provisioned trust remains available through an
  administrator-supplied bundle.
- `karst enroll` creates private keys locally, authenticates the pinned server,
  saves a server/identity-bound enrollment receipt, and atomically publishes a
  secret-free daemon configuration. It refuses existing configurations,
  insecure directory modes and unprotected bundles. An OS lock prevents
  concurrent local attempts; interrupted attempts retain the same identity.
- Reconnection uses the identity receipt independently of the topology cache.
  Revocation does not silently trigger enrollment with a retained setup key.
- Bootstrap keys are limited to one hour and ten enrollments. Renewal revokes
  previous bootstrap credentials transactionally. Startup invalidates legacy
  portal grants and unbounded bootstrap credentials; already enrolled devices
  remain registered.
- The CLI help, getting-started guide, web quickstart, Keycloak callback
  template, OpenAPI contract and generated Go/TypeScript models are updated.
  ACL and Bedrock approval remain separate from enrollment.

## Verification performed

| Requirement | Evidence |
|---|---|
| Ordinary member can enroll without general key privileges | Real account-manager test rejects `CreateSetupKey` for the member, then accepts self-enrollment. |
| Expiry, revocation, ownership and one-use enforcement | Real-store enrollment tests cover expired/revoked keys, blocked/pending/deleted/cross-account owners, JWT/legacy-owner bypass attempts, replay and eight concurrent redemptions. |
| Recover partial persistence | HTTP issuer → real account manager → control handler test injects an identity-write failure after key consumption, then verifies retry repairs the same device and a second identity fails. |
| Correct browser authentication | Playwright runs the actual OIDC client against a test IdP protocol fixture, checks the PKCE verifier/challenge, bearer requests, portal callback paths, logout, reload recovery and absence of tokens in browser storage. |
| Complete, protected onboarding artifact | Browser tests inspect the downloaded bundle's pins, URL and credential, and prove HTTP origins are refused before issuance. |
| Actual CLI produces a usable config | Built `karst` enrolls against an isolated Go control server; built `karstd check` accepts the resulting config and fetches a peer. The config contains no setup key. |
| Pin failure and restart recovery | Rust-to-Go tests cover wrong-pin refusal with no published config, retry with the same local key, and reconnect without either cache or setup key. |
| Safe local persistence | Tests cover concurrent lock exclusion/release, no overwrite or symlink following on publication, mode 0600, and parser errors that do not disclose the credential. |
| Bootstrap compatibility | Bootstrap and control startup package tests pass, including bounded expiry/usage and single-live-key rotation. |

Validation results:

- 384 existing daemon unit tests and three new filesystem safety tests passed.
- Two guided-enrollment Rust-to-Go integration tests passed.
- All account-manager peer/setup-key/enrollment tests passed (245 seconds).
  The final enrollment-specific tests also passed after the membership check
  and fault-injection additions.
- All Karst Go packages and `cmd/karst-control` passed.
- Console browser suite: 52 passed. Portal browser suite: 10 passed, including
  PKCE login, reload recovery and logout.
- Both web builds, generated API client type checking, and web lint passed.
- Rust Clippy with warnings denied and whitespace checks passed.

An earlier unfiltered account-manager run exceeded Go's default ten-minute
suite timeout while progressing through unrelated user-invitation tests. The
relevant peer/setup-key suite was rerun with an adequate timeout and passed;
this is not a claim that the entire repository's test suite was run to completion.

## Deployment and scope

Add `/portal/oidc/callback` and `/portal/silent-renew.html` to the IdP's allowed
redirects and allow the portal's post-logout URL. Rebuild/deploy the client,
server, console and portal together. Existing legacy portal bundles must be
reissued; an old unlimited bootstrap file must be explicitly renewed. See
[the updated guide](../GETTING-STARTED.md#83-guided-client-enrollment).

The delivered flow uses the authenticated portal and a short-lived bundle.
A separate native browser/device-code OAuth flow proposed in the review is
not implemented by this repair. Guided provisioning supports Unix, with the
portal instructions targeting Linux packages. Verification used isolated
fixtures, not a production deployment, external cryptographic review, or an
unaided clean-machine package acceptance run. No running deployment was changed.

The Keycloak template lists exact post-logout destinations using Keycloak's
[multivalue configuration delimiter](https://github.com/keycloak/keycloak/blob/main/server-spi-private/src/main/java/org/keycloak/models/Constants.java).
