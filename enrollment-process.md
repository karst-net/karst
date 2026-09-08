<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Simplified device enrollment

## Durable objective

A fresh device reaches a working connection through installation and one pasted
invitation, without a user portal login or interaction with an external identity
provider (IdP). Setup handles secure provisioning and service startup automatically.

This document records the agreed target and implementation acceptance criteria.
It describes work to implement, not functionality already delivered.

## Intended experience

1. An administrator clicks **Add device** in the administrative GUI, selects the
   account and permitted access groups, and generates a single-use enrollment
   invitation.
2. The administrator provides the invitation to the intended recipient through a
   trusted channel. The invitation is a credential and must be handled accordingly.
3. The user installs the client and pastes the invitation into its setup screen.
   The invitation carries the server address, server trust information, and
   enrollment credential. No separate IP address or server-key entry is required.
4. The client automatically generates its identity locally, verifies the server,
   registers, saves its configuration, discards the enrollment credential, and
   enables and starts the service. Any necessary operating-system permission
   prompt is part of setup.
5. Setup displays **Connected** once the connection is working, or a specific
   actionable status such as **Waiting for administrator approval**.

There is no user portal login, downloaded configuration to manage, manual file
permission change, manual bundle deletion, or separate daemon-start command.
Administrative authentication remains necessary, but device enrollment requires no
IdP interaction. This objective does not require replacing authentication for the
administrative GUI.

## Security and lifecycle requirements

### Administrator authorization

The invitation is scoped to an account and permitted groups. The administrator
selects policy when creating it; the client cannot select or expand its own access.
Possession authorizes one device and does not establish the recipient's human
identity. Administrator-issued invitations must not depend on the recipient having
an IdP account or completing a member login.

The current member-bound issuer needs an administrator-issued alternative. Retain
server-side authorization checks and the existing separation between enrollment,
network policy, and Bedrock approval.

### Server trust

Authenticate the control server before sending the enrollment credential. Current
public pins are too large for practical manual entry: carry them in the invitation,
or introduce a compact fingerprint that the client verifies against the server's
public trust material before releasing the credential. A compact fingerprint
requires explicit protocol and implementation support.

Never silently trust a key merely because the contacted server supplied it. The
invitation's trusted delivery establishes the initial server trust; a server address
alone is insufficient. Prefer one paste containing all required information over
separate address, key, and credential fields.

### Invitation lifecycle

Invitations must be unique, single-use, expiring, revocable, and visible in the GUI
as pending, redeemed, expired, or revoked. Choose a bounded validity period that
allows realistic delivery and installation time. Record issuance and redemption
for administrative audit without logging the credential.

At redemption, check account and grant eligibility, expiry, revocation, and usage.
Create the device and consume its authorization atomically. Concurrent attempts
must not admit multiple device identities. Bound issuance and redemption attempts.

Treat the invitation as a bearer credential. Keep it out of logs, diagnostic
reports, and persistent client configuration. Discard temporary credential material
after successful enrollment.

### Local provisioning and recovery

Generate and retain private identity keys only on the device. Preserve safe file
permissions, atomic configuration publication, concurrent-enrollment exclusion,
and protection against overwriting an existing installation.

An interrupted connection or partial persistence failure must allow retry with the
same device identity. Successful registration followed by service-start failure
must not require another invitation or create another device. Setup should explain
the failure and offer a retry of the remaining work.

Future connections use the device identity, independently of a topology cache and
without retaining an enrollment credential. Device revocation must not silently
trigger re-enrollment.

### Access readiness

Assign network policy during invitation creation. Registration alone is not proof
of working connectivity. Verify service health and control connectivity before
showing success, and validate usable access in acceptance testing.

If Bedrock approval is required, preserve that approval boundary and explicitly
show the pending state. Explain the required administrator action without sending
the user through another authentication system.

## Implementation direction

- Retain the existing secure redemption, local identity generation, server
  verification, and durable enrollment receipt mechanisms.
- Add administrator-issued, account/group-scoped invitations that do not require
  recipient authentication through the member portal or IdP.
- Define a versioned invitation format carrying address, trust material, and the
  single-use credential, with validation and credential-safe error messages.
- Add the administrative creation, status, and revocation experience.
- Integrate invitation entry and enrollment into client setup. Setup owns the
  entire process through configuration publication, service enablement/start,
  readiness checks, and actionable failure recovery.
- Update onboarding documentation and tests around the simplified experience.
  The previous portal-and-bundle flow is not the target user journey.

## Acceptance criteria

- An administrator can issue and revoke a scoped invitation and see its state.
- A recipient without an IdP account can install, paste one invitation, and reach
  a working connection without opening another system or running shell commands.
- No separate address/key entry, configuration download, permission adjustment,
  credential cleanup, or service-start action is required from the user.
- Wrong server trust, expired/revoked invitations, unauthorized scope changes,
  and second-device reuse are rejected without disclosing credentials.
- Concurrent redemption admits at most one device identity; interrupted setup
  resumes safely with that identity.
- Restart works without an invitation or topology cache, and successful local
  configuration contains no enrollment credential.
- Service-start failures are recoverable without another enrollment; policy or
  Bedrock approval delays are clearly distinguished from a connected state.
- Validate the complete experience on a fresh machine using the packaged client,
  in addition to automated issuance, redemption, installer, and UI tests.
