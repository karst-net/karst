<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Billing upgrade and rollback guide

Billing data collection is opt-in. Installing a release with billing support
does not assign a rate schedule, enable device collection, configure a relay
producer, set a relay cap, or enroll an account with Paddle. A self-hosted
deployment with no billing configuration keeps its existing membership and
forwarding behavior.

This procedure is for a future managed-billing pilot. Billing is not generally
available, and live Paddle collection remains behind separate onboarding and
market/tax gates.

## Before upgrading

1. Back up the management database and verify that the backup can be restored.
   Keep the existing backup and restore procedure for the deployment.
2. If relays already retain usage spools, back up their configured spool
   directories as part of the existing relay-state procedure. Do not change
   relay spool paths during this upgrade.
3. Review the release notes for the management database driver and migration
   requirements. Billing uses additive SQL tables created during management
   bootstrap. Device and relay usage stores also create their own tables.
4. Keep billing collection, schedule assignment, spending caps, and Paddle
   collection disabled during rollout. Do not add billing environment
   variables or run billing configuration commands as part of installation.

## Upgrade sequence

1. Stop changes to the management deployment if required by its normal database
   migration procedure, then roll out the release to every management replica
   sharing the database.
2. Let each replica complete normal startup and migration. Every replica that
   can write account membership must run the device-usage hooks before device
   collection is enabled; a mixed-version writer can otherwise create an
   interval the ledger cannot observe.
3. Confirm management health and existing peer membership before resuming
   normal writes. The migrations create billing and usage storage but do not
   populate rate assignments, caps, Paddle account mappings, or historical
   device intervals.
4. Leave accounts unassigned unless they are deliberately entering an
   approved shadow or billing pilot. Configure usage producers and account
   mappings separately using the operator procedures in
   [managed billing pilot readiness](managed-billing-pilot.md).

Device usage collection starts when an operator explicitly enables it for an
account. It can observe the devices already enrolled at activation and all
subsequent lifecycle changes. It cannot reconstruct earlier enrollment and
revocation times. Do not invoice a period that predates complete device and
relay coverage; incomplete periods remain open and unbilled.

## Checks after upgrade

For an unconfigured deployment, verify that existing devices can still connect,
direct peer traffic and relayed traffic retain their previous behavior, and no
account has a billing schedule or relay cap configured. No Paddle collection
should be possible without the explicit global provider enablement and
per-account customer/product mapping. Keep payment collection in sandbox until
separate live-selling gates are approved.

The regression suite includes checks that an account without a schedule cannot
produce an invoice, disabled device collection writes no lifecycle usage, an
unconfigured payment account makes no provider request, and an unconfigured
relay forwards without the spending-cap gate. These checks support the
default-off guarantee; they do not replace a restore rehearsal on the target
deployment's database and release.

## Rollback

Use the normal application rollback process if the upgraded management release
must be reverted. The billing schema changes are additive, and no automatic
reverse migration is provided. Do not manually drop usage or billing tables.
If restoring the pre-upgrade database backup is necessary, account for all
management writes made since that backup; restoring it discards those writes as
well as any usage data collected after the upgrade. Do not enable billing for
an account until the rollback window has closed and every membership-writing
replica is on a compatible release.
