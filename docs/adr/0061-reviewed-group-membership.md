<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-0061: Reviewed membership and conditional group edits

- **Status:** Accepted
- **Date:** 2026-10-25
- **Deciders:** Project owner direction in #439
- **Related:** ADR-0058, ADR-0060

## Context

Membership controls who can use form-managed resources. The console saved a
selection immediately, and fetched the latest group just before saving. That
preserved a newer name but could overwrite membership changed by another
administrator after the editor opened. Renaming also sends membership and
resource assignments in the inherited replacement API.

## Decision

Review named machines gaining and losing group access and the group's resource
assignments before applying membership changes. Reuse the dependency inventory
from deletion review. Acknowledgment is required. Reload assignments before
applying; changed impact requires another review. Explain that other groups and
legacy rules can independently allow access and that relay revocation converges
through its roster refresh. Preserve client exit consent and Gateway readiness.

GET of a single group returns an opaque ETag over its write-relevant account,
identity, name, source, integration reference, membership and resources. Set
ordering does not change the revision. Console membership and rename writes
send that revision in If-Match and preserve the originally opened assignments.
The account manager compares it after loading the group with an update lock in
the mutation transaction, before writing membership, serials or audit events.
A mismatch returns 412. The console keeps the rejected draft and requires an
explicit reload instead of retrying against a newer revision automatically.

The optional header preserves existing API clients. The console refuses edits
when a server does not provide revisions. Update the API schema and generated
parameter model. No persisted group schema or wire-body migration is needed.

## Alternatives rejected

- Fetching just before save still replaces changes the administrator never saw.
- A client-only comparison has a race between checking and writing.
- A mandatory header breaks inherited clients and integrations immediately.
- Cascading resource policy edits on membership change would duplicate the
  existing runtime resolution of current group membership.

## Costs and limits

Review adds account-scoped reads and may be blocked by an unavailable source.
The assignment list covers console-supported forms, not a complete effective
access calculation of every inherited policy. Dependency reads and a group edit
are not one transaction across APIs. Existing clients without If-Match retain
their previous update semantics; this is not a universal revision protocol for
all membership producers. Digests identify state rather than a monotonic event
sequence. Existing native membership audit and network-update paths remain in
use; this change does not alter packet enforcement or convergence intervals.
