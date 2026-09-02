# User portal — `karst-portal`

**PLAN.md §8.2 · W7–W9 · Frontend 2, after the console's second engineer rolls
off the read-only views.**

## 1. Scope, which is the whole design

> **Re-baselined 2026-08-27; data contract closed 2026-08-28.** The portal
> exists and has subject-derived device list, one-time enrollment key,
> rename/revoke, access explanation, session, and download views.
>
> The four contract gaps this note listed are closed. Device platform comes
> from the client's reported GoOS. Session history is a real record of
> control-channel connections — `node.DeviceSession`, written around the
> authenticated part of the stream — with a genuine end time, a genuine
> address, and a null end meaning "still connected" rather than "unknown"
> (GitHub issue [#68](https://github.com/karst-net/karst/issues/68)). The download manifest is generated from the artifacts a
> release actually contains and lists every build for the platform, since the
> client now ships four Linux packages (GitHub issue [#70](https://github.com/karst-net/karst/issues/70)). The enrollment
> instruction already matched the daemon's configuration flow.
>
> Two things surfaced while closing them and are worth carrying forward: the
> portal's Playwright suite had never run in CI (GitHub issue [#69](https://github.com/karst-net/karst/issues/69), now wired in),
> and the session address is the proxy's address behind a reverse proxy, which
> the schema states rather than implying a device location the server cannot
> know.

§8.2: "Deliberately small: download the client for your platform, see and name
your own devices, run the add-device flow, revoke a lost device, view which
network resources you can reach and why, and see your own session history.
**Nothing an end user can do here should be able to affect anyone else.**"

Six capabilities. The last sentence is the specification; everything else is
layout.

| # | Capability | Endpoint | Notes |
|---|---|---|---|
| 1 | Download the client | Static, from the release artifacts | Detect the platform, offer the right installer, show the checksum and how to check it |
| 2 | List and rename own devices | `GET/PATCH /api/karst/v1/me/devices` | Rename is the only mutation on a device besides revoke |
| 3 | Add a device | `POST /api/karst/v1/me/devices/enroll` | Issues a short-lived, single-use, non-reusable auth key scoped to the user |
| 4 | Revoke a device | `DELETE /api/karst/v1/me/devices/{handle}` | Must actually drop sessions, not just mark a row |
| 5 | What can I reach, and why | `GET /api/karst/v1/me/access` | See §3 |
| 6 | Own session history | `GET /api/karst/v1/me/sessions` | From the audit log, filtered to the caller |

## 2. Contract amendment

**None of the `/me/` endpoints are in [03](03-control-api.md) §5.** They must be
added before the W2 contract freeze, not in W7 when the portal starts. Flag
this at the W1 endpoint inventory — it is the most likely thing in the phase to
be forgotten until the week it blocks someone.

`/me/` is a separate namespace from the admin resources on purpose. Every
handler under it derives the subject from the authenticated token and **never
from a path or query parameter.** Not "check that the requested user matches
the token" — do not accept a user parameter at all. The former is one missing
`if` away from an IDOR; the latter cannot express one.

## 3. "Why can I reach this?"

The interesting feature and the one that will get used. The user's compiled
packet filter already exists — it ships in their nodes' netmaps — so the data
is there. The work is explanation: for each reachable destination, name the
ACL rule and the group membership that produced it.

`karst/policy` compiles a document to a filter. To explain, it needs to carry
provenance through the compile: each emitted rule tagged with the source rule's
index and the `src`/`dst` terms that matched. That is a change **in the
compiler**, in Go, and it is worth doing regardless — the console's preview
diff ([04](04-admin-console.md) §5.1) wants the same provenance to say *which*
rule changed, and the admin-side "why can node A reach node B" debugging
question is the same query from the other end.

**Schedule the provenance work with the policy endpoints in W3–W4, not with the
portal in W7.** Two consumers, one change, done early.

Present it plainly: "**`db-prod:5432`** — because you are in **`group:sre`**,
via rule 4 of the access policy (last changed 12 Nov by alice@)." A user who
cannot reach something they expect to reach should be able to screenshot this
page and send it to an admin, and the admin should be able to act on the
screenshot alone.

## 4. Deployment and boundary

Same origin as the console or a different one? **Different path on the same
origin, different route tree, different bundle.** A separate origin needs a
second TLS name and a second CORS story for a self-hoster to get right, and the
self-hoster is the audience. Sharing an origin is safe here because the
security boundary is the API's authorization, not the browser's — the portal
bundle being reachable by an admin, or vice versa, is not a vulnerability.

What is a vulnerability is the portal calling an admin endpoint successfully.
Which leads to the test.

## 5. Testing

One Playwright suite per capability, and one test that matters more than the
rest:

**The Member-role hostility test.** Authenticate as a Member and issue a
request to every admin route in the router — the same generated route table
[03](03-control-api.md) §6 uses for the role matrix — asserting 403 on all of
them. Then repeat with the Member's token against another user's `/me/`
resources by forging the path where one exists, asserting 404 rather than 403
(a 403 confirms the resource exists, which is a small disclosure and a free one
to avoid).

Plus:

- Revoking a device drops its live session within 60 seconds, asserted against
  a real node in the nightly compose run — the same 60-second requirement
  PLAN.md §4.4 sets for deprovisioning, because a user revoking their own
  stolen laptop is the more urgent case.
- The enrollment key issued by the add-device flow is single-use: use it twice,
  assert the second attempt fails.
- axe on every route; keyboard-only completion of the add-device flow.

## 6. Schedule

| Week | Work |
|---|---|
| W7 | Shell, auth, device list, rename, download page |
| W8 | Add-device flow, revoke, session history |
| W9 | Access explanation view, a11y sweep, hostility test |

## 7. Exit criteria

1. A Member can add a device, name it, and revoke it, and cannot do anything
   else — proved by the route-table hostility test, not by inspection.
2. Revocation drops the session within 60 seconds.
3. The access view names the rule and the group for every reachable
   destination.
4. The download page offers the correct installer per platform with a checksum
   the docs explain how to verify.
