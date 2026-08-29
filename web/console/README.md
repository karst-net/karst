<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Karst admin console

Every resource an administrator manages, what can be done to it, and which API
backs it. Two APIs are involved and the split is deliberate: **Karst owns
machines, policy, relays, network lock, posture and audit** on
`/api/karst/v1`; **users, groups, auth keys, routes, resolvers and tokens are
the fork's** on `/api`, reused unchanged (ADR-0009), so that a security fix
upstream is still a cherry-pick.

## Resource and operation matrix

| Resource | List | Create | Edit | Deprovision / revoke | Backing API |
|---|---|---|---|---|---|
| **Machines** | ✅ filter by name, handle, owner, tag | ⚠️ via auth key — see below | ✅ rename | ✅ deprovision | `PATCH`/`DELETE /karst/v1/nodes/{handle}` |
| **Machine paths** | ✅ direct or relayed, per peer | — | — | — | `GET /karst/v1/nodes/{handle}/paths` |
| **Auth keys** | ✅ state, usage, expiry, auto-groups | ✅ type, expiry, usage limit, auto-groups, ephemeral | — *(immutable by design)* | ✅ revoke **and** delete | `/api/setup-keys` |
| **Users** | ✅ role, status, last login | ✅ invite, with role and auto-groups | ✅ role, auto-groups, blocked | ✅ block *(reversible)*, deprovision *(not)* | `/api/users` |
| **Groups** | ✅ members, resources, source | ✅ | ✅ rename | ✅ | `/api/groups` |
| **Access policy** | ✅ full version history | ✅ new version on save | ✅ validate, preview diff, test | ✅ roll back to any version | `/karst/v1/policy` |
| **Relays** | ✅ address, region, admission health | ✅ with client-side address validation | — | ✅ remove | `/karst/v1/relays` |
| **Network routes** | ✅ | ✅ | ✅ including enable/disable | ✅ | `/api/routes` |
| **DNS settings** | ✅ | — | ✅ excluded groups | — | `/api/dns/settings` |
| **Nameserver groups** | ✅ | ✅ | ✅ | ✅ | `/api/dns/nameservers` |
| **Network lock** | ✅ mode, quorum, coverage, signed log, pending requests | — *(signing is offline)* | ✅ off / advisory / enforcing | — | `/karst/v1/bedrock` |
| **Audit log** | ✅ filter by actor and action | ✅ SIEM sink | — *(append-only)* | — | `/karst/v1/audit` |
| **Crypto posture** | ✅ aggregate + per-session, CSV export | — | — | — | `/karst/v1/posture` |
| **Personal access tokens** | ✅ | ✅ | — | ✅ revoke | `/api/users/{id}/tokens` |

## Four things the console deliberately will not do

Each of these is a place where an obvious button would produce a request the
server rejects, or an action that is unsafe to take from a web page.

- **Create a machine.** A machine is not created by an administrator; it enrolls
  itself with an auth key and its own identity key. *Add machine* therefore
  mints a single-use key and shows where to put it, rather than presenting a
  form for a resource the server cannot conjure.
- **Edit a machine's tags, expiry or enabled flag.** `updateNode` accepts a
  name and rejects everything else — *"only name is currently mutable for a
  Karst node"*. The view says so where the fields would otherwise be.
- **Edit a group that came from an identity provider.** The directory is the
  source; the group here is a copy. The row explains this instead of offering a
  button whose rejection an admin cannot act on. The built-in `All` group is
  likewise fixed.
- **Sign anything for the network lock.** Authority keys live on a machine that
  never touches the coordination server — that is the whole point of Bedrock.
  The console shows what is waiting for a signature and what has been signed;
  `karst-bedrock sign` does the rest, offline.

## Two guard rails worth knowing about

- **A relay address must be an IP and port.** `karstd` parses it with Rust's
  `SocketAddr`, which does not resolve, so a DNS name there is not one broken
  relay — it is a netmap **every node rejects in full**. The form refuses it
  before it is sent and points at the TLS server name field instead.
- **The network lock's acknowledgment is required only for *enforcing*.**
  Advisory and off cannot cut anyone off, so they are one click. Gating them
  behind the same acknowledgment would make the safe direction harder than the
  dangerous one, which is backwards during an incident.

## Not yet exposed

Present in the fork's API, no view here yet, and each needs a product decision
before it gets one: identity-provider connectors, user invitation links,
NetBird's newer `networks`/`routers` model, posture checks, temporary peer
access, and account-level settings. Single sign-on and SCIM are configured in
`management.json` on the server, not here — they are startup configuration, and
a console that pretended to own them would be editing a file it cannot read.

## Running it

```sh
just api-mock                                   # the frozen contract, at :4010
cd web && corepack pnpm --filter @karst-net/console dev
```

The mock serves both APIs, so every operation in the matrix above can be
exercised without a coordination server. Its fixture is deliberately not a
happy path: fifty machines across paginated results, mixed post-quantum
posture, a stale relay, a Bedrock request one signature short of quorum, and an
audit chain that fails verification.

Against a real server, serve `dist/` and proxy `/api` to `karst-control` on
33073. Every route is behind the management server's authorization middleware,
so this needs an OIDC provider configured first — see
[docs/GETTING-STARTED.md](../../docs/GETTING-STARTED.md) §7.

```sh
corepack pnpm --filter @karst-net/console test      # unit
corepack pnpm --filter @karst-net/console test:e2e  # Playwright, axe on every route
```
