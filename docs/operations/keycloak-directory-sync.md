# Keycloak directory lookups for the console (issue #432)

Both user sync (steps 1-3) and group sync (step 4) have been run end to end
on a real Nomad deployment and confirmed working: `control` picked up
Keycloak users via the Admin API, and a Keycloak group membership showed up
in `/groups` as `issued: jwt` after a fresh login. The gotchas and fixes
below came directly out of that run, not from re-reading the code.

The console's OIDC login and the management server's IdP adapter are **separate**
integrations. In the production Compose deployment, login uses the **karst**
realm through Caddy at `/auth`. This procedure opts the *control* process
into querying users from **that same realm**. It does not change console OIDC
or create users, and steps 1-3 alone do not turn Keycloak into a source of
Karst ACL groups — that is the separate, optional group-sync setup in step 4.

## 1. Prepare the existing Keycloak realm

Use the Keycloak administrator UI on the existing deployment to create a
**confidential** OpenID Connect client named `karst-directory-sync` in
the **karst** realm. Enable client authentication and service accounts;
disable standard and direct-access login flows for this machine client.
Under **Service account roles**, assign only the `realm-management`
roles **query-users** and **view-users**. Grant additional read-only
roles only if the API rejects a needed query; do not assign realm-admin,
manage-users, or manage-realm to the sync client.

Scripting this instead of clicking through the admin UI: `kcadm.sh`
(`/opt/keycloak/bin/kcadm.sh` inside the Keycloak container) does the same
thing non-interactively and is what was actually used to validate this
runbook. Authenticate once per container lifetime, then create the client,
read its secret, and grant the two roles:

```sh
# Authenticate without the password ever touching argv or a log:
cat state/kc-master-admin-password.txt | docker exec -i <keycloak-container> \
  sh -c 'read -r PW; /opt/keycloak/bin/kcadm.sh config credentials \
    --server http://localhost:8080/auth --realm master --user admin --password "$PW"'

docker exec <keycloak-container> /opt/keycloak/bin/kcadm.sh create clients -r karst \
  -s clientId=karst-directory-sync -s protocol=openid-connect -s publicClient=false \
  -s standardFlowEnabled=false -s directAccessGrantsEnabled=false \
  -s implicitFlowEnabled=false -s serviceAccountsEnabled=true \
  -s clientAuthenticatorType=client-secret -i   # prints the new client's id

# Pipe the secret straight to disk; never let it land in your own shell output:
docker exec <keycloak-container> /opt/keycloak/bin/kcadm.sh get \
  clients/<client-id>/client-secret -r karst --fields value --format csv --noquotes \
  | docker exec -i <keycloak-container> tee /tmp/.secret >/dev/null
docker cp <keycloak-container>:/tmp/.secret deploy/compose/prod/state/keycloak-directory-secret.txt
docker exec <keycloak-container> rm -f /tmp/.secret
chmod 600 deploy/compose/prod/state/keycloak-directory-secret.txt

docker exec <keycloak-container> /opt/keycloak/bin/kcadm.sh get \
  clients/<client-id>/service-account-user -r karst --fields id   # service account's user id

docker exec <keycloak-container> /opt/keycloak/bin/kcadm.sh add-roles -r karst \
  --uid <service-account-user-id> --cclientid realm-management --rolename query-users
docker exec <keycloak-container> /opt/keycloak/bin/kcadm.sh add-roles -r karst \
  --uid <service-account-user-id> --cclientid realm-management --rolename view-users
```

If you used the admin UI instead of the `kcadm.sh` block above, copy the
client secret it displayed to a local file on the host:

```sh
umask 077
mkdir -p deploy/compose/prod/state
# Write the client secret to the file using your secret manager/editor,
# not a shell history command.
chmod 600 deploy/compose/prod/state/keycloak-directory-secret.txt
```

**Do not edit or regenerate** `state/keycloak-realm.json` to add this
client. Realm imports are bootstrapping inputs, not a migration mechanism
for a running Keycloak database. Protect the secret in backups and do not
commit either it or `management.json`.

## 2. Generate the control-side configuration

From the repository root:

```sh
python3 deploy/compose/prod/configure-keycloak-idp.py \
  --management deploy/compose/state/management.json \
  --secret-file deploy/compose/prod/state/keycloak-directory-secret.txt \
  --dry-run

python3 deploy/compose/prod/configure-keycloak-idp.py \
  --management deploy/compose/state/management.json \
  --secret-file deploy/compose/prod/state/keycloak-directory-secret.txt
```

The helper preserves the existing management settings, backs up the original
privately to `management.json.pre-idp-sync`, and refuses to overwrite an
existing non-Keycloak IdP or backup. It deliberately does not rotate any
keys, access live Keycloak, or restart processes. For a separate realm or
Keycloak endpoint use `--realm` and `--keycloak-url` explicitly.
The default `http://keycloak:8080/auth` is **internal** to Compose;
the control container should not rely on the externally published TLS address.
Nomad deployments using the same Docker network can use the same address.

The resulting stanza in `management.json` has the shape:

```json
{
  "IdpManagerConfig": {
    "ManagerType": "keycloak",
    "KeycloakClientCredentials": {
      "ClientID": "karst-directory-sync",
      "ClientSecret": "<secret supplied locally>",
      "GrantType": "client_credentials",
      "TokenEndpoint": "http://keycloak:8080/auth/realms/karst/protocol/openid-connect/token",
      "AdminEndpoint": "http://keycloak:8080/auth/admin/realms/karst"
    }
  }
}
```

This is only the *stanza*; do **not** replace the rest of management.json
with this example. If you have `EmbeddedIdP.Enabled=true`, the management
server gives its embedded provider precedence over `IdpManagerConfig`.
Disable it only after auditing existing identities and migration impact.

## 3. Apply and validate

Back up Keycloak and the management database first. In Compose:

```sh
cd deploy/compose/prod
docker compose up -d --no-deps --force-recreate control
docker compose logs --tail=100 control
```

For Nomad, use the standard reviewed job deployment procedure to restart
the control allocation after updating the host's shared management.json.

Sign in using the *existing* console OIDC flow and inspect **Users**;
compare read-only IdP-sourced records with the identities in Keycloak.
A successful sync logs `N entries received from IdP management` /
`warmed up IDP cache with N entries for N accounts` at `control` startup —
absence of that line, or an authorization error from the Keycloak Admin
API nearby, means the service account's roles or secret are wrong.
Test with a non-admin directory user and verify the correct Karst account and
tenant boundary before relying on provisioning. Do not use a production user
as a deletion test: the adapter implements `DeleteUser` against Keycloak.

**Do not call `control`'s own port directly** (e.g. `http://control:33073`
inside the deployment's Docker network) to script any of this validation.
It multiplexes gRPC and REST on the same plaintext listener, and a plain
REST request sent straight to it — bypassing Caddy — gets routed wrong and
comes back as a generic, misleading auth failure that has nothing to do
with whatever credentials you sent. Always go through Caddy, i.e. the same
`https://<console-host>:33073/api/...` the browser uses (`--resolve` to
pin the hostname if you're hitting it by IP without real DNS).

**Current limitation:** `server/management/server/idp/keycloak.go` can
fetch Keycloak users but does not itself enumerate Keycloak groups or
synchronize Karst group membership — `IdpManagerConfig` only ever drives
the Users view. Group sync is a **separate, orthogonal** Karst feature
(JWT-claims-based group sync, below); configuring `IdpManagerConfig` alone
does not populate Groups. Also, returned directory users do not by
themselves guarantee that account-local user records are created: validate
the actual user lifecycle before promising automatic provisioning.

## 4. Group sync (optional, independent of IdpManagerConfig)

Karst already supports syncing group membership from any OIDC provider's
token claims — this is how every IdP integration in this codebase handles
groups; none of them do it through the Admin-API-style adapter in
`server/management/server/idp/`. It works independently of step 2 above:
you can enable it even without `IdpManagerConfig` set, and it is the
mechanism that makes the console's read-only `issued` group rows
(`web/console/src/views/groups.tsx`) populate from Keycloak.

### 4.1 Add a group-membership claim in Keycloak

Fresh deployments get this automatically: `keycloak-realm.template.json`'s
`karst-console` client now ships a `karst-console-groups` protocol mapper
(type **Group Membership**, claim name `groups`, full path off, added to
both the ID and access token). For an **already-provisioned** realm, add
the equivalent mapper by hand in the Keycloak admin UI, on the
`karst-console` client (not the `karst-directory-sync` client from step 1):
**Client scopes** (or the client's own **Mappers** tab) → add mapper →
**Group Membership** → Name `groups`, Token Claim Name `groups`, Full
group path off, Add to ID token on, Add to access token on.

### 4.2 Enable JWT group sync on the account

The console authenticates API calls with the Keycloak access token, so the
`groups` claim from 4.1 needs `JWTGroupsEnabled`/`JWTGroupsClaimName`
turned on for the account via the accounts API. Fetch the current
settings first and merge in the new fields — this endpoint replaces the
whole settings object, so do not PUT a partial body:

```sh
curl -s -H "Authorization: Bearer $PAT" https://<console-host>/api/accounts \
  | jq '.[0]' > /tmp/account.json

ACCOUNT_ID=$(jq -r '.id' /tmp/account.json)

jq '.settings.jwt_groups_enabled = true | .settings.jwt_groups_claim_name = "groups"' \
  /tmp/account.json \
  | jq '{settings: .settings, onboarding: .onboarding}' \
  | curl -s -X PUT -H "Authorization: Bearer $PAT" -H "Content-Type: application/json" \
      -d @- "https://<console-host>/api/accounts/$ACCOUNT_ID"
```

Sign in through the console afterward and confirm `/groups` shows the
directory's groups as `issued: jwt`, read-only rows. Karst does not apply
those groups to peer access automatically unless `GroupsPropagationEnabled`
is also turned on (same PUT, `.settings.groups_propagation_enabled = true`)
— enable that separately once group membership itself looks correct, since
it changes which groups peers actually get.

Two things that look like bugs but are not, if `/groups` still only shows
`issued: api` rows after this:

- **No groups exist in Keycloak yet, or your user isn't in any.** A fresh
  realm has zero groups defined; `oidc-group-membership-mapper` only emits
  whatever groups the authenticating user actually belongs to, so an empty
  claim syncs nothing. Create at least one group in Keycloak and add the
  user to it before expecting anything to show up.
- **Your browser session predates 4.1/4.2.** The `groups` claim and the
  account's `jwt_groups_enabled` flag only affect *new* tokens. An
  already-open console tab is still running on an old token with neither;
  log out and back in to pick up both.

There is no "configure Keycloak" option when creating a group in the
console, and that's intentional, not a missing feature: a group's `issued`
source is never picked by hand. Groups are either created via the API
(`issued: api`) or materialized automatically from a login token's groups
claim (`issued: jwt`) — see `getJWTGroupsChanges` in
`server/management/server/account.go`.

## Rollback

Restore `deploy/compose/state/management.json.pre-idp-sync` to
`deploy/compose/state/management.json` (while keeping its permissions
private), then restart **control**. This leaves the Keycloak realm and the
console's OIDC login configuration intact. Remove the unused sync client
from Keycloak only after confirming rollback.

To roll back group sync (step 4) independently, repeat the GET/PUT in 4.2
with `.settings.jwt_groups_enabled = false`; this does not touch
`IdpManagerConfig` or require a restart. The groups Keycloak already
created in Karst (`issued: jwt`) are left in place; the console UI refuses
to delete non-`api`-issued groups, so remove them via `DELETE
/api/groups/{id}` if you need them gone rather than just inert.

If `GroupsPropagationEnabled` was on while the group existed, the delete
fails with `group has been linked to user: <id>` — the group is still in
that user's `auto_groups`. Clear it first with `PUT /api/users/{userId}`
(body: that user's current `auto_groups` with the group's id removed,
plus their existing `role` and `is_blocked`; this endpoint replaces the
whole object, same as accounts), then retry the group delete.
