# Keycloak directory lookups for the console (issue #432)

The console's OIDC login and the management server's IdP adapter are **separate**
integrations. In the production Compose deployment, login uses the **karst**
realm through Caddy at `/auth`. This procedure opts the *control* process
into querying users from **that same realm**. It does not change console OIDC,
create users or turn Keycloak into the source of truth for Karst ACL groups.

## 1. Prepare the existing Keycloak realm

Use the Keycloak administrator UI on the existing deployment to create a
**confidential** OpenID Connect client named `karst-directory-sync` in
the **karst** realm. Enable client authentication and service accounts;
disable standard and direct-access login flows for this machine client.
Under **Service account roles**, assign only the `realm-management`
roles **query-users** and **view-users**. Grant additional read-only
roles only if the API rejects a needed query; do not assign realm-admin,
manage-users, or manage-realm to the sync client.

Copy its generated client secret to a local file on the host:

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
Inspect server logs for authorization failures from the Keycloak Admin API.
Test with a non-admin directory user and verify the correct Karst account and
tenant boundary before relying on provisioning. Do not use a production user
as a deletion test: the adapter implements `DeleteUser` against Keycloak.

**Current limitation:** `server/management/server/idp/keycloak.go` can
fetch Keycloak users but does not implement Keycloak group enumeration or
Karst group membership synchronization. Configuring `IdpManagerConfig`
alone therefore **does not** populate the console Groups view with Keycloak
groups, nor establish Karst ACL group membership. Groups and access rules
must stay explicitly administered in Karst until a separately tested
group-mapping implementation is added. Also, returned directory users do
not by themselves guarantee that account-local user records are created:
validate the actual user lifecycle before promising automatic provisioning.

## Rollback

Restore `deploy/compose/state/management.json.pre-idp-sync` to
`deploy/compose/state/management.json` (while keeping its permissions
private), then restart **control**. This leaves the Keycloak realm and the
console's OIDC login configuration intact. Remove the unused sync client
from Keycloak only after confirming rollback.
