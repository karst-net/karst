# Keycloak login theme

`themes/karst/` is a Karst-branded theme for Keycloak's sign-in pages
(login, password reset, OTP, WebAuthn, error pages -- everything Keycloak
renders before handing a user back to the console or portal). It uses the
same Cave palette, DM Sans / Fraunces type, wordmark and otter field-guide
avatar as the console and [karst-net.github.io](https://karst-net.github.io),
in both light and dark mode (following the browser's `prefers-color-scheme`).

It is a **styles-only child of Keycloak's built-in `keycloak.v2` theme**:
no `.ftl` template is copied or overridden, so Keycloak upgrades keep their
own markup, scripts, translations and fixes. Everything Karst-specific is in
`login/resources/css/karst.css` and two images.

| File | Purpose |
| --- | --- |
| `themes/karst/login/theme.properties` | Extends `keycloak.v2`, layers `karst.css` over its stylesheet. |
| `themes/karst/login/resources/css/karst.css` | Maps the Cave tokens (`web/packages/tokens/theme.css`) onto PatternFly's variables. Keep the two in sync. |
| `themes/karst/login/resources/img/otter.png` | Otter avatar, from karst-net.github.io's `assets/karst_otter_head.png`. |
| `themes/karst/login/resources/img/karst-logo.png` | Wordmark, from the same site's `assets/karst_logo.png` (matte edges trimmed). Drawn as a CSS mask, so it takes the text color in either mode. |

Only a **login** theme is provided. Do not set it as the server-wide default
(`KC_SPI_THEME__DEFAULT` / `--spi-theme--default`): that default applies to
every theme type, and with no `admin` or `account` variant here, the admin
and account consoles fail with HTTP 500.

## Enabling it

Both production deployments mount the directory read-only at
`/opt/keycloak/themes/karst`:

- Compose: `deploy/compose/prod/docker-compose.yml` (relative to the checkout).
- Nomad: `deploy/nomad/prod/karst.nomad.hcl`, from the `keycloak_theme_dir`
  variable -- an absolute host path, like `jobspec_dir`.

Mounting makes the theme available; a realm opts in through its
`loginTheme`. New deployments get that from
`deploy/compose/prod/keycloak-realm.template.json`. An **existing** realm is
not re-imported (`--import-realm` skips realms that already exist), so set it
once on the running Keycloak after the theme is mounted:

```sh
docker exec -it <keycloak-container> sh -c '
  /opt/keycloak/bin/kcadm.sh config credentials \
    --server http://localhost:8080/auth --realm master --user admin &&
  /opt/keycloak/bin/kcadm.sh update realms/karst \
    -s loginTheme=karst -s displayName=Karst'
```

(`kcadm.sh` prompts for the master admin password.) Equivalently, in the
admin console: **karst realm → Realm settings → Themes → Login theme →
karst**. To revert, set the login theme back to `keycloak.v2` (or clear it);
no restart is needed either way.

## Editing

Under `start-dev` (which both deployments use) Keycloak doesn't cache theme
resources, so edits to the mounted files show up on the next page load. A
throwaway instance is the quickest way to preview changes without touching a
live realm:

```sh
docker run --rm -p 127.0.0.1:18080:8080 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  -v "$PWD/deploy/keycloak/themes/karst:/opt/keycloak/themes/karst:ro" \
  quay.io/keycloak/keycloak:26.4 start-dev --http-relative-path=/auth
```

Then open <http://127.0.0.1:18080/auth/admin/>, set the master realm's login
theme to `karst`, sign out, and view the sign-in page. Check light and dark
mode and a ~390px-wide viewport.
