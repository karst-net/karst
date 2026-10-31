<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Console image rollout

The console is built from `web/` and served by nginx; Caddy owns runtime
`/config.json`, authentication, API/gRPC, portal, and release routes. Building
an image never embeds the deployment's runtime configuration or credentials.

## Build and release

For a local build and SPA check:

```sh
docker build -f deploy/images/karst-console.Dockerfile \
  -t local/karst-console:dev web
docker run --rm -p 127.0.0.1:8088:80 local/karst-console:dev
# In another terminal: both responses must contain the same index.html.
curl -fsS http://127.0.0.1:8088/
curl -fsS http://127.0.0.1:8088/settings/devices
```

`deliverables.yml` builds both architectures on normal runs. Release tags
publish `ghcr.io/karst-net/karst-console:<version>` and `:sha-<commit>` as a
multi-platform index, sign its digest using GitHub OIDC, and verify it. Use
the normal repository release process; a local image is not a release.

Resolve the release tag once and verify the resulting immutable reference:

```sh
release=vX.Y.Z
image=ghcr.io/karst-net/karst-console
digest=$(docker buildx imagetools inspect "$image:$release" --format '{{.Manifest.Digest}}')
test -n "$digest"
cosign verify \
  --certificate-identity "https://github.com/karst-net/karst/.github/workflows/deliverables.yml@refs/tags/$release" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "$image@$digest"
```

Record the release, digest, and verification result with the deployment.
Never substitute a local tag for `console_image_digest`.

## Rollout and rollback

Keep a private `deployment.vars.hcl` outside version control containing the
existing deployment variables (host, paths, passwords and control/relay
pins), plus `console_image_digest = "sha256:..."`. Save the previous verified
console digest and vars before changing it. The console, control and
Keycloak use the pre-created Docker network; all groups are pinned to
`node_name` because this deployment's persistent files live on that node.

```sh
nomad job validate -var-file=deployment.vars.hcl deploy/nomad/prod/karst.nomad.hcl
docker run --rm -e KARST_CONSOLE_HOST="$KARST_CONSOLE_HOST" \
  -v "$PWD/deploy/nomad/prod/Caddyfile:/etc/caddy/Caddyfile:ro" \
  caddy:2.10 caddy validate --config /etc/caddy/Caddyfile
nomad job plan -var-file=deployment.vars.hcl deploy/nomad/prod/karst.nomad.hcl
nomad job run -var-file=deployment.vars.hcl deploy/nomad/prod/karst.nomad.hcl
nomad job status karst
```

Inspect the plan: unrelated service images, state mounts and settings should
remain unchanged. Caddy's file must be installed at `jobspec_dir`; reload
Caddy after modifying an existing bind-mounted file, since Nomad does not
track its contents. Confirm all allocations are healthy and the console's
running image is the verified digest.

At the public HTTPS origin, using the deployment CA, check:

- `/` and a console deep link load the application and its JS/CSS assets.
- `/config.json` returns deployment JSON with `Cache-Control: no-cache`.
- `/auth/realms/karst/.well-known/openid-configuration` returns the public issuer.
- An unauthenticated `/api/users` request reaches the API and requires login.
- `/portal/` loads the portal and its assets; `/releases/manifest.json` returns
  the existing download manifest.
- In a browser, sign in, navigate to devices, refresh a deep link, and sign out.

Rollback by restoring the previous verified `console_image_digest` in the
vars file, then repeating plan, run, and smoke checks. This replaces only
the console image and does not change persistent state. Before the first
signed console release exists, leave the existing deployment running;
local build validation alone does not complete a production rollout.

## Observed system versions

The control task already mounts `prod_dir/versions` read-only and reads
`components.json` for **Settings → Software versions**. Populate that snapshot
on the Docker host after a rollout or rollback:

```sh
python3 scripts/compose-versions.py --nomad-job karst --nomad-namespace default \
  --output /path/to/prod_dir/versions/components.json
```

Use the exact job ID, namespace, and the `prod_dir` from your deployment vars.
The collector uses `nomad job allocs -all -json` with read access to that job,
then selects local Docker containers using Nomad's mandatory allocation-ID
label. Optional job-name/namespace Docker labels are not required. Allocation
scope comes from Nomad; releases, source revisions, image IDs, and process
states come from the actual containers/images, not the jobspec's desired image.
See the [Nomad job allocation command](https://developer.hashicorp.com/nomad/commands/job/allocs)
and [Docker driver's allocation label](https://github.com/hashicorp/nomad/blob/main/drivers/docker/driver.go).

This production job pins all groups to one host, so run the collector there.
It does not inspect containers on other Nomad nodes. If the exact job/namespace
has no matching local containers, or a query fails, the previous snapshot is
preserved with its original timestamp. The UI marks old snapshots stale; it
does not contact Nomad or Docker when refreshed. Re-run collection after
service changes, or schedule it on that host if ongoing observations are
needed. Neither the Docker socket nor Nomad credentials are mounted into
control. The snapshot contains no container environment or task configuration.
