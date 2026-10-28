<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Co-located deployment, under Nomad

The same deployment [`../compose/`](../compose/README.md) documents --
one coordination server and one relay, sharing one `./state` -- run under
HashiCorp Nomad instead of `docker compose`. This is an additional supported
path, not a replacement: `deploy/compose/` is unaffected and still the
simplest way to try karst on one machine. Reach for this directory if you
already run Nomad (for example, alongside other workloads on a shared host)
and would rather manage karst the same way.

```sh
cd ../compose && ./bootstrap.sh # same as the compose README, once
nomad job run karst.nomad.hcl   # control + relay
```

`bootstrap.sh` is orchestrator-agnostic -- it only ever does standalone
`docker run`, never touches compose -- so there is nothing Nomad-specific to
set up before running it.

## What's different from the compose path

- **The base job (`karst.nomad.hcl`, control + relay only) uses host
  networking** for both tasks -- there's no third service for either to
  collide with, so this is the simplest option.
- **`prod/` splits networking instead**, because it has two services
  (control, keycloak) that must stay unpublished and two (relay, caddy) that
  must own a real host port, and both control and caddy default to listening
  on the same internal port (33073) -- host networking for everyone would
  make them collide. See `prod/karst.nomad.hcl`'s own header comment for the
  split and the pre-created `docker network create karst` it depends on.
- **Variables instead of `.env`.** `deploy_dir` (and, in `prod/`,
  `shared_state_dir`/`prod_dir`/`repo_root`/`jobspec_dir`) replace compose's
  `${VAR}` substitution from a cwd-local `.env` file. Pass them with
  `-var`, e.g. `nomad job run -var deploy_dir=/srv/karst karst.nomad.hcl`.
  Nomad docker volumes need absolute host paths -- there's no equivalent of
  compose's convenient cwd-relative `./state`.

## `prod/`

[`prod/karst.nomad.hcl`](prod/karst.nomad.hcl) is the Caddy + Keycloak,
single-externally-forwarded-port shape documented in
[`../compose/prod/`](../compose/prod/docker-compose.yml) -- a real
production deployment shape (TLS termination up front, real OIDC via
Keycloak, image digests pinned to a cosign-verified release), not disposable
test infrastructure. It's written to reuse an *existing* `deploy/compose/`
deployment's state in place: point its variables at that deployment's
directories and there is no data to migrate, the same way switching between
compose releases never needs one.

[`prod/Caddyfile`](prod/Caddyfile) keeps the same edge routes as Compose,
but proxies its catch-all to the console container. The portal and release
files remain host-mounted. See [console rollout](prod/README.md) for image
verification, deployment, smoke checks, and rollback.

## Component model

Same note as the compose README: [ADR-0056](../../docs/adr/0056-four-component-families.md)
defines four component families (node agent, transport infrastructure,
control services, trust tooling) that this deployment's services fit without
any changes needed for either orchestrator.

## A different, unrelated "Nomad" in this codebase

This repo also has a `Nomad` *Infrastructure Connection type*
(`server/management/internals/karst/infraconnections/nomad.go`) -- karst's
own scaler treating a Nomad cluster as a placement *target* for discovery.
That is a different concern from this directory, which runs karst's own
control-plane services *under* Nomad as the orchestrator. The two aren't
related beyond sharing a name.

## Verifying a release image

See [`../compose/README.md`](../compose/README.md#verifying-a-release-image)
-- identical procedure, since the images themselves don't change based on
which orchestrator runs them.
