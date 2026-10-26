<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Co-located deployment: a coordination server and a relay

One host, one `docker compose up`, a working Karst network. This is the
deployment PLAN.md §5 makes the default, and the reason it is the default is
bandwidth: a self-hoster who relays their own traffic is not spending anyone
else's.

```sh
cd deploy/compose
KARST_RELAY_IP=203.0.113.7 ./bootstrap.sh     # once
docker compose up -d
docker compose logs control | grep 'karst: server'
```

`KARST_RELAY_IP` is the address **nodes will dial**. Use the host's public IP
for a real deployment, or `127.0.0.1` to try it on one machine. It must be an
IP address, not a DNS name — see [Why the address is an IP](#why-the-address-is-an-ip).

## What you get, and what you still have to do

Up: a coordination server on `:33073` and a relay on `:443`, sharing
`./state/`. The relay admits exactly the nodes enrolled with that server, and
every node is told about exactly that relay.

Not done for you: **enrolling nodes**. A node needs a setup key, and issuing one
needs an account, which needs the admin console — Phase 5. Until then this
artifact stands up the infrastructure; it does not finish the walk-through.
Saying so here rather than letting you discover it after the third command.

Each node also needs three things from this deployment, all printed by
`bootstrap.sh` and the startup logs:

| Node config | Where it comes from |
|---|---|
| `[control] server_kem_pin` | `docker compose logs control \| grep 'server KEM pin'` |
| `[control] server_verify_pin` | `... \| grep 'server sign pin'` |
| `[control] relay_ca_file` | `./state/tls/relay.crt`, because the certificate is self-signed |

Both pins are required. `karst-control-v1.md` §9 explains why a node given only
the first still connects but silently loses forward secrecy — which is a worse
outcome than an error.

## The two files, and why a deployment needs both

They are counterparts, they have similar names, and having only one of them is
silent in both directions:

| File | Written by | Read by | Says |
|---|---|---|---|
| `state/roster.toml` | `karst-control`, every 25s | `karst-relay` | which nodes this relay admits |
| `state/relays.json` | `bootstrap.sh`, once | `karst-control` | which relays nodes are told about |

With only the roster, the relay admits nobody who ever arrives — because no node
was ever told the relay exists. With only the registry, every node dials a relay
that refuses them. Neither failure logs anything resembling its cause, which is
why `bootstrap.sh` writes both or neither, and why the server now warns at
startup when the registry is empty.

### The roster is rewritten forever, on purpose

`karst-relay` treats a roster nobody is maintaining as untrustworthy: its lease
is **90 seconds**, and when the file stops changing the relay replaces admission
with an empty roster and stops admitting anyone. That is correct for a
membership list, and it means something must rewrite the file forever.
`karst-control` does, every 25 seconds — three attempts inside each lease, so a
transient failure costs nothing.

The rewrite is unconditional. The relay's freshness fingerprint is (contents,
mtime), so a writer that only wrote on change would leave exactly the stable,
working deployments failing closed after ninety seconds.

You can watch both halves of this:

```sh
# the file's mtime moves every 25s while its contents do not
watch -n5 'stat -c "%y %s" state/roster.toml'

# stop the producer and the relay fails closed at 90s, then recovers
docker compose stop control
docker compose logs -f relay        # "roster lease expired" after ~90s
docker compose start control        # "roster reloaded"
```

## Why the address is an IP

`relays.json` carries `address` and `tls_server_name` as separate fields.
`address` is parsed by `karstd` with Rust's `SocketAddr`, which does not resolve
names, so a DNS name there produces a netmap **every node rejects in full** —
not one relay they skip. The name belongs in `tls_server_name`, which is what
the certificate must match. `KARST_RELAY_SERVER_NAME` sets it; the default is
`relay.karst.local`.

This is also why the registry is validated when the server starts rather than
when a node fetches: one malformed entry fails the whole netmap, and a startup
error naming the field beats every node failing to apply a netmap it just
authenticated.

## The certificate is self-signed, and that is fine

`ponor-v1.md` §4.2 declines to trust certificates for relay identity at all — a
node authenticates a relay by the ML-DSA-65 key pinned in its netmap. The
certificate only has to get a TLS session established. Replace it with a
CA-issued one if you prefer; it changes nothing about who the relay is proved to
be, only which certificates the hop will accept.

## The policy is allow-all

`bootstrap.sh` writes `state/policy.json` permitting every node to reach every
other node on every port, and prints a line saying so. The alternative default
is worse in a different way: an absent policy compiles to an empty filter, which
is **default deny**, and a first deployment where nothing passes looks broken
rather than locked down. Narrow it before you rely on it — the format is
PLAN.md §4.3.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `KARST_RELAY_IP` | *(required)* | Address nodes dial. IP, not a name |
| `KARST_RELAY_PORT` | `443` | Host port for the relay; must match what nodes dial |
| `KARST_RELAY_SERVER_NAME` | `relay.karst.local` | TLS name and certificate subject |
| `KARST_CONTROL_PORT` | `33073` | Host port for the coordination server |
| `KARST_AQUIFER` | *(unset)* | Optional deployment-namespace prefix on the per-account forwarding scope (§5.4, ADR-0033) — not required for isolation itself |
| `KARST_REGION` | `default` | Relay region (§8, §9) |

## Component model

[ADR-0056](../../docs/adr/0056-four-component-families.md) defines four families:
node agent, transport infrastructure, control services and trust tooling. The
Relay component is transport infrastructure's only member — ADR-0056's
addendum dropped the standalone TURN fallback this deployment used to also
support, in favor of the co-located relay alone. The
[Relay deployment adapter](#relay-deployment-adapter) uses one manifest to
manage the reference Compose process. Gateway subnet/exit forwarding is a
capability of an enrolled node.

`bootstrap.sh` is idempotent: every step skips if its output exists, so
re-running it after a partial failure finishes the job rather than replacing a
relay identity that every node has already pinned.

## Notes

- **`NB_DISABLE_GEOLOCATION` is set for a reason.** Without it, first start
  fetches GeoLite2 databases from a third-party mirror before serving
  anything, and a bad download is fatal — a dependency this deployment has no
  use for and should not be able to break it.
- `./state/` holds private keys and is in `.gitignore`. Back it up; losing the
  server keys breaks every enrolled node at once, because nodes pin them.
- `state/management.json` is mounted read-write on purpose. The daemon writes a
  generated store encryption key back into it on first boot, and mounting it
  read-only stops the server before any store is created.

## Building the images

```sh
cd ../..
docker build -f deploy/images/karst-control.Dockerfile -t ghcr.io/karst-net/karst-control:dev .
docker build -f deploy/images/karst-relay.Dockerfile -t ghcr.io/karst-net/karst-relay:dev .
```

## Verifying a release image

Release images are keylessly signed by the `deliverables.yml` workflow in
`karst-net/karst`. Verify the signature before deploying, and then use the
verified digest rather than a mutable tag.

**The `karst-control`/`karst-relay`/`karstd` GHCR packages are currently
private**, confirmed via `gh api /orgs/karst-net/packages/container/<name>`,
despite this repository being public — an outside self-hoster following this
section as written has no credentials to `docker login` with and gets
`unauthorized` on `docker pull`. This needs to be flipped to public (or
documented as requiring an access grant) before the procedure below works for
anyone outside the org; it is not a client-side or docs-only problem.

```sh
image=ghcr.io/karst-net/karst-control
tag=v0.1.0 # replace with the release tag
# Not `docker buildx imagetools inspect --format '{{.Digest}}'`: current
# buildx (confirmed on 0.30.1) errors `can't evaluate field Digest` — there
# is no top-level `.Digest` in the template data, only per-platform
# manifests. `docker pull` then `docker inspect` gets the same multi-arch
# index digest without depending on buildx's template shape at all.
docker pull "$image:$tag"
digest=$(docker inspect "$image:$tag" --format '{{index .RepoDigests 0}}' | cut -d@ -f2)

cosign verify \
  --certificate-identity-regexp 'https://github\\.com/karst-net/karst/\\.github/workflows/deliverables\\.yml@refs/tags/v.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "$image@$digest"

docker pull "$image@$digest"
```

Run the same procedure for `karstd` and `karst-relay`. A development image
tagged `:dev` is a local build and is intentionally not a release claim.


## Relay deployment adapter

`relay-service.py` (Python 3.11+, Docker Compose v2) manages the Ponor process
from `relay-service.toml`. It targets this reference Compose layout, not the
production/HA or Kubernetes stacks. Existing `bootstrap.sh`, `docker compose`
commands and profiles remain valid. The adapter never rotates identity keys,
TLS material, shared secrets, registry files or allocation ports.

For a new managed deployment, run `bootstrap.sh`, review its policy, quotas,
listening addresses and firewall settings, then start control. Bootstrap is
idempotent for existing material. Copy and edit the shared manifest:

```sh
cp relay-service.toml.example relay-service.toml
docker compose up -d control
./relay-service.py plan
./relay-service.py apply --acknowledge-process-change
./relay-service.py status
```

For an existing deployment, retain a backup of `state/` and `.env` using your
normal secret-safe backup process; copy the example manifest and explicitly
match the running mode before the first apply. `plan` validates required
bootstrap material and control's configured file paths. It prints only the
desired mode and commands, without resolved environment or secrets. A
manifest with unknown fields or a missing boolean fails instead of disabling
the mode implicitly. `plan` does not contact Docker or test network readiness.

`apply` validates the Compose configuration, starts enabled managed processes
with `--no-deps`, then stops disabled local processes. Control must already be
running; the adapter does not restart it. It never runs `down`, removes volumes,
or stops control. If a command fails, earlier commands may have completed;
inspect `status` and fix the failure before retrying. Apply is idempotent, not
transactional. Do not run concurrent applies or edit the manifest while applying.
Docker retains its ordinary image-pull/start behavior; pin images according to
your deployment's release policy.

A successful apply saves `state/relay-service.applied.toml` and retains the prior
successful manifest as `state/relay-service.applied.toml.previous`, both mode
0600. For process rollback, review/copy that previous manifest to
`relay-service.toml`, run `plan`, then apply again. Failed applies do not record
success. The snapshots contain desired mode configuration, not database or
secret backups. Original bootstrap and Compose commands remain usable when
rolling back to tooling without this adapter.

### Process modes and account publication

Local process state and account publication are distinct. Before stopping the
mode, withdraw the relevant endpoints through the control **Relay Services**
mode/publication controls and allow agents to refresh their netmaps. Coordinate
all accounts using the shared process; disabling the association does not mean
the backend is unused. Review fallback availability and active allocation loss,
then apply the deployment manifest. On enabling, start/check the process first,
then activate publication after admission observations succeed. Neither the
script nor its acknowledgment changes membership, policy, local Gateway
consent or control's publication authority. See
[Relay Services](../../docs/relay-services.md) for version gates and rollback.

Status exposes the Ponor process's state. Running containers with no
healthcheck report `unprobed`, not healthy. Use control's fresh Ponor
admission observations for readiness; deployment state does not prove
credential acceptance, permissions/channel bindings, network reachability, or
end-to-end encrypted transit.

Run the adapter tests with:

```sh
python3 -m unittest discover -s deploy/compose -p test_relay_service.py -v
# Also exercise real Compose start/stop/re-enable in an isolated project.
# Requires local alpine:latest; containers are harmless process stand-ins.
KARST_COMPOSE_LIFECYCLE_TEST=1 python3 -m unittest discover -s deploy/compose -p test_relay_service.py -v
```

## Console-generated Relay installation/configuration handoff

For an existing reference deployment with trusted Relay TLS material, the admin
console's **Relays → Install a local relay** supplies a Python installer. This
replaces manual Relay TOML and admission-writer environment editing for the
supported local case. It supports one control replica and one co-located Relay
on Linux, with Python 3.11+, OpenSSL and Docker Compose v2. It does not create a
new control deployment or distribute TLS trust to nodes.

Use the existing endpoint address, TLS name and region when adopting a bootstrapped
Relay. In Runtime settings choose compatible Karst control/Relay images; preload
or pull those images first if needed. The installer probes the selected control
image for `managed-roster-v1` before changing runtime state. Older images fail
explicitly. Image tags are not a capability guarantee; digests are preferable
for repeatable deployment. The installer does not upgrade an unsupported image
by silently changing the requested version.

```sh
python3 karst-relay-install.py --directory /srv/karst/compose
python3 karst-relay-install.py --directory /srv/karst/compose --apply
```

The first command checks prerequisites; apply generates the files and restarts
control and Relay. It preserves management credentials, policy, registry, Relay
seed and trusted TLS material. It stops the old writer before replacing the
roster. The generated writer uses `KARST_RELAY_REQUIRE_MANAGED=true`: tenants
without managed backend access are denied, including during the installation /
registration / group-configuration gap. Adopting an unrestricted Relay therefore
interrupts its legacy access. Existing managed grants are evaluated normally.

Import the generated `state/relay-install/receipt.json` in the console's Add relay
form. It contains public metadata only, not enrollment or administrator tokens.
Review registration, choose groups and optional egress, then inspect operational
observations. `runtime_started` in `state/relay-install/status.json` means that
containers reported running, not that admission, a saved revision or traffic was
verified. `failed` means earlier actions may have completed. Diagnose locally and
rerun the same handoff; no automatic rollback reinstates broad access. Different
settings require an explicit migration, not a retry.

Keep the generated overlay in every subsequent lifecycle command:

```sh
docker compose --project-directory /srv/karst/compose \
  -f /srv/karst/compose/docker-compose.yml \
  -f /srv/karst/compose/state/relay-install/compose.json ps
```

Use the same prefix for `logs`, `up` and `stop`. The `relay-service.py` process adapter automatically includes this overlay when
it exists, preserving the installed writer configuration. Removing managed-only mode, reverting to a legacy
writer or downgrading control can reopen admission. The overlay is private local
state; do not publish it with deployment credentials. Custom inherited ports,
mounts, execution settings, multiple writers and mismatched registries are
rejected rather than silently altered. Remote roster delivery, provider workload
provisioning and Gateway agent installation remain unsupported by this handoff.
