<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# The Kubernetes scaler driver

Operations reference for `karst-scaler-k8s` (ADR-0045 §7 Phase 2 PR 4) — the
first real `Driver` the scaler can actuate through. This is the mechanism
this PR adds; it is not a complete relay-on-Kubernetes deployment guide.
Identity-key persistence, TLS certificate issuance, and roster distribution
for a relay pod are the same operational concerns they already are for any
non-Kubernetes relay deployment — provision them the way your deployment
already does (typically: identity on a per-pod `PersistentVolumeClaim` via
`volumeClaimTemplates`, since regenerating it on every pod restart would
mean the control server's registry entry no longer matches).

## Naming convention this driver assumes

There is no separate configuration for most of this — it is all derived
from `pool_id` (ADR-0045 §1), which is also the `StatefulSet`'s own name:

| Object | Name |
|---|---|
| `StatefulSet` | `<pool_id>` |
| Headless `Service` | `<pool_id>` (same name — `spec.serviceName` points at it) |
| Pods | `<pool_id>-0`, `<pool_id>-1`, ... (Kubernetes's own `StatefulSet` convention) |
| Bundle `Secret` | `<pool_id>-enroll` |
| Bundle `Secret` keys | `<pool_id>-<i>.toml`, one per ordinal |

The headless `Service` and the (initially empty) bundle `Secret` are
**operator-provisioned prerequisites** — the driver's own RBAC
(`deploy/kubernetes/scaler/rbac.yaml`) deliberately has no `services` verb
and no `secrets create` verb. Create both once per pool before the scaler
ever sizes it.

## What `create(n)` actually does

1. Mints `n` relay-enroll tokens (ADR-0045 §7 Phase 2 PR 3,
   `POST /karst/v1/relays/enroll-tokens`).
2. Patches the bundle `Secret`, adding one key per new ordinal — the TOML
   body `karst-relay enroll` reads (`control_api_base`, `token`, `address`,
   `tls_server_name`).
3. Bumps the `StatefulSet`'s `spec.replicas`.

A `Secret` volume projects every key as a file, so the simplest working
pod template mounts the whole bundle `Secret` and has an init container
read its own key by its own stable hostname:

```yaml
initContainers:
  - name: enroll
    image: ghcr.io/karst-net/karst-relay:latest
    command:
      - karst-relay
      - enroll
      - --config
      - /etc/karst/relay.toml
      - --bundle
      - /etc/karst/enroll/$(POD_NAME).toml
    env:
      - name: POD_NAME
        valueFrom: { fieldRef: { fieldPath: metadata.name } }
    volumeMounts:
      - { name: config, mountPath: /etc/karst, readOnly: true }
      - { name: enroll-bundle, mountPath: /etc/karst/enroll, readOnly: true }
volumes:
  - name: enroll-bundle
    secret: { secretName: <pool_id>-enroll }
```

`$(POD_NAME)` here is Kubernetes's own `command`/`args` variable
substitution (no shell involved) — it resolves to exactly the pod's name,
which is exactly the bundle key's own name minus the `.toml` suffix. A
pod whose `enroll` init container fails never starts the main `karst-relay`
container — an unenrolled relay has no roster entry and cannot serve
anyone, so failing loud and early here is correct, not a bug to work
around with a retry loop in the image's own entrypoint.

## `drain`/`destroy` and `StatefulSet` scale-down

A `StatefulSet` scale-down always removes its **highest-ordinal** pod —
Kubernetes's own semantics, not a choice this driver makes.
`karst-scaler drive`'s own reconciliation loop already accounts for this
(it selects the highest-ordinal instances as excess); `destroy` itself
refuses a request naming any other pod rather than silently scaling down
a different one than asked.

## Configuring `karst-scaler drive` to use this driver

```toml
# advise-config.toml, alongside the existing [breaker] section (required
# regardless of which driver is selected — ADR-0045 §6 allows no
# "unlimited" default).
[driver]
kind = "k8s"
namespace = "karst-relays"
enroll_pat_file = "/etc/karst-scaler/enroll.pat"   # a UserRoleScaler-scoped PAT
```

Requires a `karst-scaler` binary built with `cargo build --features k8s`
(see `bins/karst-scaler-k8s`'s own crate doc for why this is opt-in) and a
`kubeconfig`/in-cluster service account reachable the ordinary way every
`kubectl`-adjacent tool discovers one — this driver does not add its own
connection configuration on top of that.
