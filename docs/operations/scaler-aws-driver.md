<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# The AWS scaler driver

Operations reference for `karst-scaler-aws` (ADR-0045 §5/§7 Phase 3) — the
second real `Driver` the scaler can actuate through, after
`karst-scaler-k8s`. This is the mechanism this PR adds; it is not a
complete relay-on-EC2 deployment guide. The AMI this driver launches is
expected to already have `karst-relay` installed and configured to run
`enroll` from its own boot path (e.g. a systemd unit ordered after
network-online.target, or the same step a cloud-init user-data script
would normally run) — provisioning that image is the same AMI-build
concern it already is for any EC2 workload, not something this driver
does for you.

## Why this driver's bundle has no `address`, and the Kubernetes one does

`karst-scaler-k8s` can write a pod's own address into its enrollment
bundle *before* the pod exists, because a `StatefulSet` ordinal's
hostname is fixed by Kubernetes's own naming convention. EC2 has no
equivalent: an instance's IP is assigned only once `RunInstances`
actually launches it, but the bundle has to be baked into `UserData` at
the moment of that same call. `create(n)` therefore writes a bundle with
no address at all; `karst-relay enroll` resolves its own, after boot, via
the AWS instance metadata service (IMDS) — extending the same probe
`bins/karst-relay/src/cloud_location.rs` already uses for ADR-0048's
self-reported location, not a new mechanism. `tls_server_name`, by
contrast, is derived from the enrollment token at `create(n)` time and
never needs to wait, since it is a stable label the mesh dials by, not a
DNS name (`bins/karst-relay/src/tls.rs`'s own crate doc: a relay's
certificate is never what authenticates it).

## Tag convention and IAM

Every instance this driver creates and manages carries one tag,
`karst:pool` = `pool_id` (ADR-0045 §1) — `list`/`destroy` both filter by
it independently of whatever the planner believes exists, the same
defense-in-depth posture `karst_scaler::breaker::BoundedDriver` already
applies generically. `deploy/aws/scaler/iam-policy.json` is the reference
policy: tag-conditioned `RunInstances`/`StopInstances`/
`TerminateInstances`/`CreateTags` on the instances themselves, plus the
unconditional grants `RunInstances` also needs against the subnet,
security group(s), and AMI it references (none of which this driver
creates, so none of which are tag-conditioned the same way). Validate
this policy against a real account before relying on it — it has not
been exercised against one in this environment.

## What `create(n)` actually does

Not one batched call for all `n` — one `RunInstances` call *per*
instance, with `MinCount = 1, MaxCount = 1`:

1. Mints one relay-enroll token (ADR-0045 §7 Phase 2 PR 3,
   `POST /karst/v1/relays/enroll-tokens`).
2. Builds a bundle (`control_api_base`, `token`, `tls_server_name`, no
   `address`), base64-encodes it, and launches exactly one instance with
   it as `UserData`.
3. Tags the returned instance with `karst:pool`.

`RunInstances`'s own `UserData` field is one value per call — the reason
for the per-instance loop is that reason alone, not a design preference:
giving each new instance its own enrollment token requires it.

## `drain`/`destroy`

`drain(id)` calls `StopInstances`, then polls until the instance reaches
`stopped` (or `terminated`) or a bounded timeout elapses. `destroy(id)`
calls `TerminateInstances`. `StopInstances` sends a normal ACPI shutdown
signal to the guest, which a standard Linux init system delivers to
`karst-relay` as `SIGTERM` — the same `shutdown_signal` →
`announce_restart` path `bins/karst-relay/src/server.rs` already handles
for the Kubernetes driver's own pod deletion. **Not independently
verified against a real EC2 instance in this environment** — confirm
this before relying on it in production, the same caveat the Kubernetes
driver's own deployment doc gives for a real cluster.

## Configuring `karst-scaler drive` to use this driver

```toml
# advise-config.toml, alongside the existing [breaker] section (required
# regardless of which driver is selected — ADR-0045 §6 allows no
# "unlimited" default).
[driver]
kind = "aws"
region = "us-east-1"
ami_id = "ami-0123456789abcdef0"
instance_type = "t3.micro"
subnet_id = "subnet-0123456789abcdef0"
security_group_ids = ["sg-0123456789abcdef0"]
enroll_pat_file = "/etc/karst-scaler/enroll.pat"   # a UserRoleScaler-scoped PAT
```

Requires a `karst-scaler` binary built with `cargo build --features aws`
(see `bins/karst-scaler-aws`'s own crate doc for why this is opt-in) and
AWS credentials reachable through `aws-config`'s own ambient credential
chain — environment variables, a shared config/credentials file, or an
EC2 instance profile when `karst-scaler` itself runs on EC2 — the same
"this driver adds no connection configuration of its own" posture the
Kubernetes driver's kubeconfig discovery already has.
