<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Karst Kubernetes operator

`karst-operator` currently reconciles a `KarstNode` into one host-networked,
privileged `karstd` DaemonSet. The daemon also supports an unprivileged
userspace mode when configured directly:

```toml
[node]
network_mode = "userspace"
userspace_socks5_listen = "127.0.0.1:1080"
```

That listener accepts TCP SOCKS5 `CONNECT` requests to literal overlay IP
addresses; a workload uses it as its sidecar proxy. Operator injection of this
configuration remains outstanding.

The resulting pod shares the host network namespace, is privileged, requests
`NET_ADMIN`, and receives the host's `/dev/net/tun`. Those permissions are
necessary because `karstd` creates a TUN device and installs routes in that
network namespace. Treat a `KarstNode` author as a cluster administrator.

The node configuration is a Kubernetes Secret, not a ConfigMap: it can contain
private keys and roster PSKs. The volume is mounted read-only with mode `0400`,
which also satisfies `karstd`'s key-material permission checks.

## Install

Build and publish the three images first (or replace the image names in the
manifest):

```sh
docker build -f deploy/images/karstd.Dockerfile -t ghcr.io/karst-net/karstd:dev .
docker build -f deploy/images/karst-relay.Dockerfile -t ghcr.io/karst-net/karst-relay:dev .
docker build -f deploy/kubernetes/operator/Dockerfile -t ghcr.io/karst-net/karst-operator:dev deploy/kubernetes/operator
kubectl apply -f deploy/kubernetes/operator/config.yaml
```

Then create the Secret and `KarstNode` shown in `example.yaml`. The operator
watches its own namespace; install a copy per namespace that needs a node
agent. The relay image is deliberately independent of this operator.

**Deploying the relay is not just "a TLS certificate and an explicit roster",
which is what this page used to say.** A relay's roster has a 90-second lease
and something must rewrite it forever, and a relay nothing publishes in the
netmap is one no node will ever dial. Both are easy to miss and neither
announces itself. See [`deploy/compose`](../compose/README.md), which wires a
coordination server and a relay together correctly and explains both traps;
a Kubernetes relay needs the same two pieces.

The `KarstNode` controller owns only the DaemonSet named after the resource.
Deleting the custom resource deletes that DaemonSet. It never mutates
application Pods, so it cannot silently grant their workloads network
privileges.
