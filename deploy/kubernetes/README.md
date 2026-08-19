<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Karst Kubernetes operator

`karst-operator` reconciles a `KarstNode` into one host-networked `karstd`
DaemonSet. It is intentionally **not** an admission webhook and it does not
inject an unprivileged/userspace sidecar. Userspace operation is out of scope.

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
agent. The relay image is deliberately independent of this operator: deploy it
as ordinary infrastructure with a TLS certificate and an explicit roster.

The `KarstNode` controller owns only the DaemonSet named after the resource.
Deleting the custom resource deletes that DaemonSet. It never mutates
application Pods, so it cannot silently grant their workloads network
privileges.
