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
artefact stands up the infrastructure; it does not finish the walk-through.
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
| `KARST_AQUIFER` | `default` | Forwarding scope (§5.4) |
| `KARST_REGION` | `default` | Relay region (§8, §9) |

`bootstrap.sh` is idempotent: every step skips if its output exists, so
re-running it after a partial failure finishes the job rather than replacing a
relay identity that every node has already pinned.

## Notes

- **First start needs outbound network.** The coordination server downloads
  GeoLite2 databases into `state/netbird/`.
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
