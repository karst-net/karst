<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Bare-metal / VM deployment: systemd

For a node that is not a container — a laptop, a VM, a rack server.

```sh
cargo build --release --package karstd --package karst-cli
sudo install -m 0755 target/release/karstd target/release/karst /usr/local/bin/
sudo mkdir -p /etc/karst
sudo cp /path/to/your/karstd.toml /etc/karst/karstd.toml
sudo cp deploy/systemd/karstd.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now karstd
```

## Why `ExecStopPost=` matters here specifically

`karstd` can be told to configure the host's DNS resolver — see
`spec/karstdns-v1.md` and `plans/phase-5/01-karstdns.md` §6. That
configuration must not survive the daemon: a host left pointing at a resolver
that stopped listening has **every DNS lookup failing**, which looks
indistinguishable from "the network is broken" to whoever it happens to.

`karstd` has no signal handler for this (see the comment in
`bins/karstd/src/main.rs`), so it cannot revert its own DNS change on the way
out — including on `SIGKILL`, which a signal handler could not survive anyway.
The unit's `ExecStopPost=` runs `karst dns revert` after every stop instead,
successful or not, which is what keeps a crash-restart loop from leaving a
machine unable to resolve names. `karst dns revert` does not talk to the
daemon; it reads `/etc/karst/karstd.toml` directly and undoes whatever host
DNS change it finds on disk or on the D-Bus session for `systemd-resolved` or
NetworkManager, so it works even though the process it is cleaning up after
has already exited.

Run it by hand at any time to check or force the same recovery:

```sh
sudo karst dns revert --config /etc/karst/karstd.toml
```

## Relay deployment adapter

For a bare-metal relay installed per
[GETTING-STARTED.md §6.1](../../docs/GETTING-STARTED.md), `relay-service.py`
(Python 3.11+) manages the Ponor process from `relay-service.toml`, the same
manifest contract as the reference Compose
[deployment adapter](../compose/README.md#relay-deployment-adapter), except
it drives `systemctl` against the already-installed `karst-relay.service`
unit instead of `docker compose`. It targets this bare-metal layout, not the
Compose stack. It never rotates identity keys, TLS material, shared secrets,
registry files or allocation ports, and it does not install, enable or touch
`karst-control.service` — control must already be running.

```sh
sudo cp relay-service.toml.example /etc/karst/relay-service.toml
sudo ./relay-service.py plan
sudo ./relay-service.py apply --acknowledge-process-change
sudo ./relay-service.py status
```

`plan` validates that `relay.key`, `roster.toml`, `relays.json` and
`tls/relay.{crt,key}` exist under `/etc/karst` (override with `--directory`)
and prints the desired mode and commands, without resolved unit configuration
or secrets; it does not contact systemd. `apply` validates the unit is
installed (`systemctl cat`, output never printed — a unit file can carry
`Environment=` secrets), starts it when enabled or stops it when disabled,
and requires `--acknowledge-process-change` because stopping it can interrupt
active allocations and connections. If a command fails, earlier commands may
have completed; inspect `status` and `journalctl -u karst-relay` before
retrying. Apply is idempotent, not transactional.

A successful apply saves `/etc/karst/relay-service.applied.toml` (mode 0600)
and retains the prior successful manifest as
`relay-service.applied.toml.previous`. For process rollback, review/copy that
previous manifest to `relay-service.toml`, run `plan`, then apply again.
Failed applies do not record success.

As with the Compose adapter, local process state and account publication are
distinct: withdraw endpoints through control's **Relay Services** mode/
publication controls before stopping the unit, and see
[Relay Services](../../docs/relay-services.md) for version gates and
rollback. `status` reports the unit's `ActiveState` (`active`/`inactive`/
`absent` when not installed); a unit with no health probe is `unprobed`, not
healthy — use control's fresh Ponor admission observations for readiness.

Run the adapter tests with:

```sh
python3 -m unittest discover -s deploy/systemd -p test_relay_service.py -v
# Also exercise a real transient systemd unit as a process stand-in (root).
KARST_SYSTEMD_LIFECYCLE_TEST=1 sudo -E python3 -m unittest discover -s deploy/systemd -p test_relay_service.py -v
```
