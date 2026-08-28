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
